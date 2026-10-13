#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Share-Safe Renders scanner.

Before you share a ComfyUI-style render (PNG, JPEG, MP4/MOV) find out what it leaks:
API keys, secret-named fields, Discord and Slack webhooks, home-path usernames,
e-mail addresses, LAN addresses, EXIF GPS, and secrets hidden in bypassed nodes,
double-encoded JSON, compressed PNG chunks, or MP4 boxes that ffprobe does not show.

    python scan.py PATH [PATH...] [--json OUT.json] [--max-bytes N]

Exit codes: 0 nothing found in everything scanned, 1 findings, 2 usage error,
3 something could not be scanned (and nothing else was found).

Design rules
  * Python 3.9+, standard library only.  ffprobe is used as an extra witness if it
    is on PATH (found in the absolute directories listed on PATH, never in the
    current folder); the built-in reader does not depend on it.
  * The scanner NEVER prints text it scanned.  Output is class, carrier, location,
    length and a short hash.  Metadata is untrusted input; it may contain
    instructions aimed at an AI agent.  Every label that originates from the file
    (chunk keyword, JSON key, box type) is either mapped to a fixed vocabulary or
    replaced by a hash before it is shown.
  * A file that could not be scanned is not reported as clean (it is listed, and the exit code is 3).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import string
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import zlib

VERSION = "1.2.0"
EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, EXIT_UNSCANNED = 0, 1, 2, 3

# --------------------------------------------------------------------------
# limits
# --------------------------------------------------------------------------
DEFAULT_MAX_BYTES = 1 << 30           # per-file size ceiling (override: --max-bytes)
DEFAULT_MAX_DEPTH = 12                # directory depth
DEFAULT_MAX_FILES = 20000             # files visited per directory argument
INFLATE_CAP_STREAM = 32 << 20         # decompressed bytes per zTXt/iTXt stream
INFLATE_CAP_FILE = 128 << 20          # decompressed bytes per file
INFLATE_RATIO_CAP = 200               # out/in ratio that marks a bomb ...
INFLATE_RATIO_FLOOR = 1 << 20         # ... once at least this much was produced
PAYLOAD_CAP = 64 << 20                # largest single chunk/box/segment we read
NESTED_BOX_CAP = 1 << 20              # a box nested inside moov/trak/udta that we do not recognise: only this much is read
STRUCT_JSON_MAX = 16 << 20            # larger JSON is scanned as text only
MAX_FINDINGS_PER_FILE = 1000          # per file AND per class: a flood of one class cannot hide another
MAX_REPORT_HIGH = 50000               # records kept in one report (K1 K2 K3 G1 H*)
MAX_REPORT_LOW = 20000                # records kept in one report (P1 P2 P3 M1)
MAX_PRINT_FINDINGS = 1000             # finding lines printed in the human report (the rest is summarised)
MAX_SKIP_NAMES = 100                 # skipped entries (links, unrecognized files) named under NOTES; the rest is only counted
MAX_HITS_PER_TEXT = 20000             # distinct values per class collected from one scanned text; more is a reported problem
MAX_MP4_ITEMS = 4096                  # entries read from one metadata list (keys, ilst, the children of an item); more is a reported problem
MAX_JSON_DEPTH = 120
NUMERIC_SECRET_DIGITS = 8             # a number under a secret-looking name is a finding from this many digits
MAX_DOUBLE_ENCODE = 12
MAX_BOXES = 200000
MAX_PNG_CHUNKS = 1000000
MAX_JPEG_SEGMENTS = 100000
MAX_BOX_DEPTH = 16
MAX_TEXT_RUNS = 4000000               # text-like runs examined in one unparsed region
MAX_EXIF_TEXTS = 5000                 # text-valued EXIF tags examined per TIFF block
DEFAULT_TIME_LIMIT = 120.0            # wall-clock seconds per file (override: --time-limit)
TIME_LIMIT = DEFAULT_TIME_LIMIT

KNOWN_MISSES = [
    "Data hidden in pixel bits (steganography, LSB or otherwise).",
    "Secrets, faces, logos or text that appear in the generated pixels themselves.",
    "The contents of C2PA / Content Credentials manifests are not decoded or classified.",
    "The image or video content itself (what the picture shows).",
    "Secrets that were base64-, hex-, rot13- or otherwise re-encoded, or split across fields.",
    "ICC profile contents, and audio/video sample data (incl. the first mdat).",
    "Data hidden inside the compressed image stream itself (PNG IDAT, JPEG entropy-coded segments).",
    "UTF-16 text inside raw (unparsed) regions such as trailing data; UTF-16 whole-chunk text is decoded.",
    "Containers other than PNG, JPEG, MP4/MOV and plain JSON (WebP, GIF, WebM, HEIC, AVIF ... are reported as not "
    "scanned; in a folder, other unrecognized file types are only counted as skipped).",
    "IPv6 addresses, loopback, link-local and CGNAT ranges, and public IPv4 addresses.",
    "Vendor key formats other than the eight it knows (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, "
    "Hugging Face), webhook URLs other than Discord and Slack, and secrets in fields whose names it does not recognise.",
]


# --------------------------------------------------------------------------
# wall-clock budget: a hostile file must not be able to pin a CPU for minutes
# --------------------------------------------------------------------------
class ScanBudget(Exception):
    """The per-file wall-clock budget ran out."""


_BUDGET = {"deadline": None, "n": 0}


def budget_start(seconds=None):
    s = TIME_LIMIT if seconds is None else seconds
    _BUDGET["deadline"] = (time.monotonic() + s) if s and s > 0 else None
    _BUDGET["n"] = 0


def tick():
    """Cheap budget check for loops: looks at the clock once every 256 calls."""
    _BUDGET["n"] += 1
    if _BUDGET["n"] & 0xFF == 0:
        d = _BUDGET["deadline"]
        if d is not None and time.monotonic() > d:
            raise ScanBudget()

SEVERITY = {"K1": "high", "K2": "high", "K3": "high", "G1": "high",
            "H1": "high", "H2": "high", "H3": "high",
            "P1": "medium", "P2": "medium", "M1": "medium", "P3": "low"}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
_HASH_KEY = os.urandom(16)            # made once per run, never written anywhere: see sha8


def sha8(v):
    """First 8 hex digits of HMAC-SHA-256(v) under a random key that exists for this run only.  The same value gets the
    same prefix everywhere in one report, so repeats can be matched; the key is never stored or printed, so a prefix
    cannot be checked against a guessed value (a plain hash of a short value such as a LAN address or a user name
    can be recovered offline from its prefix and length) and prefixes of two reports cannot be compared."""
    if isinstance(v, str):
        v = v.encode("utf-8", "surrogatepass")
    return hmac.new(_HASH_KEY, v, hashlib.sha256).hexdigest()[:8]


_BAD_CP = set(range(0x00, 0x20)) | {0x7F} | set(range(0x80, 0xA0)) | {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0xFFF9, 0xFFFA, 0xFFFB}


def esc_text(s):
    """Escape control, bidi, zero-width and surrogate code points so that anything we
    print (file names) cannot drive the terminal or smuggle invisible text."""
    out = []
    for ch in str(s):
        o = ord(ch)
        if o in _BAD_CP or 0xD800 <= o <= 0xDFFF or not ch.isprintable():
            out.append("\\u%04x" % o if o <= 0xFFFF else "\\U%08x" % o)
        else:
            out.append(ch)
    return "".join(out)


_ASCII_LOWER = {i: i + 32 for i in range(65, 91)}


def lower_ascii(s):
    """Length-preserving lower-casing (str.lower can change length for some code points)."""
    return s.lower() if s.isascii() else s.translate(_ASCII_LOWER)


def decode_bytes(b):
    """bytes -> str without ever raising: BOMs, BOM-less UTF-16, UTF-8, then Latin-1."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return str(b)
    b = bytes(b)
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "replace")
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if len(b) >= 8:
        samp = b[:4096]
        n = len(samp) // 2
        ev = samp[0::2].count(0)
        od = samp[1::2].count(0)
        if n and od >= 0.4 * n and ev <= 0.1 * n:
            return b.decode("utf-16-le", "replace")
        if n and ev >= 0.4 * n and od <= 0.1 * n:
            return b.decode("utf-16-be", "replace")
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


_RUN_CACHE = {}
_ASCII_RUN_CACHE = {}


class RunOverflow(Exception):
    """More text-like runs than MAX_TEXT_RUNS in one region (reported, never silent)."""


def printable_runs(b, minlen=8):
    """Yield maximal runs of text-like bytes.  A run is ASCII text, or valid UTF-8 text; a stretch that
    mixes high bytes that are NOT valid UTF-8 (binary data, thumbnails ...) is cut down to its ASCII runs.
    There is no silent cap: more than MAX_TEXT_RUNS runs raises RunOverflow so the caller can report it."""
    rx = _RUN_CACHE.get(minlen)
    if rx is None:
        rx = _RUN_CACHE[minlen] = re.compile(rb"[\t\r\n\x20-\x7e\x80-\xff]{%d,}" % minlen)
        _ASCII_RUN_CACHE[minlen] = re.compile(rb"[\t\r\n\x20-\x7e]{%d,}" % minlen)
    arx = _ASCII_RUN_CACHE[minlen]
    n = 0
    for m in rx.finditer(b):
        run = m.group(0)
        n += 1
        if n > MAX_TEXT_RUNS:
            raise RunOverflow()
        tick()
        if run.isascii():
            yield run
            continue
        try:
            run.decode("utf-8")
            yield run
        except UnicodeDecodeError:
            for sm in arx.finditer(run):
                yield sm.group(0)


def scan_runs(sink, carrier, label, data, minlen=8, tags=()):
    """process_blob over every text-like run of `data`; reports a run overflow as an error."""
    try:
        for run in printable_runs(data, minlen):
            process_blob(sink, carrier, label, run, tags)
    except RunOverflow:
        sink.rp.error(sink.file, "text_run_cap", carrier)


# --------------------------------------------------------------------------
# label safety: nothing that came out of a file is printed unless it is in a
# fixed vocabulary; everything else becomes a hash.
# --------------------------------------------------------------------------
PNG_KEYWORDS = frozenset([
    "prompt", "workflow", "parameters", "extra_pnginfo", "comment", "description", "title", "author",
    "software", "source", "copyright", "creation time", "warning", "disclaimer", "xml:com.adobe.xmp",
    "raw profile type exif", "raw profile type xmp", "raw profile type iptc", "generation_data",
    "invokeai_metadata", "sd-metadata", "dream", "negative prompt", "model", "seed"])

FIELD_VOCAB = frozenset([
    "inputs", "outputs", "widgets_values", "nodes", "links", "groups", "extra", "properties", "config",
    "definitions", "subgraphs", "prompt", "workflow", "text", "string", "value", "title", "class_type",
    "_meta", "type", "id", "mode", "name", "label", "widget", "models", "version", "state", "ds", "info",
    "note", "notes", "parameters", "text_g", "text_l", "clip_l", "clip_g", "t5xxl", "ckpt_name",
    "lora_name", "vae_name", "unet_name", "filename_prefix", "image", "video", "audio", "seed", "steps",
    "cfg", "sampler_name", "scheduler", "denoise", "width", "height", "batch_size", "positive",
    "negative", "url", "uri", "path", "file", "filename", "folder", "directory", "comment",
    "description", "author", "email", "user", "username", "host", "hostname", "address", "ip", "server",
    "endpoint", "webhook", "webhook_url", "key", "secret", "token", "password", "api_key", "apikey",
    "access_token", "authorization", "bearer", "client_secret", "headers", "body", "data", "args",
    "kwargs", "metadata", "tags", "template", "content", "message", "messages", "input", "output",
    "extra_pnginfo", "extra_data", "frontendversion", "revision", "last_node_id", "last_link_id"])

# Node ids are echoed only when they have the shape ComfyUI gives them: a whole number of up to 6 digits ("12"), or two
# of them joined by a colon for a node inside a subgraph ("12:34").  Any other id (text, longer numbers, more parts)
# could carry a message to a reader (decimal codes for letters), so it is shown as id~<hash>.  fullmatch, never $: "$"
# also matches before a trailing newline.
_NODE_ID_RE = re.compile(r"[0-9]{1,6}(?::[0-9]{1,6})?", re.ASCII)


def safe_node_id(nid):
    if nid is None:
        return None
    s = str(nid)
    return s if _NODE_ID_RE.fullmatch(s) else "id~" + sha8(s)


def safe_field(k):
    s = str(k)
    return s if lower_ascii(s) in FIELD_VOCAB and s.isascii() else "~" + sha8(s)


def safe_png_kw(kw):
    s = decode_bytes(kw) if isinstance(kw, (bytes, bytearray)) else str(kw)
    return s if lower_ascii(s) in PNG_KEYWORDS and s.isascii() else "kw~" + sha8(s)


# Only registered four-character codes are ever printed.  Anything else is a hash: four free characters
# per finding, times a thousand findings, would let a file spell out a message in the report.
_PNG_CHUNKS = frozenset(b.decode("ascii") for b in (
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"sBIT", b"bKGD", b"hIST", b"pHYs",
    b"sPLT", b"tIME", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCV", b"cLLI", b"oFFs", b"pCAL", b"sCAL", b"sTER",
    b"iCCP", b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"caBX", b"jUMb", b"dSIG", b"vpAg", b"gIFg", b"gIFx", b"gIFt",
    b"eXIf", b"prVW", b"mkBT", b"mkBS", b"mkTS", b"mkBF", b"tXMP"))


def safe_png_type(t):
    try:
        s = bytes(t).decode("ascii")
    except Exception:
        return "chunk~" + sha8(bytes(t))
    return s if s in _PNG_CHUNKS else "chunk~" + sha8(bytes(t))


_BOX_TYPES = frozenset((
    "ftyp styp mdat moov mvhd trak tkhd tref edts elst mdia mdhd hdlr minf vmhd smhd hmhd nmhd sthd dinf dref url urn "
    "stbl stsd stts ctts cslg stsc stsz stz2 stco co64 stss stsh padb stdp sdtp sbgp sgpd subs saiz saio udta meta "
    "ilst keys data mean name free skip wide junk uuid moof mfhd traf tfhd tfdt trun mvex mehd trex leva mfra tfra "
    "mfro sidx ssix pdin prft emsg pnot clip matt kind chpl iods cprt titl dscr auth perf kywd albm yrrc rtng clsf "
    "gnre loci xml bxml iloc iinf infe iref pitm iprp ipco ipma ispe pixi colr pasp clap btrt avc1 avc2 avc3 avc4 "
    "avcC hvc1 hev1 hvcC av01 av1C vp08 vp09 vpcC mp4a mp4v mp4s esds ac-3 ec-3 dac3 dec3 alac samr sawb Opus dOps "
    "fLaC dfLa twos sowt in24 in32 fl32 fl64 lpcm ipcm fpcm raw tx3g text stpp wvtt sbtl tmcd gmhd gmin gpmd gpmf "
    "fiel gama chrm nclc nclx pcmC chnl srat sinf frma schm schi tenc pssh senc mett Xtra XMP_ ----").split())
_BOX_TYPES_B = frozenset(s.encode("latin-1") for s in _BOX_TYPES)
def safe_box_type(t):
    """4-byte box type -> a label.  Registered codes (and the QuickTime (c)-atoms we name) print as
    themselves; any other code prints as box~<hash>."""
    try:
        t = bytes(t)
    except Exception:
        return "box~?"
    if t in _BOX_TYPES_B:
        return t.decode("latin-1")
    if t in _ATOM_NAMES:
        return t.decode("latin-1").replace("\xa9", "(c)")
    return "box~" + sha8(t)


_LABEL_BAD = re.compile(r"[^A-Za-z0-9_:.\-/\[\]~()=+,; ]")


def clean_label(s, limit=160):
    """Last line of defence for every label we print (carrier, location, detail): a fixed safe alphabet and a
    length cap.  All labels are already built from vocabularies or hashes; this makes it impossible for one
    to carry control characters or a long sentence even if a code path is ever wrong."""
    s = _LABEL_BAD.sub("_", str(s))
    return s if len(s) <= limit else s[:limit - 10] + "~" + sha8(s)


_NAME_PART_MAX = 40
FULL_NAMES = [False]


def disp_path(p):
    """File name for the human report.  Control, bidi and zero-width characters are escaped; a path
    component longer than 40 characters is shortened to head~hash~tail, so a file name cannot carry a whole
    sentence into the report.  The --json report keeps the exact path (a documented untrusted field)."""
    s = esc_text(p)
    if FULL_NAMES[0]:
        return s
    seps = os.sep + (os.altsep or "")             # on macOS and Linux a backslash is an ordinary file-name character
    out = []
    for part in re.split("([%s])" % re.escape(seps), s):
        if len(part) > _NAME_PART_MAX and part not in tuple(seps):
            part = part[:16] + "~" + sha8(part) + "~" + part[-12:]
        out.append(part)
    return "".join(out)


# --------------------------------------------------------------------------
# findings / report
# --------------------------------------------------------------------------
class Report(object):
    def __init__(self):
        self.findings = []
        self.errors = []
        self.info = []
        self.files_scanned = 0
        self.files_with_findings = set()
        self.skipped_links = 0
        self.skipped_other = 0
        self.unsupported = 0
        self.ffprobe = "unknown"
        self.n_high = 0                  # records kept, by severity group (report-wide caps)
        self.n_low = 0
        self.dropped = {}                # class -> records not kept because a report-wide cap was reached
        self._err_seen = set()
        self._info_seen = set()
        self._skip_named = 0

    def error(self, file, code, carrier=None):
        key = (file, code, carrier)
        if key in self._err_seen:
            return
        self._err_seen.add(key)
        self.errors.append({"file": file, "code": code, "carrier": clean_label(carrier) if carrier else carrier})

    def note(self, file, code):
        key = (file, code)
        if key in self._info_seen:
            return
        self._info_seen.add(key)
        self.info.append({"file": file, "code": code})

    def skip(self, path, is_link):
        """An entry the walk did not examine: a link (not followed) or a file of a type this scanner does not read.
        All are counted; the first MAX_SKIP_NAMES are also named under NOTES, so the user can find them."""
        if is_link:
            self.skipped_links += 1
        else:
            self.skipped_other += 1
        if self._skip_named < MAX_SKIP_NAMES:
            self._skip_named += 1
            self.note(path, "skipped_link" if is_link else "skipped_other")


class Sink(object):
    """Per-file finding collector with de-duplication and a hard cap."""

    def __init__(self, report, file):
        self.rp = report
        self.file = file
        self._seen = set()
        self._sigs = set()
        self._tagsigs = set()
        self._n = {}
        self.capped = False
        self.force_fallback = False
        self.loci_gps = False            # a position was read from a `loci` box: ffprobe's copy of it is not a second finding
        self.inflate_left = INFLATE_CAP_FILE

    def has_sig(self, cls, h, ln):
        return (cls, h, ln) in self._sigs

    def add(self, carrier, cls, location, value, node_id=None, bypassed=False, tags=(), detail="",
            fallback=False, vlen=None, count=1):
        fallback = fallback or self.force_fallback
        if fallback and cls == "G1" and self.loci_gps:
            return False
        h = sha8(value)
        ln = len(value) if vlen is None else vlen
        if fallback and (cls, h, ln) in self._sigs:
            return False
        carrier, location, detail = clean_label(carrier), clean_label(location), clean_label(detail, 240)
        key = (carrier, cls, location, node_id, h, ln)
        if key in self._seen:
            return False
        if carrier == "mp4:tag":
            # MOV/MP4 muxers mirror one tag into several atoms (udta and meta/ilst): one leak, not two
            tkey = (cls, h, ln, node_id)
            if tkey in self._tagsigs:
                return False
            self._tagsigs.add(tkey)
        if self._n.get(cls, 0) >= MAX_FINDINGS_PER_FILE:
            if not self.capped:
                self.capped = True
                self.rp.note(self.file, "findings_capped_%d" % MAX_FINDINGS_PER_FILE)
            return False
        sev = SEVERITY.get(cls, "medium")
        rp = self.rp
        if (rp.n_high >= MAX_REPORT_HIGH) if sev == "high" else (rp.n_low >= MAX_REPORT_LOW):
            rp.dropped[cls] = rp.dropped.get(cls, 0) + 1          # counted, not kept: bounds the report size
            rp.files_with_findings.add(self.file)
            self._seen.add(key)
            self._sigs.add((cls, h, ln))
            return True
        self._seen.add(key)
        self._sigs.add((cls, h, ln))
        nid = safe_node_id(node_id)
        base = {"file": self.file, "carrier": carrier, "class": cls, "location": location,
                "node_id": nid, "bypassed": bool(bypassed), "length": ln, "sha256_prefix": h,
                "severity": sev}
        rec = dict(base)
        rec["detail"] = detail
        rec["tags"] = sorted(tags)
        if count > 1:
            rec["count"] = count
        rp.findings.append(rec)
        if sev == "high":
            rp.n_high += 1
        else:
            rp.n_low += 1
        self._n[cls] = self._n.get(cls, 0) + 1
        for t in sorted(tags):
            comp = dict(base)
            comp["class"] = t
            comp["severity"] = SEVERITY.get(t, "high")
            comp["detail"] = "companion of %s (%s)" % (cls, _TAG_WHY.get(t, ""))
            comp["tags"] = []
            comp["companion_of"] = cls
            rp.findings.append(comp)
        rp.files_with_findings.add(self.file)
        return True


_TAG_WHY = {"H1": "held in a bypassed or muted node", "H2": "inside a double-encoded JSON string",
            "H3": "inside a compressed PNG chunk"}


# --------------------------------------------------------------------------
# text detectors.  Every loop is linear: str.find with bounded look-around,
# per-character scans with hard caps, or regexes with no nested quantifiers.
# A detector returns (class, sensitive_value, detail); the value is only ever
# hashed and measured by the caller, never printed.
# --------------------------------------------------------------------------
class Hits(list):
    """Detector output.  A value is stored once per class (a repeat of the same class and value is not counted), and each
    class stops at MAX_HITS_PER_TEXT distinct values, so one hostile text cannot make the scanner build millions of
    values (memory and time) and a flood of one class cannot use up the room of another.  `capped` is the set of
    classes that hit the limit: the caller reports it as a problem, because values of that class were not examined."""
    __slots__ = ("capped", "_seen", "_n")

    def __init__(self):
        list.__init__(self)
        self.capped = set()
        self._seen = set()
        self._n = {}

    def add(self, item):
        """True while the detector may go on; False once its class is full (it stops collecting)."""
        key = (item[0], item[1])
        if key in self._seen:
            return True
        n = self._n.get(item[0], 0)
        if n >= MAX_HITS_PER_TEXT:
            self.capped.add(item[0])
            return False
        self._seen.add(key)
        self._n[item[0]] = n + 1
        self.append(item)
        return True


_ASCII_LETTERS = frozenset(string.ascii_letters)
_UPPER_ONLY = frozenset(string.ascii_uppercase)
_TOKCHARS = frozenset(string.ascii_letters + string.digits + "_-")
GLUE_MAX = 24                        # longest word a key may be glued to (OPENAI_API_KEY_ is 15)
_NO_BLOCK = frozenset()
_RIGHT_BAD = frozenset("+/")
_RUN_TOK = re.compile(r"[A-Za-z0-9_\-]*")
_RUN_AL = re.compile(r"[A-Za-z0-9]*")
_RUN_DASH = re.compile(r"[A-Za-z0-9\-]*")
_UPPER_DIGITS = frozenset(string.ascii_uppercase + string.digits)


def _prose_like(body):
    """Hyphenated words such as 'task-list-of-the-day' are prose, not a key.  Prose is short lowercase
    words; a random key has digits and capitals, so a hyphen every 12 characters does not make it prose."""
    segs = body.split("-")
    if len(segs) < 2 or max(len(s) for s in segs) > 14:
        return False
    letters = [c for c in body if c != "-"]
    odd = sum(1 for c in letters if c.isdigit() or c.isupper())
    return odd * 6 <= len(letters)                    # at most ~1 in 6 characters is a digit or capital


def _chk_openai(t):
    body = t[3:]
    return not body.startswith("ant-") and not _prose_like(body)


def _chk_aws(t):
    return len(t) == 20 and all(c in _UPPER_DIGITS for c in t) and not t.endswith("EXAMPLE")


def _chk_slack(t):
    return t.count("-") >= 2


_RUN_AL_US = re.compile(r"[A-Za-z0-9_]*")

# (vendor, prefix, run regex, min total, max total, check or None, left-blocked chars, right-blocked chars)
# Distinctive prefixes need only a length window.  Prefixes that start like an ordinary word (sk-, sk_live_, hf_)
# are not accepted when an ASCII letter sits directly in front ('task-', 'risk_live_'), but a key glued to ENV_,
# a digit, a slash or a hyphen is still a key.  AWS ids are exactly 20 upper-case/digit characters, so an
# upper-case letter in front means a longer identifier.  The '+' and '/' right boundary exists only for the
# prefixes that can occur inside standard base64 (no '-' or '_' in them).
_K1_RULES = [
    ("anthropic", "sk-ant-", _RUN_TOK, 23, 300, None, _ASCII_LETTERS, _NO_BLOCK),
    ("openai", "sk-", _RUN_TOK, 19, 300, _chk_openai, _ASCII_LETTERS, _NO_BLOCK),
    ("github", "ghp_", _RUN_AL, 24, 270, None, _NO_BLOCK, _NO_BLOCK),
    ("github", "gho_", _RUN_AL, 24, 270, None, _NO_BLOCK, _NO_BLOCK),
    ("github", "ghu_", _RUN_AL, 24, 270, None, _NO_BLOCK, _NO_BLOCK),
    ("github", "ghs_", _RUN_AL, 24, 270, None, _NO_BLOCK, _NO_BLOCK),
    ("github", "ghr_", _RUN_AL, 24, 270, None, _NO_BLOCK, _NO_BLOCK),
    ("github", "github_pat_", _RUN_AL_US, 41, 300, None, _NO_BLOCK, _NO_BLOCK),
    ("aws", "AKIA", _RUN_AL, 20, 20, _chk_aws, _UPPER_ONLY, _RIGHT_BAD),
    ("aws", "ASIA", _RUN_AL, 20, 20, _chk_aws, _UPPER_ONLY, _RIGHT_BAD),
    ("google", "AIza", _RUN_TOK, 30, 60, None, _NO_BLOCK, _RIGHT_BAD),
    # the Slack prefixes are written as two pieces so that this file holds no contiguous credential-shaped literal
    ("slack", "xox" + "b-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "p-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "a-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "r-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "s-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "o-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xox" + "e-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("slack", "xapp-", _RUN_DASH, 15, 300, _chk_slack, _NO_BLOCK, _NO_BLOCK),
    ("stripe", "sk_live_", _RUN_AL_US, 18, 270, None, _ASCII_LETTERS, _NO_BLOCK),
    ("stripe", "rk_live_", _RUN_AL_US, 18, 270, None, _ASCII_LETTERS, _NO_BLOCK),
    ("huggingface", "hf_", _RUN_AL, 23, 70, None, _ASCII_LETTERS, _NO_BLOCK),
    ("huggingface", "api_org_", _RUN_AL, 28, 80, None, _NO_BLOCK, _NO_BLOCK),
]


def _scan_k1(text, hits):
    n = len(text)
    for vendor, prefix, run_re, lo, hi, check, lblock, rblock in _K1_RULES:
        plen = len(prefix)
        i = text.find(prefix)
        while i != -1:
            tick()
            glued_ok = True
            if i > 0 and text[i - 1] in _TOKCHARS:
                # glued to the end of a word: ENV_ghp_..., api-sk-..., 2024hf_... are keys, but the same
                # shape deep inside a long token run (a base64url blob) is not
                k, run = i - 1, 0
                while k >= 0 and text[k] in _TOKCHARS and run <= GLUE_MAX:
                    run += 1
                    k -= 1
                glued_ok = run <= GLUE_MAX
            if glued_ok and (i == 0 or text[i - 1] not in lblock):
                # the run is matched with an end position, so one occurrence costs at most `hi` characters:
                # total work stays linear however many prefixes a text repeats
                end = run_re.match(text, i + plen, min(n, i + hi + 1)).end()
                total = end - i
                if lo <= total <= hi and (not rblock or end >= n or text[end] not in rblock):
                    tok = text[i:end]
                    if check is None or check(tok):
                        if not hits.add(("K1", tok, "vendor=" + vendor)):
                            return
            i = text.find(prefix, i + 1)


# ---- K3 webhooks ---------------------------------------------------------
_DISCORD_TAIL = re.compile(r"[0-9]{6,25}/[A-Za-z0-9_\-]{10,120}")
_SLACK_TAIL = re.compile(r"T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{16,40}")


def _url_start(low, host_pos):
    if low[max(0, host_pos - 8):host_pos] == "https://":
        return host_pos - 8
    if low[max(0, host_pos - 7):host_pos] == "http://":
        return host_pos - 7
    return host_pos


_URLPATH_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_/")


def _scan_webhooks(text, low, hits):
    n = len(text)
    pos = low.find("/webhooks/")
    while pos != -1:
        tick()
        # the host and path prefix sit directly in front of /webhooks/ (discord.com/api, ptb.discord.com/api/v10 ...):
        # walk left over URL characters only, so the span starts at the host and never at some word earlier in the text
        j = pos
        lim = max(0, pos - 80)
        while j > lim and low[j - 1] in _URLPATH_OK:
            j -= 1
        while j < pos and low[j] in "/.-_":
            j += 1
        d = low.find("discord", j, pos)
        if d != -1:
            m = _DISCORD_TAIL.match(text, pos + 10, min(n, pos + 10 + 160))
            if m and not hits.add(("K3", text[_url_start(low, j):m.end()], "kind=discord_webhook")):
                return
        pos = low.find("/webhooks/", pos + 10)
    pos = low.find("hooks.slack.com/services/")
    while pos != -1:
        m = _SLACK_TAIL.match(text, pos + 25, min(n, pos + 25 + 120))
        if m and not hits.add(("K3", text[_url_start(low, pos):m.end()], "kind=slack_webhook")):
            return
        pos = low.find("hooks.slack.com/services/", pos + 25)


# ---- P2 e-mail -----------------------------------------------------------
_LOCAL_OK = frozenset(string.ascii_letters + string.digits + "._%+-")
_DOM_OK = frozenset(string.ascii_letters + string.digits + ".-")
# File extensions that are not top-level domains: "icon@2x.png", "weights@v2.safetensors" are not mail addresses.
# A few extensions are ALSO real country / generic TLDs (.pt Portugal, .md Moldova, .py Paraguay, .so Somalia,
# .zip and .mov): there the domain must look like a name (3+ letters before the TLD) to count as an address.
_FILE_TLDS = frozenset((
    "png jpg jpeg gif webp svg bmp tif tiff ico mp4 avi mkv webm mp3 wav flac json txt js ts "
    "csv yaml yml toml ini log pth ckpt safetensors bin onnx gguf pkl npy npz tar gz exe dll "
    "html htm css xml pdf cfg conf lock").split())
_AMBIGUOUS_TLDS = frozenset("pt md py so zip mov".split())
_PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")
_PLACEHOLDER_TLDS = frozenset(["example", "test", "invalid", "localhost"])


def _domain_ok(dom):
    labels = dom.split(".")
    if len(labels) < 2 or len(dom) > 253:
        return None
    for lab in labels:
        if not lab or len(lab) > 63 or lab[0] == "-" or lab[-1] == "-":
            return None
    return labels


def _email_domain_hit(local, dom):
    """-> 'local@dom' when dom is a plausible real mail domain, else None."""
    labels = _domain_ok(dom)
    if labels is None:
        return None
    tld = labels[-1].lower()
    dl = dom.lower()
    if tld in _PLACEHOLDER_TLDS or any(dl == d or dl.endswith("." + d) for d in _PLACEHOLDER_DOMAINS):
        return None
    if tld in _FILE_TLDS:
        return None
    if tld in _AMBIGUOUS_TLDS and not (len(labels[-2]) >= 3 and labels[-2].isalpha()):
        return None
    is_punycode = tld.startswith("xn--") and len(tld) >= 6
    if not ((tld.isalpha() and 2 <= len(tld) <= 24) or is_punycode):
        return None
    return local + "@" + dom


def _scan_emails(text, hits):
    n = len(text)
    i = text.find("@")
    while i != -1:
        tick()
        a = i
        lim = max(0, i - 64)
        while a > lim and text[a - 1] in _LOCAL_OK:
            a -= 1
        too_long = a == lim and a > 0 and text[a - 1] in _LOCAL_OK
        local = text[a:i].lstrip(".%+-")
        if local and not too_long:
            ascii_end = i + 1
            while ascii_end < n and ascii_end < i + 1 + 255 and text[ascii_end] in _DOM_OK:
                ascii_end += 1
            for uni in (False, True):
                if uni and not (ascii_end < n and ord(text[ascii_end]) > 127 and text[ascii_end].isalnum()):
                    break                                 # (the ASCII domain was not followed by a letter of another script)
                b = i + 1
                lim2 = min(n, i + 1 + 255)
                if uni:                                   # internationalised domain: letters of any script
                    while b < lim2 and (text[b] in _DOM_OK or (ord(text[b]) > 127 and text[b].isalnum())):
                        b += 1
                    too_long_dom = b == lim2 and b < n and (text[b] in _DOM_OK or text[b].isalnum())
                else:
                    b = ascii_end
                    too_long_dom = b == lim2 and b < n and text[b] in _DOM_OK
                dom = text[i + 1:b].rstrip(".-")
                if dom and not too_long_dom:
                    found = _email_domain_hit(local, dom)
                    if found:
                        if not hits.add(("P2", found, "kind=email")):
                            return
                        break
        i = text.find("@", i + 1)


# ---- P3 private IPv4 + internal hostnames --------------------------------
_IP_RE = re.compile(r"(?<![0-9])([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(?![0-9])")
_HOST_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]*")
_INTERNAL_SUFFIXES = (".local", ".lan", ".internal")


def _private_ip(a, b):
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def _scan_private_net(text, low, hits):
    n = len(text)
    for m in _IP_RE.finditer(text):
        tick()
        octets = [int(g) for g in m.groups()]
        if max(octets) > 255 or not _private_ip(octets[0], octets[1]):
            continue
        s, e = m.start(), m.end()
        if s > 0:
            c = text[s - 1]
            # v10.1.2.3, foo.10.1.2.3, py3.10.1.2 are versions; "host_10.0.0.5" and "ip192.168.0.2" are addresses
            if c.isdigit() or c == "." or c in "vV":
                continue
        if e < n and (text[e].isalnum() or (text[e] == "." and e + 1 < n and text[e + 1].isdigit())):
            continue                      # 10.1.2.3.4, 10.1.2.3beta
        if not hits.add(("P3", m.group(0), "kind=private_ipv4")):
            return
    if ".local" in low or ".lan" in low or ".internal" in low:
        for m in _HOST_RUN.finditer(text):
            tick()
            run = m.group(0).rstrip(".-")
            if len(run) < 5 or len(run) > 253:
                continue
            rl = run.lower()
            if not rl.endswith(_INTERNAL_SUFFIXES):
                continue
            labels = _domain_ok(run)
            if labels is None or len(labels[-2]) < 1:
                continue
            if not hits.add(("P3", run, "kind=internal_hostname")):
                return


# ---- P1 home paths -------------------------------------------------------
_PATH_PLACEHOLDERS = frozenset(["public", "default", "default user", "all users", "shared", "localservice",
                                "networkservice", "defaultuser0"])
_NAME_STOP_WIN = frozenset("\\/\"'<>|?*:`\r\n\t\x00")
_NAME_STOP_POSIX = frozenset("\\/\"'<>|?*:`\r\n\t\x00 ")


def _take_name(text, p, stops):
    n = len(text)
    e = p
    lim = min(n, p + 65)
    while e < lim and text[e] not in stops:
        e += 1
    if e - p > 64:
        return None
    name = text[p:e].rstrip(" .")
    if not name or not any(c.isalnum() for c in name) or not name[0].isalnum() and name[0] not in "_-":
        return None
    if name.lower() in _PATH_PLACEHOLDERS or any(c in name for c in "%$<>{}[]*"):
        return None
    return name


def _posix_left_ok(text, i, home=False):
    if i == 0:
        return True
    c = text[i - 1]
    if i >= 6 and text[i - 6:i - 1].lower() == "/mnt/" and c.isalpha():
        return True                                           # WSL: /mnt/c/Users/...
    if home and text[max(0, i - 4):i] in ("/var", "/usr"):
        k = i - 4                                             # /usr/home/<name> (FreeBSD), /var/home/<name> (Silverblue)
        return k == 0 or not (text[k - 1].isalnum() or text[k - 1] in "._-~")
    if c == "/":
        return text[max(0, i - 7):i].lower() == "file://"
    return not (c.isalnum() or c in "._-~")


_HOST_CH = frozenset(string.ascii_letters + string.digits + ".-_")


def _scan_home_paths(text, low, hits):
    n = len(text)
    if "users" in low:
        i = low.find("users")
        while i != -1:
            tick()
            j, k = i, 0
            while j > 0 and text[j - 1] in "\\/" and k < 4:
                j -= 1
                k += 1
            ok = False
            if k >= 1 and j >= 2 and text[j - 1] == ":" and text[j - 2].isascii() and text[j - 2].isalpha():
                ok = True                                        # a drive letter, a colon, then the Users folder
            elif k >= 1 and "\\" in text[j:i]:
                # \\server\Users\name (UNC share) or a drive-less \Users\name
                h = j
                while h > 0 and j - h < 64 and text[h - 1] in _HOST_CH:
                    h -= 1
                if h < j:                                       # a host name precedes: two backslashes in front of it
                    b, cnt = h, 0
                    while b > 0 and text[b - 1] == "\\" and cnt < 8:
                        b -= 1
                        cnt += 1
                    ok = cnt >= 2
                else:                                           # nothing precedes the separators: drive-less path
                    ok = j == 0 or not (text[j - 1].isalnum() or text[j - 1] in ".-_:")
            if ok:
                p, k2 = i + 5, 0
                while p < n and text[p] in "\\/" and k2 < 4:
                    p += 1
                    k2 += 1
                if k2 >= 1:
                    name = _take_name(text, p, _NAME_STOP_WIN)
                    if name:
                        if not hits.add(("P1", name, "kind=windows_home")):
                            return
            i = low.find("users", i + 5)
    # C:\Documents and Settings\name  (Windows XP / 2003 profile root)
    if "documents and settings" in low:
        i = low.find("documents and settings")
        while i != -1:
            tick()
            p, k2 = i + 22, 0
            while p < n and text[p] in "\\/" and k2 < 4:
                p += 1
                k2 += 1
            if k2 >= 1 and i >= 1 and text[i - 1] in "\\/":
                name = _take_name(text, p, _NAME_STOP_WIN)
                if name and not hits.add(("P1", name, "kind=windows_home")):
                    return
            i = low.find("documents and settings", i + 22)
    i = text.find("/Users/")
    while i != -1:
        tick()
        if _posix_left_ok(text, i):
            name = _take_name(text, i + 7, _NAME_STOP_WIN)
            wsl = i >= 6 and text[i - 6:i - 1].lower() == "/mnt/" and text[i - 1].isalpha()     # a Windows drive under WSL
            if name and not hits.add(("P1", name, "kind=windows_home" if wsl else "kind=macos_home")):
                return
        i = text.find("/Users/", i + 7)
    i = text.find("/home/")
    while i != -1:
        tick()
        if _posix_left_ok(text, i, home=True):
            name = _take_name(text, i + 6, _NAME_STOP_POSIX)
            if name and not hits.add(("P1", name, "kind=posix_home")):
                return
        i = text.find("/home/", i + 6)


# ---- K2 free-text assignments, bearer tokens, PEM keys --------------------
_PLACEHOLDER_WORDS = frozenset([
    "none", "null", "nil", "false", "true", "n/a", "na", "undefined", "changeme", "change_me", "redacted",
    "placeholder", "your_api_key", "your-api-key", "your_key_here", "your_token_here", "api_key_here",
    "insert_key_here", "insert_your_key", "enter_your_key", "token", "secret", "password", "apikey",
    "api_key", "xxxxxxxx", "********", "example", "test", "dummy", "sample", "empty", "unset", "default"])


def is_placeholder(v):
    s = v.strip()
    sl = s.lower()
    if sl in _PLACEHOLDER_WORDS:
        return True
    if len(set(s)) <= 2 and len(s) >= 4:
        return True                                      # xxxxxxxx, ********, ........
    if s[:1] in "<[{$%" and s[-1:] in ">]}%" or s.startswith(("${", "{{", "<your", "[your", "your_", "your-")):
        return True
    if all(c in "x*.#_-\u2022\u25cf " for c in sl):
        return True
    return False


def _classes(v):
    c = set()
    for ch in v:
        if ch.islower():
            c.add("l")
        elif ch.isupper():
            c.add("u")
        elif ch.isdigit():
            c.add("d")
        else:
            c.add("o")
    return len(c)


_K2_STEMS = ("api_key", "api-key", "apikey", "access_token", "auth_token", "client_secret", "secret_key",
             "secret_access_key", "private_key", "password", "passwd", "token", "secret", "authorization",
             "access_key", "auth_key", "signing_key", "passphrase")
_VALUE_RE = re.compile(r"[^ \t\r\n\"'`,;&)}\]<>]*")
_B64TOK = re.compile(r"[A-Za-z0-9._~+/=\-]*")


def _scan_assignments(text, low, hits):
    n = len(text)
    for stem in _K2_STEMS:
        i = low.find(stem)
        while i != -1:
            tick()
            j = i + len(stem)
            q = 0
            while j < n and q < 3 and text[j] in "\"'`":
                j += 1
                q += 1
            w = 0
            while j < n and w < 6 and text[j] in " \t":
                j += 1
                w += 1
            if j < n and text[j] in ":=" and text[j:j + 3] != "://":
                j += 1
                w = q = 0
                while j < n and w < 6 and text[j] in " \t":
                    j += 1
                    w += 1
                nl = False
                if j < n and text[j] in "\r\n":                 # YAML: the value sits on the next, indented line
                    k = j + 1 if text[j] == "\n" or text[j:j + 2] != "\r\n" else j + 2
                    w = 0
                    while k < n and w < 8 and text[k] in " \t":
                        k += 1
                        w += 1
                    if w:
                        j, nl = k, True
                while j < n and q < 3 and text[j] in "\"'`":
                    j += 1
                    q += 1
                # a value is read with one bounded regex match (C speed): "token:" repeated millions of
                # times costs 300 characters per occurrence at most, not a Python loop per character
                e = _VALUE_RE.match(text, j, min(n, j + 300)).end()
                val = text[j:e]
                if val.lower() in ("bearer", "basic", "token"):
                    pass                                   # handled by the bearer scan
                elif 8 <= len(val) <= 299 and not is_placeholder(val) and _classes(val) >= (3 if nl else 2) \
                        and (not nl or len(val) >= 12):
                    if not hits.add(("K2", val, "field=" + stem.replace("-", "_"))):
                        return
            i = low.find(stem, i + len(stem))
    for word, minlen in (("bearer ", 16), ("basic ", 12)):
        i = low.find(word)
        while i != -1:
            tick()
            ok_ctx = word == "bearer " or "authorization" in low[max(0, i - 60):i]
            j = i + len(word)
            while j < n and j < i + len(word) + 3 and text[j] == " ":
                j += 1
            m = _B64TOK.match(text, j, min(n, j + 2100))
            tok = m.group(0) if m else ""
            if ok_ctx and len(tok) >= minlen and (any(c.isdigit() for c in tok) or "." in tok) \
                    and not is_placeholder(tok):
                if not hits.add(("K2", tok, "field=" + word.strip())):
                    return
            i = low.find(word, i + len(word))
    p = text.find("-----BEGIN ")
    while p != -1:
        tick()
        e = text.find("-----", p + 11, p + 11 + 60)
        if e != -1 and "PRIVATE KEY" in text[p:e]:
            if not hits.add(("K2", text[p:e + 5], "field=pem_private_key")):
                return
        p = text.find("-----BEGIN ", p + 11)


# ---- G1 in XMP text --------------------------------------------------------
def _scan_xmp_gps(text, low, hits):
    if "gpslatitude" not in low and "gpslongitude" not in low:
        return
    n = len(text)
    for name in ("gpslatitude", "gpslongitude"):
        i = low.find(name)
        while i != -1:
            tick()
            j = i + len(name)
            if not low.startswith("ref", j) and j < n and text[j] in "=\"'>":
                while j < n and text[j] in "=\"'> ":
                    j += 1
                e = j
                while e < min(n, j + 64) and text[e] not in "\"'<":
                    e += 1
                val = text[j:e]
                if any(c in "123456789" for c in val):
                    if not hits.add(("G1", val, "kind=xmp_gps")):
                        return
            i = low.find(name, i + len(name))


_ESC_RE = re.compile(r"\\(u[0-9a-fA-F]{4}|[\"\\/bfnrt])")
_ESC_MAP = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_UESC_RE = re.compile(r"\\u[0-9a-fA-F]{4}")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_ASCII_RUN = re.compile(r"[\x00-\x7f]+")
_PCT_BYTE = re.compile(rb"%([0-9A-Fa-f]{2})")


def percent_decode(text):
    """%XX decoding, byte for byte what the standard library's URL unquote returns with errors="replace" (a test
    compares the two).  Each run of ASCII characters is decoded to bytes, then read as UTF-8 with replacement;
    characters outside ASCII pass through unchanged.  Written here so the scanner imports no URL or network module."""
    if "%" not in text:
        return text

    def one(m):
        raw = m.group(0).encode("ascii")
        return _PCT_BYTE.sub(lambda mm: bytes([int(mm.group(1), 16)]), raw).decode("utf-8", "replace")

    return _PCT_ASCII_RUN.sub(one, text)


def unescape_json_text(s):
    def sub(m):
        g = m.group(1)
        return chr(int(g[1:], 16)) if g[0] == "u" else _ESC_MAP[g]
    return _ESC_RE.sub(sub, s)


def _invisible_re():
    """Characters that render as nothing (format controls, zero-width, bidi, tag characters, variation
    selectors, the combining grapheme joiner) and so can be spliced into a token to defeat a matcher."""
    cps = [cp for cp in range(0x10000) if not 0xD800 <= cp <= 0xDFFF and unicodedata.category(chr(cp)) == "Cf"]
    cps += [0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0] + list(range(0xFE00, 0xFE10)) + list(range(0x180B, 0x180E)) + [0x180F]
    parts = []
    for cp in sorted(set(cps)):
        parts.append("\\u%04x" % cp)
    parts.append("\\U000e0001\\U000e0020-\\U000e007f\\U000e0100-\\U000e01ef")
    return re.compile("[" + "".join(parts) + "]")


_ZW_RE = _invisible_re()


def _scan_core(text):
    hits = Hits()
    low = lower_ascii(text)
    _scan_k1(text, hits)
    _scan_webhooks(text, low, hits)
    if "@" in text:
        _scan_emails(text, hits)
    _scan_private_net(text, low, hits)
    _scan_home_paths(text, low, hits)
    _scan_assignments(text, low, hits)
    _scan_xmp_gps(text, low, hits)
    return hits


def scan_text(text, unescape=False, flags=None):
    """All text-level detectors.  Returns unique (class, value, detail) tuples.  `flags` (a dict) receives
    'capped' = True when a class reached MAX_HITS_PER_TEXT distinct values and the rest of that class was not collected."""
    if len(text) < 6:
        return []
    base = text
    if unescape and "\\u" in text:
        # the unescaped copy is scanned as well (below); in this copy an escape is a boundary, so
        # "\uff1aname@host.example" does not glue the escape's hex digits onto the local part
        base = _UESC_RE.sub("\x00", text)
    variants = [base]
    if _ZW_RE.search(text):
        variants.append(_ZW_RE.sub("", base))
    if unescape and "\\" in text:
        t2 = unescape_json_text(text)
        if t2 != text:
            variants.append(t2)
            if _ZW_RE.search(t2):
                variants.append(_ZW_RE.sub("", t2))
    if "%" in text and len(_PCT_RE.findall(text, 0, 4096)) >= 2:
        # percent-encoded copy: https%3A%2F%2Fhooks... and api_key%3D... are the same leak
        try:
            t3 = percent_decode(text)
        except Exception:
            t3 = text
        if t3 != text:
            variants.append(t3)
    out, seen, capped = [], set(), False
    for v in variants:
        h = _scan_core(v)
        capped = capped or bool(h.capped)
        for cls, val, det in h:
            key = (cls, val)
            if key not in seen:
                seen.add(key)
                out.append((cls, val, det))
    if flags is not None and capped:
        flags["capped"] = True
    return out


# --------------------------------------------------------------------------
# JSON: lenient parsing, secret-name logic, ComfyUI-aware walking
# --------------------------------------------------------------------------
class JObj(list):
    """A JSON object kept as a list of (key, value) pairs so duplicate keys survive."""
    __slots__ = ()

    def get(self, key, default=None):
        for k, v in reversed(self):
            if k == key:
                return v
        return default

    def has(self, key):
        for k, _v in self:
            if k == key:
                return True
        return False


DEEP = object()                  # sentinel: JSON nested deeper than the parser allows


class BigInt(int):
    """An integer literal too long to convert: it stands for 10**18 in arithmetic but keeps its digits."""

    def __new__(cls, digits):
        o = int.__new__(cls, 10 ** 18)
        o.txt = digits
        return o


def _p_int(s):
    return int(s) if len(s) <= 18 else BigInt(s)      # never call int() on huge digit strings


_DEC = json.JSONDecoder(object_pairs_hook=JObj, parse_int=_p_int, parse_float=float,
                        parse_constant=lambda s: 0.0, strict=False)


def _try_decode(text, i):
    try:
        return _DEC.raw_decode(text, i)[0]
    except RecursionError:
        return DEEP
    except (ValueError, MemoryError, OverflowError):
        return None


def _try_decode_end(text, i):
    try:
        return _DEC.raw_decode(text, i)
    except RecursionError:
        return DEEP, i
    except (ValueError, MemoryError, OverflowError):
        return None, i


_JSON_START_RE = re.compile(r'\{\s*["}]|\[\s*[\{\["]')
JSON_FIND_TRIES = 8          # failed parse attempts per text (each costs at most one pass over it)
JSON_FIND_DOCS = 8           # separate JSON documents examined per text


def find_json_all(text):
    """Every JSON document found in `text` as ([(obj, start, end)], failed_attempts).  Junk in front of a
    document (prose, an instruction, padding) can be any length: a candidate start is any bracket in the first
    64 characters, then anywhere a brace or bracket is followed by what JSON would put there.  Documents do not
    overlap; at most JSON_FIND_DOCS are returned and JSON_FIND_TRIES failed attempts are made, so the cost is
    bounded, and the search never walks through the inside of a document it already parsed."""
    docs, tries, n = [], 0, len(text)
    lim = min(n, 64)
    i = 0
    while i < lim and tries < JSON_FIND_TRIES and len(docs) < JSON_FIND_DOCS:
        c = text[i]
        if c in "{[" or (c == '"' and i == 0):
            obj, end = _try_decode_end(text, i)
            if obj is None:
                tries += 1
                i += 1
            else:
                docs.append((obj, i, end))
                i = n if obj is DEEP else end
        else:
            i += 1
    pos = max(i, lim)
    while pos < n and tries < JSON_FIND_TRIES and len(docs) < JSON_FIND_DOCS:
        m = _JSON_START_RE.search(text, pos)
        if m is None:
            break
        obj, end = _try_decode_end(text, m.start())
        if obj is None:
            tries += 1
            pos = m.start() + 1
        else:
            docs.append((obj, m.start(), end))
            pos = n if obj is DEEP else end
    return docs, tries


def find_json(text):
    """The first JSON document in `text` (or DEEP / None)."""
    docs, _ = find_json_all(text)
    return docs[0][0] if docs else None


def nested_json(s):
    t = s.strip()
    n = len(t)
    if n < 2 or n > STRUCT_JSON_MAX:
        return None
    a, b = t[0], t[-1]
    if (a == "{" and b == "}") or (a == "[" and b == "]") or (a == '"' and b == '"' and n > 2):
        return _try_decode(t, 0)
    return None


def lex_pairs(text, limit=100000):
    """Linear lexer: yield (key, string_value) for  "key" : "value"  sequences in malformed or
    truncated JSON where json.loads gives up."""
    n = len(text)
    out = []

    def literal(q):
        e = q + 1
        while True:
            e = text.find('"', e)
            if e == -1:
                return text[q + 1:], n
            b, k = 0, e - 1
            while k > q and text[k] == "\\":
                b += 1
                k -= 1
            if b % 2 == 0:
                return text[q + 1:e], e + 1
            e += 1

    i = 0
    while i < n and len(out) < limit:
        tick()
        q = text.find('"', i)
        if q == -1:
            break
        lit, i = literal(q)
        j = i
        while j < n and j < i + 16 and text[j] in " \t\r\n":
            j += 1
        if j < n and text[j] == ":":
            j += 1
            while j < n and j < i + 32 and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] == '"':
                val, i = literal(j)
                out.append((unescape_json_text(lit), unescape_json_text(val)))
            else:
                i = j
    return out


def split_words(key):
    words, cur, prev = [], [], ""
    for ch in key[:80]:
        if not ch.isalnum():
            if cur:
                words.append("".join(cur))
                cur = []
        else:
            if cur and ch.isupper() and prev.islower():
                words.append("".join(cur))
                cur = []
            cur.append(ch)
        prev = ch
    if cur:
        words.append("".join(cur))
    return [w.lower() for w in words]


_SECRET_WORDS_ANY = {"secret": "secret", "password": "password", "passwd": "password",
                     "passphrase": "password", "pwd": "password", "apikey": "api_key",
                     "authorization": "authorization", "bearer": "bearer"}
_SECRET_BIGRAMS = {("api", "key"): "api_key", ("secret", "key"): "secret", ("private", "key"): "private_key",
                   ("access", "key"): "api_key", ("auth", "key"): "api_key", ("access", "token"): "access_token",
                   ("auth", "token"): "access_token", ("api", "token"): "access_token",
                   ("api", "secret"): "secret", ("client", "secret"): "client_secret",
                   ("signing", "key"): "secret", ("refresh", "token"): "access_token",
                   ("session", "token"): "access_token", ("bearer", "token"): "bearer"}
_SECRET_SUFFIXES = (("token", "token"), ("secret", "secret"), ("password", "password"),
                    ("passwd", "password"), ("apikey", "api_key"), ("passphrase", "password"))


def secret_stem(key):
    """Canonical stem if `key` names a secret (api_key, token, password ...), else None.
    'max_tokens', 'token_normalization' and 'tokenizer' are deliberately NOT secret names."""
    if not isinstance(key, str) or not key or len(key) > 120:
        return None
    words = split_words(key)
    if not words:
        return None
    for w in words:
        s = _SECRET_WORDS_ANY.get(w)
        if s:
            return s
    for a, b in zip(words, words[1:]):
        s = _SECRET_BIGRAMS.get((a, b))
        if s:
            return s
    last = words[-1]
    for suf, name in _SECRET_SUFFIXES:
        if last.endswith(suf):
            return name
    return None


def is_secret_value(v):
    """Non-trivial value rule for secret-named fields."""
    s = v.strip()
    return len(s) >= 6 and not is_placeholder(s)


def _secretish_blob(v):
    s = v.strip()
    return 8 <= len(s) <= 300 and not any(c.isspace() for c in s) and _classes(s) >= 2 and not is_placeholder(s)


def _inherited_secret(v):
    """A string inside a secret-named list or object (no name of its own): it has to look like a credential,
    not like a word or a path, because nothing but the parent's name says it is one."""
    s = v.strip()
    if not (12 <= len(s) <= 300) or any(c.isspace() for c in s) or is_placeholder(s):
        return False
    if "://" in s or s.startswith(("/", "./", "../", "~", "\\")):
        return False                                  # a URL or a path is not a credential
    k = _classes(s)
    return k >= 3 or (len(s) >= 24 and k >= 2 and any(c.isdigit() for c in s))


_CONTROL_WORDS = frozenset(["fixed", "increment", "decrement", "randomize"])


def _mode_bypassed(mode):
    """ComfyUI node modes: 0 always, 2 muted (never), 4 bypassed.  Both 2 and 4 still leak.
    4, 4.0 and "4" all mean bypassed."""
    if isinstance(mode, bool):
        return False
    if isinstance(mode, (int, float)):
        return mode in (2, 4)
    if isinstance(mode, str):
        try:
            return float(mode.strip()) in (2.0, 4.0)
        except ValueError:
            return False
    return False


_VERSION_WORDS = frozenset(["version", "ver", "vers", "build", "release", "revision", "rev"])


def _versionish(key):
    return isinstance(key, str) and any(w in _VERSION_WORDS for w in split_words(key))


class St(object):
    __slots__ = ("node_id", "bypassed", "lvl", "ntype", "sec")

    def __init__(self, node_id=None, bypassed=False, lvl=0, ntype=None, sec=None):
        self.node_id, self.bypassed, self.lvl, self.ntype, self.sec = node_id, bypassed, lvl, ntype, sec

    def tags(self):
        t = set()
        if self.bypassed:
            t.add("H1")
        if self.lvl > 0:
            t.add("H2")
        return t

    def nested(self):
        return St(self.node_id, self.bypassed, self.lvl + 1, self.ntype, self.sec)

    def with_sec(self, stem):
        return St(self.node_id, self.bypassed, self.lvl, self.ntype, stem)


def classify_comfy(obj, _depth=0):
    """'api' / 'ui' when the JSON is a ComfyUI prompt (API format) or workflow (UI format)."""
    if not isinstance(obj, JObj) or _depth > 2:
        return None
    nodes = obj.get("nodes")
    if isinstance(nodes, list) and nodes and (obj.has("links") or obj.has("last_node_id") or obj.has("version")):
        if any(isinstance(x, JObj) and x.has("type") for x in nodes[:50]):
            return "ui"
    for k, v in obj[:300]:
        if isinstance(v, JObj) and v.has("class_type") and v.has("inputs"):
            return "api"
    for k in ("prompt", "workflow", "extra_pnginfo"):
        sub = obj.get(k)
        if isinstance(sub, JObj):
            r = classify_comfy(sub, _depth + 1)
            if r:
                return r
    return None


class JsonWalker(object):
    """Walks parsed JSON.  Understands API format ({id: {class_type, inputs}}) and UI format
    ({nodes:[{id,type,mode,widgets_values,inputs}]}, incl. subgraph definitions)."""

    def __init__(self, sink, carrier, label, base_tags, seen, k2vals=None):
        self.sink, self.carrier, self.label = sink, carrier, label
        self.base_tags = frozenset(base_tags)
        self.seen = seen
        self.k2vals = k2vals if k2vals is not None else []
        self.deep = False

    @staticmethod
    def loc(comps):
        out = ""
        for c in comps:
            out += c if c.startswith("[") else (("/" if out else "") + c)
        return out

    def emit(self, cls, value, comps, st, detail):
        self.seen.add((cls, sha8(value), len(value)))
        if cls == "K2":
            self.k2vals.append(value)
        self.sink.add(self.carrier, cls, self.label + ":" + self.loc(comps), value, node_id=st.node_id,
                      bypassed=st.bypassed, tags=set(self.base_tags) | st.tags(), detail=detail)

    def run(self, obj):
        self.walk(obj, (), 0, St())

    @staticmethod
    def ui_state(v, st):
        """A UI-format node: {type, widgets_values / mode / inputs / outputs, id}.  A node without a usable id
        is still a node (its mode and widgets matter); it just has no id to report."""
        if not v.has("type"):
            return None
        if not (v.has("widgets_values") or v.has("mode") or v.has("inputs") or v.has("outputs")):
            return None
        nid, typ, mode = v.get("id"), v.get("type"), v.get("mode")
        if not isinstance(typ, str) or isinstance(nid, bool) or not (nid is None or isinstance(nid, (int, float, str))):
            return None
        if not v.has("id") and not (v.has("widgets_values") or v.has("mode")):
            return None                                      # {type, inputs/outputs} alone: a link or a socket
        return St(str(nid) if nid is not None else st.node_id, _mode_bypassed(mode), st.lvl, typ)

    @staticmethod
    def widget_names(node, wv):
        names = []
        inputs = node.get("inputs")
        if isinstance(inputs, list):
            for inp in inputs:
                if isinstance(inp, JObj):
                    w = inp.get("widget")
                    if isinstance(w, JObj) and isinstance(w.get("name"), str):
                        names.append(w.get("name"))
        if not names:
            return None
        mapping, ni = [], 0
        for i, val in enumerate(wv):
            if isinstance(val, str) and val in _CONTROL_WORDS and i > 0 and isinstance(wv[i - 1], int) \
                    and not isinstance(wv[i - 1], bool):
                mapping.append(None)                       # control_after_generate value
                continue
            mapping.append(names[ni] if ni < len(names) else None)
            ni += 1
        return mapping if ni == len(names) else None       # never guess when counts disagree

    def on_widgets(self, node, wv, comps, depth, st):
        names = self.widget_names(node, wv)
        title = node.get("title")
        hint = (secret_stem(title) if isinstance(title, str) else None) or \
               (secret_stem(st.ntype) if st.ntype else None)
        for idx, item in enumerate(wv):
            ic = comps + ("[%d]" % idx,)
            if isinstance(item, str):
                nm = names[idx] if names is not None else None
                if nm is not None:
                    stem = secret_stem(nm)
                    if stem and is_secret_value(item):
                        self.emit("K2", item, ic + (stem,), st, "field=" + stem)
                elif hint and _secretish_blob(item):
                    self.emit("K2", item, ic, st, "field=" + hint + ";name=unrecovered")
            self.walk(item, ic, depth + 1, st)

    def on_string(self, s, comps, depth, st, version_key=False):
        sub = nested_json(s)
        handled = False
        if sub is DEEP:
            self.deep = True
        elif sub is not None:
            if st.lvl >= MAX_DOUBLE_ENCODE:
                self.deep = True
            else:
                # JSON inside a string: the decoded walk covers every string in it, so the outer
                # text is not scanned again (that would report each secret twice)
                self.walk(sub, comps + ("(json)",), depth + 1, st.nested())
                handled = True
        if not handled and len(s) >= 6:
            flags = {}
            whole = ("K2", sha8(s), len(s)) in self.seen             # this very string was reported as a secret
            for cls, val, det in scan_text(s, flags=flags):
                if whole and cls == "K2":
                    continue                       # the token inside "Bearer <token>" is the same secret, not a second one
                if version_key and cls == "P3" and det == "kind=private_ipv4" and val == s.strip():
                    # {"build": "10.2.3.4"}: a version string that is also a valid address is a version
                    self.seen.add((cls, sha8(val), len(val)))
                    continue
                self.emit(cls, val, comps, st, det)
            if flags.get("capped"):
                self.sink.rp.error(self.sink.file, "detector_hit_cap", self.carrier)

    def walk(self, v, comps, depth, st, version_key=False):
        if depth > MAX_JSON_DEPTH:
            self.deep = True
            return
        tick()
        if isinstance(v, str):
            if st.sec and _inherited_secret(v) and ("K2", sha8(v), len(v)) not in self.seen:
                # a string inside a secret-named list/object ({"api_key": ["..."]}, {"token": {"value": "..."}})
                self.emit("K2", v, comps, st, "field=" + st.sec + ";inherited")
            self.on_string(v, comps, depth, st, version_key)
        elif isinstance(v, JObj):
            ui = self.ui_state(v, st)
            if ui is not None:
                st = ui
            for k, val in v:
                key = k if isinstance(k, str) else str(k)
                cst, comp = st, safe_field(key)
                if isinstance(val, JObj) and val.has("class_type"):
                    cst = St(key, _mode_bypassed(val.get("mode")), st.lvl, None)
                    comp = "node:" + safe_node_id(key)
                # JObj is a list subclass: a dict-style widgets_values is walked like any object, not as positions
                if ui is not None and key == "widgets_values" and isinstance(val, list) and not isinstance(val, JObj):
                    self.on_widgets(v, val, comps + (comp,), depth + 1, st)
                    continue
                vk = False
                stem = secret_stem(key)
                if isinstance(val, str):
                    if stem and is_secret_value(val):
                        self.emit("K2", val, comps + ((comp,) if comp == stem else (comp, stem)), st,
                                  "field=" + stem)
                    vk = _versionish(key)
                elif stem and isinstance(val, int) and not isinstance(val, bool):
                    digits = str(getattr(val, "txt", None) or val).lstrip("-")
                    if len(digits) >= NUMERIC_SECRET_DIGITS:   # {"password": 12345678}: a number is still a secret
                        self.emit("K2", digits, comps + ((comp,) if comp == stem else (comp, stem)), st,
                                  "field=" + stem + ";numeric")
                elif stem and isinstance(val, list):
                    cst = cst.with_sec(stem)                   # JObj is a list too: covers objects and lists
                self.walk(val, comps + (comp,), depth + 1, cst, vk)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                self.walk(item, comps + ("[%d]" % i,), depth + 1, st)


def process_blob(sink, carrier, label, data, base_tags=(), span_out=None):
    """Scan one text-carrying payload (bytes or str).  Structural pass first (node ids, bypass,
    double encoding), then a raw-text safety net.  Returns 'api' / 'ui' / 'json' / None.
    `span_out` (a list) receives (start, end) of the first ComfyUI workflow document found in the text."""
    tick()
    text = data if isinstance(data, str) else decode_bytes(data)
    kind, seen, k2vals = None, set(), []
    docs, tries = find_json_all(text) if len(text) <= STRUCT_JSON_MAX else ([], 0)
    walked = 0
    for obj, s, e in docs:
        if obj is DEEP:
            sink.rp.error(sink.file, "json_too_deep", carrier)
            continue
        if not isinstance(obj, (JObj, list, str)):
            continue
        k = classify_comfy(obj) or "json"
        if kind is None or (k in ("api", "ui") and kind not in ("api", "ui")):
            kind = k
            if span_out is not None and k in ("api", "ui"):
                span_out[:] = [s, e]
        w = JsonWalker(sink, carrier, label, base_tags, seen, k2vals)
        w.run(obj)
        walked += 1
        if w.deep:
            sink.rp.error(sink.file, "json_depth_cap", carrier)
    if (not walked or tries) and '"' in text and ":" in text:
        # truncated or malformed JSON: a linear lexer still finds the "name": "value" pairs
        w = JsonWalker(sink, carrier, label, base_tags, seen, k2vals)
        for key, val in lex_pairs(text):
            stem = secret_stem(key)
            if stem and is_secret_value(val) and ("K2", sha8(val), len(val)) not in seen:
                w.emit("K2", val, ("raw-json", stem), St(), "field=" + stem)
    flags = {}
    for cls, val, det in scan_text(text, unescape=True, flags=flags):
        if (cls, sha8(val), len(val)) in seen:
            continue
        if cls == "K2" and det in ("field=bearer", "field=basic") and any(val in v for v in k2vals):
            continue                       # the token of an Authorization value already reported whole
        sink.add(carrier, cls, label + ":raw", val, tags=set(base_tags), detail=det)
    if flags.get("capped"):
        sink.rp.error(sink.file, "detector_hit_cap", carrier)
    return kind


# --------------------------------------------------------------------------
# byte sources (a file on disk, or a slice already in memory)
# --------------------------------------------------------------------------
class FileSrc(object):
    def __init__(self, f, size):
        self.f, self.size = f, size

    def read_at(self, off, n):
        if off < 0 or n <= 0 or off >= self.size:
            return b""
        self.f.seek(off)
        return self.f.read(min(n, self.size - off))


class BytesSrc(object):
    def __init__(self, b):
        self.b, self.size = b, len(b)

    def read_at(self, off, n):
        return self.b[off:off + n] if off >= 0 and n > 0 else b""


def crc_stream(src, off, n, init):
    crc, done = init, 0
    while done < n:
        b = src.read_at(off + done, min(1 << 20, n - done))
        if not b:
            break
        crc = zlib.crc32(b, crc)
        done += len(b)
    return crc & 0xFFFFFFFF


def inflate_full(blob, budget, wbits=zlib.MAX_WBITS, ratio=True):
    """zlib inflate with a size cap, a ratio cap and a shared per-file budget.
    Returns (data, status, tail); status in ok | bomb_size | bomb_ratio | corrupt | truncated | budget;
    `tail` = bytes that follow the end of the compressed stream (data appended after it, not compressed)."""
    d = zlib.decompressobj(wbits)
    cap = min(INFLATE_CAP_STREAM, budget)
    if cap <= 0:
        return b"", "budget", b""
    out, total, pending, status = [], 0, blob, "ok"
    try:
        while True:
            tick()
            chunk = d.decompress(pending, 65536)
            out.append(chunk)
            total += len(chunk)
            pending = d.unconsumed_tail
            if d.eof:
                break
            if total > cap:
                status = "bomb_size" if cap == INFLATE_CAP_STREAM else "budget"
                break
            consumed = len(blob) - len(pending)
            if ratio and total > INFLATE_RATIO_FLOOR and total > INFLATE_RATIO_CAP * max(consumed, 1):
                status = "bomb_ratio"
                break
            if not pending and not chunk:
                status = "truncated"
                break
    except zlib.error:
        status = "corrupt"
    data = b"".join(out)
    tail = d.unused_data if status == "ok" and d.eof else b""
    return (data[:cap] if len(data) > cap else data), status, tail


def inflate_capped(blob, budget):
    """inflate_full without the trailing bytes: (data, status)."""
    data, status, _tail = inflate_full(blob, budget)
    return data, status


def _looks_zlib(b):
    return len(b) >= 2 and (b[0] & 0x0F) == 8 and ((b[0] << 8) | b[1]) % 31 == 0 and (b[0] >> 4) <= 7


def _looks_gzip(b):
    return b[:3] == b"\x1f\x8b\x08"


def inflate_layers(sink, rp, carrier, body, tail_out, max_layers=3, ratio=True):
    """Peel compression layers: a payload that is itself a zlib/gzip stream (zlib inside zlib) is inflated
    again, up to max_layers, under the same per-file budget.  Returns (innermost data, True if any layer was
    peeled).  Bytes that follow a stream are appended to tail_out."""
    layers = 0
    while layers < max_layers and (_looks_zlib(body) or _looks_gzip(body)):
        wbits = zlib.MAX_WBITS | (16 if _looks_gzip(body) else 0)
        data, st, tail = inflate_full(body, sink.inflate_left, wbits, ratio)
        if st == "corrupt" and not data:
            break                            # it only looked like a zlib header (about 1 text in 30 does)
        sink.inflate_left -= len(data)
        if st != "ok":
            rp.error(sink.file, "png_" + _INFLATE_ERR[st], carrier)
            return data, True
        if tail:
            tail_out.append(tail)
        body = data
        layers += 1
    return body, layers > 0


_INFLATE_ERR = {"bomb_size": "inflate_bomb_size", "bomb_ratio": "inflate_bomb_ratio",
                "corrupt": "zlib_corrupt", "truncated": "zlib_truncated", "budget": "inflate_budget"}


# --------------------------------------------------------------------------
# TIFF / EXIF  (JPEG APP1, PNG eXIf)
# --------------------------------------------------------------------------
_TIFF_SZ = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 129: 1}      # 129 = UTF-8 text (EXIF 3.0)
_GPS_TAGS = {0x0002: "lat", 0x0004: "lon", 0x0014: "destlat", 0x0016: "destlon"}
_XP_TAGS = frozenset([0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F])
# EXIF / TIFF tags that hold text and have a registered number: only these are named by number in a location.  The tag
# number is 16 bits chosen by the file, so any other number is shown as tag~<hash>, like every other label from a file.
_EXIF_NAMED_TAGS = frozenset([0x010D, 0x010E, 0x010F, 0x0110, 0x0131, 0x0132, 0x013B, 0x013C, 0x02BC, 0x83BB, 0x8298,
                              0x9286, 0x927C, 0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F, 0xA004, 0xA420, 0xA430, 0xA431,
                              0xA432, 0xA433, 0xA434, 0xA435, 0xC614, 0xC62F, 0xC68B])


def _exif_tag_label(tag):
    return "tag0x%04x" % tag if tag in _EXIF_NAMED_TAGS else "tag~" + sha8(struct.pack(">H", tag))


def scan_tiff(sink, carrier, buf):
    rp, f = sink.rp, sink.file
    n = len(buf)
    if n < 8 or buf[:2] not in (b"II", b"MM"):
        rp.error(f, "exif_bad_header", carrier)
        return
    e = "<" if buf[:2] == b"II" else ">"
    if struct.unpack(e + "H", buf[2:4])[0] != 42:
        rp.error(f, "exif_bad_header", carrier)
        return
    queue = [(struct.unpack(e + "I", buf[4:8])[0], "ifd")]
    visited, ifds, texts, gps, bad = set(), 0, 0, {}, False
    while queue and ifds < 16:
        off, kind = queue.pop(0)
        if (off, kind) in visited:           # keyed by kind: one offset may legitimately be both an
            continue                         # Exif IFD and the GPS IFD (a hostile file can arrange that)
        if off < 8 or off + 2 > n:
            bad = True
            continue
        visited.add((off, kind))
        ifds += 1
        cnt = struct.unpack(e + "H", buf[off:off + 2])[0]
        if cnt > 1024:
            cnt, bad = 1024, True
        for i in range(cnt):
            p = off + 2 + 12 * i
            if p + 12 > n:
                bad = True
                break
            tag, typ, count = struct.unpack(e + "HHI", buf[p:p + 8])
            field = buf[p + 8:p + 12]
            tsz = _TIFF_SZ.get(typ)
            if tsz is None:
                bad = True                       # a value type we cannot read: reported as a problem, not skipped
                continue
            size = tsz * count
            if size <= 4:
                data = field[:size]
            elif size > (1 << 20):
                bad = bad or kind == "gps"
                if typ in (2, 129) or (typ in (1, 7) and size >= 8):
                    rp.error(f, "exif_tag_too_big", carrier)          # a text tag we do not read; never a silent skip
                continue
            else:
                voff = struct.unpack(e + "I", field)[0]
                if voff + size > n:
                    bad = bad or kind == "gps" or tag in (0x8769, 0x8825, 0xA005)
                    continue
                data = buf[voff:voff + size]
            if tag in (0x8769, 0xA005, 0x8825) and typ in (4, 13) and len(data) >= 4:
                queue.append((struct.unpack(e + "I", data[:4])[0], "gps" if tag == 0x8825 else "ifd"))
                continue
            if kind == "gps" and tag in _GPS_TAGS:
                gps[tag] = (typ, data)
                continue
            if typ in (2, 129) or (typ in (1, 7) and size >= 8) or (tag in _XP_TAGS and typ == 1):
                texts += 1
                if texts > MAX_EXIF_TEXTS:
                    if texts == MAX_EXIF_TEXTS + 1:
                        rp.error(f, "exif_text_cap", carrier)         # never a silent skip
                    continue
                if tag in _XP_TAGS:
                    txt = data.decode("utf-16-le", "replace")
                elif tag == 0x9286 and len(data) > 8:
                    txt = decode_bytes(data[8:])
                else:
                    txt = decode_bytes(data)
                process_blob(sink, carrier, _exif_tag_label(tag), txt.rstrip("\x00"))
        q = off + 2 + 12 * cnt
        if q + 4 <= n:
            nxt = struct.unpack(e + "I", buf[q:q + 4])[0]
            if nxt:
                queue.append((nxt, "ifd"))
    if queue and ifds >= 16:
        bad = True
    present = [t for t in (0x0002, 0x0004, 0x0014, 0x0016) if t in gps]
    if present:
        raw = b""
        nonzero = False
        for t in present:
            typ, data = gps[t]
            raw += data
            if typ == 5 and len(data) >= 8:
                vals = struct.unpack(e + "%dI" % (len(data) // 4), data[:(len(data) // 4) * 4])
                nonzero = nonzero or any(vals[k] != 0 and vals[k + 1] != 0 for k in range(0, len(vals) - 1, 2))
            else:
                nonzero = nonzero or any(data)
        if nonzero:
            names = ",".join(_GPS_TAGS[t] for t in present)
            sink.add(carrier, "G1", "exif:GPS", raw, detail="kind=exif_gps;tags=" + names)
    if bad:
        rp.error(f, "exif_malformed", carrier)


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------
PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_NOTEXT = frozenset([b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"sBIT",
                         b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"acTL", b"fcTL", b"fdAT", b"cICP",
                         b"mDCV", b"cLLI", b"oFFs", b"pCAL", b"sCAL", b"sTER", b"iCCP"])
_PNG_TEXT = (b"tEXt", b"zTXt", b"iTXt")
# Largest legal payload of the fixed-layout chunks.  A chunk that is longer than its format allows carries
# something else; the excess is scanned as text instead of being trusted because the chunk type is "known".
_PNG_MAXLEN = {b"IHDR": 13, b"IEND": 0, b"gAMA": 4, b"cHRM": 32, b"sRGB": 1, b"sBIT": 4, b"bKGD": 6,
               b"hIST": 512, b"pHYs": 9, b"tIME": 7, b"acTL": 8, b"fcTL": 26, b"cICP": 4, b"mDCV": 24,
               b"cLLI": 8, b"oFFs": 9, b"sTER": 1, b"PLTE": 768, b"tRNS": 256}
# chunks that start with a NUL-terminated name: the name is text and is scanned
_PNG_NAMED = (b"sPLT", b"iCCP")
_PNG_SMALLTEXT = (b"pCAL", b"sCAL")


def _png_type_ok(t):
    return len(t) == 4 and all((65 <= c <= 90) or (97 <= c <= 122) for c in t)


def _png_raw_profile(sink, carrier, label, body, tags):
    """'Raw profile type exif' (ImageMagick, exiftool): name, byte count, then the profile as hex."""
    toks = decode_bytes(body).split()
    if len(toks) < 3:
        return
    try:
        raw = bytes.fromhex("".join(toks[2:])[:2 * PAYLOAD_CAP])
    except ValueError:
        sink.rp.error(sink.file, "png_raw_profile_bad_hex", carrier)
        return
    if toks[0].lower().startswith("exif"):
        scan_tiff(sink, carrier, raw[6:] if raw[:6] == b"Exif\x00\x00" else raw)
    else:
        scan_runs(sink, carrier, label + "/profile", raw, 8, tags)


def png_text_chunk(sink, ctype, data):
    rp, f = sink.rp, sink.file
    carrier = "png:" + ctype.decode("ascii")
    nul = data.find(b"\x00")
    if nul < 0:
        rp.error(f, "png_bad_text_chunk", carrier)
        kw, rest = data[:79], b""
        body = data
    else:
        kw, rest = data[:nul], data[nul + 1:]
        body = rest
    if not (1 <= len(kw) <= 79):
        rp.error(f, "png_bad_keyword", carrier)
    compressed, extras, trailing = False, [], []
    if ctype == b"zTXt" and nul >= 0:
        if len(rest) < 1 or rest[0] != 0:
            rp.error(f, "png_unknown_compression", carrier)
            body = rest[1:] if rest else b""
        else:
            body, st, tail = inflate_full(rest[1:], sink.inflate_left)
            compressed = True
            sink.inflate_left -= len(body)
            if st != "ok":
                rp.error(f, "png_" + _INFLATE_ERR[st], carrier)
            elif tail:
                trailing.append(tail)                           # bytes after the end of the zlib stream
    elif ctype == b"iTXt" and nul >= 0:
        flag, method = (rest[0], rest[1]) if len(rest) >= 2 else (0, 0)
        p1 = rest.find(b"\x00", 2)
        p2 = rest.find(b"\x00", p1 + 1) if p1 >= 0 else -1
        if len(rest) < 2 or p1 < 0 or p2 < 0:
            rp.error(f, "png_bad_text_chunk", carrier)
            body = rest[2:]
        else:
            extras = [rest[2:p1], rest[p1 + 1:p2]]            # language tag, translated keyword
            body = rest[p2 + 1:]
            if flag == 1:
                if method != 0:
                    rp.error(f, "png_unknown_compression", carrier)
                else:
                    body, st, tail = inflate_full(body, sink.inflate_left)
                    sink.inflate_left -= len(body)
                    if st != "ok":
                        rp.error(f, "png_" + _INFLATE_ERR[st], carrier)
                    elif tail:
                        trailing.append(tail)
                compressed = True
            elif flag != 0:
                rp.error(f, "png_bad_compression_flag", carrier)
    if _looks_zlib(body) or _looks_gzip(body):
        # a payload that is itself compressed (zlib inside zlib, or a zlib stream in a plain tEXt chunk)
        body, peeled = inflate_layers(sink, rp, carrier, body, trailing)
        compressed = compressed or peeled
    tags = ("H3",) if compressed else ()
    label = "%s[%s]" % (ctype.decode("ascii"), safe_png_kw(kw))
    kind = process_blob(sink, carrier, label, body, tags)
    if decode_bytes(kw).lower().startswith("raw profile type"):
        _png_raw_profile(sink, carrier, label, body, tags)
    for k, ex in enumerate(extras):
        if len(ex) >= 6:
            process_blob(sink, carrier, label + ("/lang" if k == 0 else "/tkw"), ex, tags)
    if nul >= 0 and len(kw) >= 6:
        process_blob(sink, carrier, label + "/kw", kw[:79 * 4])    # a key can sit in the keyword itself
    for k, tl in enumerate(trailing):
        process_blob(sink, carrier, label + "/trailing", tl[:PAYLOAD_CAP])
    if kind in ("api", "ui") and safe_png_kw(kw) in ("prompt", "workflow", "extra_pnginfo"):
        rp.note(f, "embedded_comfyui_%s_json" % kind)
    return kind


def png_other_chunk(sink, tname, data):
    """A chunk that is neither text nor EXIF (a private or unregistered type): its text is scanned.  When the payload is
    itself a zlib or gzip stream it is inflated first (under the same size and ratio limits as a compressed text chunk),
    and what it holds is reported with the H3 tag, like a secret in a compressed text chunk.  A stream that merely compresses very
    well (a mostly empty layer) is not a bomb here: only the size limits apply, not the ratio limit."""
    carrier = "png:" + tname
    if _looks_zlib(data) or _looks_gzip(data):
        trailing = []
        body, peeled = inflate_layers(sink, sink.rp, carrier, data, trailing, ratio=False)
        if peeled:
            scan_runs(sink, carrier, tname + "/inflated", body, 8, ("H3",))
            for tl in trailing:
                scan_runs(sink, carrier, tname + "/trailing", tl[:PAYLOAD_CAP], 8)
            return
    scan_runs(sink, carrier, tname, data, 8)


def png_recover(src, sink, pos):
    """Chunk walk lost sync: carve text chunks by marker, then scan what is left as raw text.  Every carved
    region ends at the next marker, so the work is linear in the bytes left (a forged length in front of each
    marker cannot make each carve re-read the whole remainder)."""
    rest = src.read_at(pos, PAYLOAD_CAP)
    sink.force_fallback = True
    try:
        marks = []
        for marker in _PNG_TEXT:
            j = rest.find(marker)
            while j != -1:
                tick()
                if j >= 4:
                    marks.append((j, marker))
                j = rest.find(marker, j + 4)
        marks.sort()
        for idx, (j, marker) in enumerate(marks):
            tick()
            ln = struct.unpack(">I", rest[j - 4:j])[0]
            end = j + 4 + ln if ln <= len(rest) else len(rest)
            if idx + 1 < len(marks):
                end = min(end, max(j + 4, marks[idx + 1][0] - 4))
            png_text_chunk(sink, marker, rest[j + 4:end])
        scan_runs(sink, "png:raw", "raw", rest, 8)
    finally:
        sink.force_fallback = False


def scan_png(src, sink, depth=0):
    rp, f = sink.rp, sink.file
    size = src.size
    pos, seen_iend, first, crc_bad, nchunks = 8, False, True, 0, 0
    while pos + 8 <= size:
        nchunks += 1
        tick()
        if nchunks > MAX_PNG_CHUNKS:
            rp.error(f, "png_chunk_cap", "png")
            return
        hdr = src.read_at(pos, 8)
        ln, ctype = struct.unpack(">I", hdr[:4])[0], hdr[4:8]
        if not _png_type_ok(ctype) or ln > 0x7FFFFFFF:
            rp.error(f, "png_bad_chunk", "png")
            png_recover(src, sink, pos)
            return
        if first and ctype != b"IHDR":
            rp.error(f, "png_bad_structure", "png")
        first = False
        dstart = pos + 8
        dend = dstart + ln
        truncated = dend + 4 > size
        avail = max(0, min(ln, size - dstart))
        crc_calc = zlib.crc32(ctype)
        tname = safe_png_type(ctype)
        if ctype in _PNG_NOTEXT:
            mx = _PNG_MAXLEN.get(ctype)
            if avail > PAYLOAD_CAP and (mx is not None or ctype in _PNG_NAMED + _PNG_SMALLTEXT):
                rp.error(f, "png_chunk_too_big", "png:" + tname)         # far longer than its format allows: not skipped quietly
                if not truncated:
                    crc_calc = crc_stream(src, dstart, ln, crc_calc)
            elif (mx is not None and avail > mx and avail <= PAYLOAD_CAP) or (
                    ctype in _PNG_NAMED + _PNG_SMALLTEXT and 0 < avail <= PAYLOAD_CAP):
                data = src.read_at(dstart, avail)
                crc_calc = zlib.crc32(data, crc_calc) & 0xFFFFFFFF
                if ctype in _PNG_NAMED:
                    name = data[:data.find(b"\x00")] if b"\x00" in data[:256] else data[:80]
                    if len(name) >= 6:
                        process_blob(sink, "png:" + tname, tname + "/name", name)
                elif ctype in _PNG_SMALLTEXT:
                    scan_runs(sink, "png:" + tname, tname, data, 6)
                else:
                    rp.note(f, "png_chunk_longer_than_format")
                    scan_runs(sink, "png:" + tname, tname + "/excess", data, 6)
            elif not truncated:
                crc_calc = crc_stream(src, dstart, ln, crc_calc)
        elif avail > PAYLOAD_CAP:
            rp.error(f, "png_chunk_too_big", "png:" + tname)
            if not truncated:
                crc_calc = crc_stream(src, dstart, ln, crc_calc)
        else:
            data = src.read_at(dstart, avail)
            crc_calc = zlib.crc32(data, crc_calc) & 0xFFFFFFFF
            if ctype in _PNG_TEXT:
                png_text_chunk(sink, ctype, data)
            elif ctype == b"eXIf":
                scan_tiff(sink, "png:eXIf", data[6:] if data[:6] == b"Exif\x00\x00" else data)
            else:
                png_other_chunk(sink, tname, data)
        if truncated:
            rp.error(f, "png_truncated", "png")
            return
        if struct.unpack(">I", src.read_at(dend, 4))[0] != (crc_calc & 0xFFFFFFFF):
            crc_bad += 1
        pos = dend + 4
        if ctype == b"IEND":
            seen_iend = True
            break
    if crc_bad:
        rp.error(f, "png_crc_mismatch", "png")
    if not seen_iend:
        rp.error(f, "png_no_iend", "png")
        if pos < size:
            png_recover(src, sink, pos)
        return
    if pos < size:
        rp.note(f, "png_trailing_data")
        tail = src.read_at(pos, PAYLOAD_CAP)
        if size - pos > PAYLOAD_CAP:
            rp.error(f, "png_trailing_too_big", "png:trailing")
        if tail[:8] == PNG_SIG and depth < 2:
            scan_png(BytesSrc(tail), sink, depth + 1)
        else:
            scan_runs(sink, "png:trailing", "trailing", tail, 8)


# --------------------------------------------------------------------------
# JPEG
# --------------------------------------------------------------------------
def _jpeg_skip_entropy(src, pos, size):
    cur = pos
    while cur < size:
        blk = src.read_at(cur, 1 << 20)
        if not blk:
            break
        j = 0
        while True:
            k = blk.find(b"\xff", j)
            if k < 0:
                cur += len(blk)
                break
            if k + 1 >= len(blk):
                if cur + k + 1 >= size:
                    return size
                cur += k                      # re-read starting at this 0xFF
                break
            nb = blk[k + 1]
            if nb == 0 or 0xD0 <= nb <= 0xD7:
                j = k + 2
                continue
            return cur + k
    return size


def _jpeg_segment(sink, m, payload):
    if m == 0xE1:
        if payload[:6] == b"Exif\x00\x00" or payload[:5] == b"Exif\x00":
            scan_tiff(sink, "jpeg:exif", payload[6:])
        elif payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            process_blob(sink, "jpeg:xmp", "APP1-xmp", payload[29:])
        elif payload.startswith(b"http://ns.adobe.com/xmp/extension/\x00"):
            process_blob(sink, "jpeg:xmp", "APP1-xmp-ext", payload[35:])
        else:
            scan_runs(sink, "jpeg:app1", "APP1", payload, 8)
    elif m == 0xFE:
        process_blob(sink, "jpeg:com", "COM", payload)
    elif 0xE0 <= m <= 0xEF:
        if payload.startswith((b"JFIF\x00", b"ICC_PROFILE\x00", b"Adobe\x00", b"MPF\x00")):
            return
        scan_runs(sink, "jpeg:app%d" % (m - 0xE0), "APP%d" % (m - 0xE0), payload, 8)


def scan_jpeg(src, sink, depth=0):
    rp, f = sink.rp, sink.file
    size = src.size
    pos, eoi, nseg = 2, False, 0
    while pos < size:
        nseg += 1
        tick()
        if nseg > MAX_JPEG_SEGMENTS:
            rp.error(f, "jpeg_segment_cap", "jpeg")
            return
        hdr = src.read_at(pos, 4)
        if len(hdr) < 2:
            break
        if hdr[0] != 0xFF:
            rp.error(f, "jpeg_bad_marker", "jpeg")
            rest = src.read_at(pos, PAYLOAD_CAP)
            sink.force_fallback = True
            try:
                scan_runs(sink, "jpeg:raw", "raw", rest, 8)
            finally:
                sink.force_fallback = False
            return
        m = hdr[1]
        if m == 0xFF:
            pos += 1
            continue
        if m == 0xD9:
            pos, eoi = pos + 2, True
            break
        if m in (0x00, 0x01) or 0xD0 <= m <= 0xD8:
            pos += 2
            continue
        if len(hdr) < 4:
            break
        seglen = (hdr[2] << 8) | hdr[3]
        if seglen < 2:
            rp.error(f, "jpeg_bad_segment", "jpeg")
            return
        plen = seglen - 2
        payload = src.read_at(pos + 4, plen)
        _jpeg_segment(sink, m, payload)
        if len(payload) < plen:
            break
        pos += 2 + seglen
        if m == 0xDA:
            pos = _jpeg_skip_entropy(src, pos, size)
    if not eoi:
        rp.error(f, "jpeg_truncated", "jpeg")
        return
    if pos < size:
        rp.note(f, "jpeg_trailing_data")
        tail = src.read_at(pos, PAYLOAD_CAP)
        if size - pos > PAYLOAD_CAP:
            rp.error(f, "jpeg_trailing_too_big", "jpeg:trailing")
        if tail[:3] == b"\xff\xd8\xff" and depth < 2:
            scan_jpeg(BytesSrc(tail), sink, depth + 1)
        else:
            scan_runs(sink, "jpeg:trailing", "trailing", tail, 8)


# --------------------------------------------------------------------------
# MP4 / MOV  (pure-python ISO-BMFF / QuickTime box walker + ffprobe as a second witness)
# --------------------------------------------------------------------------
# stbl is walked: its sample tables are skipped below, but an unknown box inside it is a hiding place
_MP4_DESCEND = frozenset([b"moov", b"trak", b"mdia", b"minf", b"udta", b"edts", b"dinf", b"moof", b"traf",
                          b"mvex", b"clip", b"matt", b"sinf", b"schi", b"meta", b"mfra", b"stbl"])
_MP4_SKIP = frozenset([b"stts", b"stsc", b"stsz", b"stz2", b"stco", b"co64", b"ctts", b"stss", b"stsd",
                       b"stsh", b"stdp", b"sdtp", b"sbgp", b"sgpd", b"subs", b"saiz", b"saio", b"elst",
                       b"tfra", b"trun", b"tfhd", b"tfdt", b"mfhd", b"vmhd", b"smhd", b"hmhd", b"nmhd",
                       b"dref", b"mvhd", b"tkhd", b"mdhd", b"trex", b"sidx", b"mdat", b"tref", b"mfro",
                       b"mehd", b"cslg", b"padb"])
# Boxes with a fixed layout, or a count followed by fixed-size entries: bytes beyond the layout are not part
# of the box's job and are scanned as hidden data (a key tucked into mvhd, a table with extra rows ...).
_MP4_FIXED = {b"mvhd": (100, 112), b"tkhd": (84, 96), b"mdhd": (24, 36), b"vmhd": (12, 12), b"smhd": (8, 8),
              b"hmhd": (20, 20), b"nmhd": (4, 4), b"mfhd": (8, 8), b"mehd": (8, 12), b"trex": (24, 24),
              b"tfdt": (8, 12), b"mfro": (8, 8)}
_MP4_TABLES = {b"stts": (8, 8), b"ctts": (8, 8), b"stsc": (8, 12), b"stco": (8, 4), b"co64": (8, 8),
               b"stss": (8, 4)}
_MP4_TOP_KNOWN = frozenset([b"ftyp", b"styp", b"moov", b"mdat", b"moof", b"mfra", b"sidx", b"ssix", b"meta",
                            b"pdin", b"prft", b"emsg", b"uuid"])
_MP4_PADDING = (b"free", b"skip", b"junk", b"wide")
_XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")
_MP4_FIRST = frozenset([b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot", b"styp", b"moof",
                        b"junk", b"uuid", b"sidx"])

_ATOM_NAMES = {b"\xa9cmt": "comment", b"\xa9des": "description", b"desc": "description", b"\xa9nam": "title",
               b"\xa9too": "encoder", b"\xa9ART": "artist", b"\xa9alb": "album", b"\xa9day": "date",
               b"cprt": "copyright", b"\xa9wrt": "composer", b"\xa9gen": "genre", b"\xa9swr": "software",
               b"\xa9inf": "info", b"\xa9xyz": "location", b"\xa9mak": "make", b"\xa9mod": "model",
               b"titl": "title", b"dscr": "description", b"auth": "author", b"perf": "artist",
               b"kywd": "keywords", b"\xa9aut": "author", b"\xa9cpy": "copyright", b"ldes": "description",
               b"\xa9grp": "grouping", b"\xa9lyr": "lyrics"}
_TAG_VOCAB = frozenset([
    "comment", "description", "title", "artist", "album", "encoder", "prompt", "workflow", "copyright",
    "author", "software", "genre", "date", "creation_time", "handler_name", "language", "synopsis",
    "keywords", "composer", "info", "location", "make", "model", "extra_pnginfo", "comfyui", "grouping",
    "lyrics", "major_brand", "minor_version", "compatible_brands", "vendor_id", "encoded_by",
    "com.apple.quicktime.comment", "com.apple.quicktime.description", "com.apple.quicktime.title"])


def safe_tag_name(name):
    s = str(name).strip().lower()
    if s.startswith("com.apple.quicktime."):
        s = s[len("com.apple.quicktime."):]
    return s if s in _TAG_VOCAB else "tag~" + sha8(str(name))


def _is_padding(data):
    return len(data) == 0 or data.count(data[:1]) == len(data)


def mp4_tag(sink, label, name, raw, carrier="mp4:tag"):
    text = decode_bytes(raw).strip("\x00")
    if not text.strip():
        return
    sname = safe_tag_name(name)
    span = []
    kind = process_blob(sink, carrier, label, text, span_out=span)
    if kind in ("api", "ui") or (kind and sname in ("prompt", "workflow", "extra_pnginfo", "comfyui")):
        # M1 is keyed on the workflow JSON itself, not on the text around it: the same tag mirrored into a
        # QuickTime atom (which carries a few header bytes) and into ffprobe's view is one leak, not two
        body = text[span[0]:span[1]] if span else text
        sink.add(carrier, "M1", label, body, detail="workflow_json_in_tag;format=%s;tag=%s" % (kind, sname))
    if sname in ("location",) or label.endswith("ISO6709"):
        m = _ISO6709.match(text.strip())
        if m:
            sink.add(carrier, "G1", label, m.group(0), detail="kind=iso6709_location")


_ISO6709 = re.compile(r"[+-][0-9]{1,3}\.[0-9]{2,8}[+-][0-9]{1,3}\.[0-9]{2,8}")


def _mp4_hidden(src, sink, typ, pstart, plen, label, usertype=None, lead=b"", binary_ok=True):
    """A box whose payload ffprobe never shows.  `lead` = header bytes that are themselves printable
    text (a text blob appended where a box header was expected): scanned together with the payload.
    binary_ok=False (a second mdat): report M1 only when the payload is text or yields a finding."""
    rp, f = sink.rp, sink.file
    if plen > PAYLOAD_CAP:
        rp.error(f, "mp4_box_too_big", "mp4:box:" + safe_box_type(typ))
    data = src.read_at(pstart, min(plen, PAYLOAD_CAP))
    carrier = "mp4:box:" + safe_box_type(typ)
    if usertype == _XMP_UUID:
        process_blob(sink, "mp4:xmp", label, data)
        return
    if _is_padding(data) and not lead:
        return
    scan_data = lead + data
    before = len(rp.findings)
    try:
        total = sum(len(r) for r in printable_runs(scan_data, 6))
        textual = total >= 0.8 * len(scan_data)
        if textual:
            process_blob(sink, carrier, label, scan_data.strip(b"\x00"))
        else:
            for r in printable_runs(scan_data, 6):
                process_blob(sink, carrier, label, r)
    except RunOverflow:
        rp.error(f, "text_run_cap", carrier)
        textual = False
    if binary_ok or textual or len(rp.findings) > before:
        sink.add(carrier, "M1", label, data, detail="hidden_box;payload=%s" % ("text" if textual else "binary"))


def _mp4_expected(src, typ, pstart):
    """Payload length a fixed-layout or table box should have, or None when the layout is unknown."""
    if typ in _MP4_FIXED:
        v0, v1 = _MP4_FIXED[typ]
        if v0 == v1:
            return v0
        ver = src.read_at(pstart, 1)
        return v1 if ver and ver[0] == 1 else v0
    head = src.read_at(pstart, 12)
    if typ in _MP4_TABLES and len(head) >= 8:
        base, es = _MP4_TABLES[typ]
        return base + struct.unpack(">I", head[4:8])[0] * es
    if typ == b"stsz" and len(head) >= 12:
        ss, cnt = struct.unpack(">II", head[4:12])
        return 12 + (0 if ss else 4 * cnt)
    if typ == b"elst" and len(head) >= 8:
        return 8 + struct.unpack(">I", head[4:8])[0] * (20 if head[0] == 1 else 12)
    return None


def _mp4_is_fragmented(src):
    """True when a top-level moof / sidx / styp / mfra exists: such a file legitimately has many mdat boxes."""
    pos, n = 0, 0
    while pos + 8 <= src.size and n < MAX_BOXES:
        hdr = src.read_at(pos, 16)
        size, typ = struct.unpack(">I", hdr[:4])[0], hdr[4:8]
        if typ in (b"moof", b"sidx", b"styp", b"mfra"):
            return True
        if size == 1 and len(hdr) >= 16:
            size = struct.unpack(">Q", hdr[8:16])[0]
        if size < 8:
            break
        pos += size
        n += 1
    return False


def _mp4_keys(src, pstart, plen, sink=None, label="keys"):
    """The key names of a QuickTime `keys` box.  The names are text a tool chose, so each is scanned like any other tag text;
    a box that is too big to read, an entry that does not fit, or fewer entries than the count says is a reported problem
    (a key whose name is lost would hide the value stored under it)."""
    rp = sink.rp if sink is not None else None
    if plen > PAYLOAD_CAP and rp is not None:
        rp.error(sink.file, "mp4_box_too_big", "mp4:box:keys")
    data = src.read_at(pstart, min(plen, PAYLOAD_CAP))
    names = []
    if len(data) < 8:
        return names
    count = struct.unpack(">I", data[4:8])[0]
    if count > MAX_MP4_ITEMS and rp is not None:
        rp.error(sink.file, "mp4_item_cap", "mp4:box:keys")
    want = min(count, MAX_MP4_ITEMS)
    p = 8
    while len(names) < want and p + 8 <= len(data):
        tick()
        sz = struct.unpack(">I", data[p:p + 4])[0]
        if sz < 8 or p + sz > len(data):
            break
        name = data[p + 8:p + sz].decode("utf-8", "replace")
        names.append(name)
        if sink is not None and len(name) >= 6:
            process_blob(sink, "mp4:box:keys", label + "/key", name)
        p += sz
    if len(names) < want and rp is not None:
        rp.error(sink.file, "mp4_bad_box", "mp4:box:keys")
    return names


def _mp4_children(src, start, end, limit=MAX_MP4_ITEMS, sink=None):
    """Yield (type, payload_start, payload_len) for the immediate children of a box.  When there are more than `limit`
    children the rest is not read, and (if a sink is given) that is reported as a problem."""
    pos, n = start, 0
    while pos + 8 <= end:
        if n >= limit:
            if sink is not None:
                sink.rp.error(sink.file, "mp4_item_cap", "mp4:box")
            return
        hdr = src.read_at(pos, 16)
        size, typ, hl = struct.unpack(">I", hdr[:4])[0], hdr[4:8], 8
        if size == 1 and len(hdr) >= 16:
            size, hl = struct.unpack(">Q", hdr[8:16])[0], 16
        elif size == 0:
            size = end - pos
        if size < hl:
            if sink is not None:
                sink.rp.error(sink.file, "mp4_bad_box", "mp4:box")        # the children after it were not read
            return
        box_end = min(pos + size, end)
        yield typ, pos + hl, max(0, box_end - pos - hl)
        pos = box_end
        n += 1


def _c_string(data, p):
    """(bytes, next position) of the NUL-terminated string at p; a string that starts with a UTF-16 byte-order mark
    ends at a 16-bit NUL."""
    if data[p:p + 2] in (b"\xfe\xff", b"\xff\xfe"):
        q = p + 2
        while q + 1 < len(data) and data[q:q + 2] != b"\x00\x00":
            q += 2
        return data[p:q], min(q + 2, len(data))
    q = data.find(b"\x00", p)
    if q < 0:
        q = len(data)
    return data[p:q], min(q + 1, len(data))


def _mp4_loci(src, sink, pstart, plen, label):
    """The 3GPP location box (`loci`), which is where ffmpeg puts a `location` tag in an .mp4: version/flags, a
    language, a place name, a role byte, longitude, latitude and altitude as signed 16.16 fixed-point numbers, then
    the name of the body and free notes.  A non-zero position is GPS (G1); the text fields are scanned like any
    other tag text.  An all-zero position is a 'no fix' record and is not reported."""
    data = src.read_at(pstart, plen)
    carrier = "mp4:box:loci"
    if len(data) < 6:
        sink.rp.error(sink.file, "mp4_bad_box", carrier)
        return
    name, p = _c_string(data, 6)
    if p + 13 > len(data):
        sink.rp.error(sink.file, "mp4_bad_box", carrier)
        return
    lon, lat, alt = struct.unpack(">iii", data[p + 1:p + 13])
    place = data[p + 1:p + 13]
    body, p = _c_string(data, p + 13)
    notes, p = _c_string(data, p)
    if (lon or lat) and abs(lon) <= (180 << 16) and abs(lat) <= (90 << 16):
        sink.loci_gps = sink.add(carrier, "G1", label, place, detail="kind=loci_location") or sink.loci_gps
    for raw in (name, body, notes):
        text = decode_bytes(raw).strip("\x00")
        if text.strip():
            process_blob(sink, carrier, label, text)


def _mp4_ilst(src, sink, start, end, label, keys):
    rp = sink.rp
    pos = start
    n = 0
    while pos + 8 <= end:
        if n >= MAX_MP4_ITEMS:
            rp.error(sink.file, "mp4_item_cap", "mp4:box:ilst")        # the items after this one were not read
            return
        tick()
        hdr = src.read_at(pos, 8)
        size, typ = struct.unpack(">I", hdr[:4])[0], hdr[4:8]
        if size < 8:
            rp.error(sink.file, "mp4_bad_box", "mp4")
            return
        item_end = min(pos + size, end)
        idx = struct.unpack(">I", typ)[0]
        shown = None                      # label for an atom type we have no name for: never its four bytes
        if keys and 1 <= idx <= len(keys):
            name = keys[idx - 1]
        elif typ in _ATOM_NAMES:
            name = _ATOM_NAMES[typ]
        else:
            name, shown = "", safe_box_type(typ)
        mean = nm = None
        datas = []
        others = []                       # name, mean and unknown children: text in them is scanned like any other text
        for ct, ps, pl in _mp4_children(src, pos + 8, item_end, sink=sink):
            if ct == b"data":
                datas.append((ps, pl))
            else:
                others.append((ct, ps, pl))
                if ct == b"name":
                    nm = decode_bytes(src.read_at(ps + 4, min(pl, 4096))[0:]).strip("\x00")
                elif ct == b"mean":
                    mean = True
        if typ == b"----" and nm:
            name, shown = nm, None
        if name.lower().endswith("iso6709"):
            name = "location"
        ilabel = "%s/%s" % (label, shown or safe_tag_name(name))
        for ct, ps, pl in others:
            if pl > NESTED_BOX_CAP:
                rp.error(sink.file, "mp4_box_too_big", "mp4:box:" + safe_box_type(ct))
                pl = NESTED_BOX_CAP
            scan_runs(sink, "mp4:box:" + safe_box_type(ct), "%s/%s" % (ilabel, safe_box_type(ct)),
                      src.read_at(ps, pl), 8)
        for ps, pl in datas:
            if pl > PAYLOAD_CAP:
                rp.error(sink.file, "mp4_box_too_big", "mp4:tag")
                continue
            payload = src.read_at(ps, pl)
            ind = struct.unpack(">I", payload[:4])[0] & 0xFFFFFF if len(payload) >= 4 else 0
            value = payload[8:]
            if ind in (0, 1, 2, 3, 4, 5, 6) or ind > 30:
                mp4_tag(sink, ilabel, name, value)
            else:
                scan_runs(sink, "mp4:tag", ilabel + "(bin)", value, 8)
        pos = item_end
        n += 1


def _mp4_nested_text(src, sink, typ, pstart, plen, label, cap=NESTED_BOX_CAP):
    """A box below the top level whose layout is unknown (or whose declared layout does not fit): its text is scanned for
    keys, addresses and the like, up to `cap` bytes, and a larger payload is reported as a problem.  `cap` is NESTED_BOX_CAP
    for a box the scanner does not recognise and PAYLOAD_CAP for a box that is known but has no layout to check (dref, stsd,
    sdtp, saiz ...: a long video can legitimately have several megabytes of those)."""
    rp, f = sink.rp, sink.file
    if plen <= 0:
        return
    if plen > cap:
        rp.error(f, "mp4_box_too_big", "mp4:box:" + safe_box_type(typ))
        plen = cap
    data = src.read_at(pstart, plen)
    name = _ATOM_NAMES.get(typ)
    try:
        for run in printable_runs(data, 4 if name else 8):
            mp4_tag(sink, label, name or "", run, carrier="mp4:" + ("tag" if name else "box"))
    except RunOverflow:
        rp.error(f, "text_run_cap", "mp4:box")


def _mp4_walk(src, sink, start, end, depth, path, state, top, keys_holder):
    rp, f = sink.rp, sink.file
    pos = start
    while pos + 8 <= end:
        state["boxes"] += 1
        tick()
        if state["boxes"] > MAX_BOXES:
            rp.error(f, "mp4_box_cap", "mp4")
            return
        hdr = src.read_at(pos, 16)
        size, typ, hl = struct.unpack(">I", hdr[:4])[0], hdr[4:8], 8
        if size == 1:
            if len(hdr) < 16:
                rp.error(f, "mp4_truncated", "mp4")
                return
            size, hl = struct.unpack(">Q", hdr[8:16])[0], 16
        elif size == 0:
            size = end - pos
        if size < hl:
            rp.error(f, "mp4_bad_box", "mp4")
            tail = src.read_at(pos, min(end - pos, PAYLOAD_CAP))
            if not _is_padding(tail):
                _mp4_hidden(src, sink, b"tail", pos, len(tail), path + "/tail" if path else "tail")
            return
        trunc = pos + size > end
        box_end = min(pos + size, end)
        pstart = pos + hl
        usertype = None
        if typ == b"uuid":
            usertype = src.read_at(pstart, 16)
            pstart += 16
        plen = max(0, box_end - pstart)
        label = (path + "/" if path else "") + safe_box_type(typ)
        if trunc:
            rp.error(f, "mp4_truncated", "mp4:box:" + safe_box_type(typ))
        if typ in _MP4_DESCEND:
            if depth >= MAX_BOX_DEPTH:
                rp.error(f, "mp4_depth", "mp4")
            else:
                cs = pstart
                if typ == b"meta":
                    peek = src.read_at(pstart, 8)
                    cs = pstart if peek[4:8] in (b"hdlr", b"keys", b"ilst") else pstart + 4
                _mp4_walk(src, sink, cs, box_end, depth + 1, label, state, False, keys_holder)
        elif typ == b"keys":
            keys_holder[0] = _mp4_keys(src, pstart, plen, sink, label)
        elif typ == b"ilst":
            _mp4_ilst(src, sink, pstart, box_end, label, keys_holder[0])
        elif typ in _MP4_PADDING or typ == b"uuid" or (top and typ not in _MP4_TOP_KNOWN
                                                       and typ not in _MP4_SKIP):
            lead = hdr[:hl] if all(32 <= c < 127 for c in hdr[:4]) else b""
            _mp4_hidden(src, sink, typ, pstart, plen, label, usertype, lead)
        elif typ == b"mdat" and top:
            # the first mdat is the media.  Another one in a file that is not fragmented is not part of any
            # sample table: it is scanned like an appended box
            state["mdats"] += 1
            if state["mdats"] > 1 and not state["fragmented"]:
                _mp4_hidden(src, sink, typ, pstart, plen, label + "/extra", binary_ok=False)
        elif typ in _MP4_SKIP and typ != b"mdat":
            exp = _mp4_expected(src, typ, pstart)
            if exp is None:
                _mp4_nested_text(src, sink, typ, pstart, plen, label, PAYLOAD_CAP)        # dref, stsd ...: no layout to check against
            elif plen > exp:
                _mp4_hidden(src, sink, typ, pstart + exp, plen - exp, label + "/excess")
            elif plen < exp:
                rp.error(f, "mp4_bad_box", "mp4:box:" + safe_box_type(typ))   # a table that claims more entries than it holds, or a short fixed box
                _mp4_nested_text(src, sink, typ, pstart, plen, label, PAYLOAD_CAP)
        elif typ == b"loci":
            if plen > NESTED_BOX_CAP:
                rp.error(f, "mp4_box_too_big", "mp4:box:loci")          # only the first 1 MiB is read
            _mp4_loci(src, sink, pstart, min(plen, NESTED_BOX_CAP), label)
        elif plen > 0:
            _mp4_nested_text(src, sink, typ, pstart, plen, label)             # includes an mdat nested below the top level
        if trunc:
            return
        pos = box_end
    if top and pos < end:
        tail = src.read_at(pos, end - pos)
        if not _is_padding(tail):
            _mp4_hidden(src, sink, b"tail", pos, len(tail), "trailing")


def scan_mp4(src, sink):
    state = {"boxes": 0, "mdats": 0, "fragmented": _mp4_is_fragmented(src)}
    _mp4_walk(src, sink, 0, src.size, 0, "", state, True, [None])


def same_dir(a, b):
    """True or False when two paths do or do not name the same folder, whatever their spelling (an extended-length prefix, a
    share path, a short name, a junction, a symbolic link); None when that cannot be told.  Folders are compared by identity
    (os.stat), and by their resolved text when the file system gives no file identifiers."""
    try:
        sa, sb = os.stat(a), os.stat(b)
        if sa.st_ino or sb.st_ino:
            return os.path.samestat(sa, sb)
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))
    except (OSError, ValueError):
        return None


def find_program(name):
    """Full path of the program `name`, looked up only in the absolute directories listed on PATH, never in the
    current folder.  (The library lookup on Windows searches the current folder first, so a file called ffprobe.exe
    or ffprobe.bat planted in a folder you scan from would run.)  On Windows only `<name>.exe` counts.  This is the
    only place the scripts read the environment (PATH); None when the program is not found."""
    try:
        here = os.getcwd()
    except OSError:
        here = None
    for d in os.get_exec_path():
        if not d or not os.path.isabs(d):
            continue
        if here is not None and same_dir(d, here) is not False:      # the current folder under any spelling, or an entry we cannot identify
            continue
        cand = os.path.join(d, name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def ffprobe_scan(path, sink, real=None):
    """`path` is the name shown in reports; `real` (default: the same) is what the walker opened, and what ffprobe is given,
    so the file ffprobe describes is the file that was scanned (a name Windows would rewrite, such as `a.mp4.`, is not
    the file `a.mp4`)."""
    exe = find_program("ffprobe")
    rp = sink.rp
    if not exe:
        rp.ffprobe = "absent"
        return
    rp.ffprobe = "used"
    target = fs_path(path if real is None else real)
    if not os.path.isabs(target):
        target = os.path.abspath(target)          # (never on an absolute path: abspath would drop the trailing dot of "a.mp4.")
    try:
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = 0x08000000                    # CREATE_NO_WINDOW
        r = subprocess.run([exe, "-v", "error", "-protocol_whitelist", "file", "-print_format", "json",
                            "-show_format", "-show_streams", "-show_chapters", "-i",
                            "file:" + target],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=30, **kw)
        doc = json.loads(r.stdout.decode("utf-8", "replace")) if r.returncode == 0 else None
    except subprocess.TimeoutExpired:
        rp.note(sink.file, "ffprobe_timeout")
        return
    except Exception:
        rp.note(sink.file, "ffprobe_failed")
        return
    if not isinstance(doc, dict):
        rp.note(sink.file, "ffprobe_failed")
        return
    groups = []
    if isinstance(doc.get("format"), dict):
        groups.append(("format", doc["format"].get("tags")))
    for k in ("streams", "chapters"):
        for i, item in enumerate(doc.get(k) or []):
            if isinstance(item, dict):
                groups.append(("%s[%d]" % (k, i), item.get("tags")))
    sink.force_fallback = True        # only report what the box walker has not already reported
    try:
        for where, tags in groups:
            if isinstance(tags, dict):
                for name, val in tags.items():
                    if isinstance(val, str) and val.strip():
                        mp4_tag(sink, "ffprobe/%s/%s" % (where, safe_tag_name(name)), str(name), val,
                                carrier="mp4:ffprobe")
    finally:
        sink.force_fallback = False


# --------------------------------------------------------------------------
# file dispatch, directory walk
# --------------------------------------------------------------------------
_UNSUPPORTED_MAGIC = (b"GIF8", b"RIFF", b"\x1a\x45\xdf\xa3", b"OggS", b"fLaC", b"ID3", b"%PDF", b"BM",
                      b"II*\x00", b"MM\x00*", b"PK\x03\x04", b"\x00\x00\x01\x00")
_UNSUPPORTED_EXTS = frozenset([".webp", ".gif", ".webm", ".mkv", ".avi", ".flac", ".wav", ".mp3", ".ogg",
                               ".tif", ".tiff", ".bmp", ".ico", ".pdf", ".psd", ".exr",
                               ".heic", ".heif", ".hif", ".avif", ".jxl", ".jp2"])
# HEIC / HEIF / AVIF photos (the iPhone default) are ISO-BMFF files like MP4, but their EXIF and XMP sit in items inside
# the first mdat, which this scanner does not read.  They must not be walked as an MP4 and reported as "nothing found".
# What marks one: its file extension, a HEIF brand as the major brand or among the compatible brands of the ftyp box
# (an AVIF can carry an encoder-specific major brand and name "avif" only as a compatible brand), or a top-level meta box
# whose handler is `pict`.
_HEIF_BRANDS = frozenset([b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs", b"mif1", b"msf1",
                          b"avif", b"avis", b"miaf"])
_HEIF_EXTS = frozenset([".heic", ".heif", ".hif", ".avif"])
_RENDER_EXTS = frozenset([".png", ".jpg", ".jpeg", ".mp4", ".mov", ".m4v", ".json"])
JSON_FILE_CAP = 256 << 20


_WIN_RESERVED = frozenset(["con", "prn", "aux", "nul", "conin$", "conout$"] +
                          ["com%d" % k for k in range(1, 10)] + ["lpt%d" % k for k in range(1, 10)])


def _odd_win_name(name):
    """A Windows name that the Win32 layer would rewrite: a reserved device name (nul, con, aux, com1 ...) or a
    name ending in a dot or a space."""
    return name.endswith((".", " ")) or name.split(".")[0].rstrip(" ").lower() in _WIN_RESERVED


def force_prefix(p):
    """The extended-length form of an absolute Windows path: no name normalisation, so 'nul', 'x.png.' and
    'y.png ' are the files they are."""
    if os.name != "nt" or p.startswith("\\\\?\\") or p.startswith("\\\\.\\"):
        return p
    ap = os.path.abspath(p)
    if ap.startswith("\\\\.\\"):                    # a device name such as "nul" resolves to \\.\nul: leave it
        return ap
    return "\\\\?\\UNC\\" + ap[2:] if ap.startswith("\\\\") else "\\\\?\\" + ap


def fs_path(p):
    """Path as handed to the OS: long Windows paths get the extended-length prefix."""
    if os.name == "nt":
        ap = os.path.abspath(p)
        if len(ap) >= 248 and not ap.startswith("\\\\?\\"):
            return force_prefix(p)
    return p


def child_path(parent_os, name):
    """OS path of an entry found while walking: a name Windows would rewrite is reached through the prefixed
    parent, so the entry listed is the entry opened."""
    if os.name == "nt" and _odd_win_name(name):
        parent_os = force_prefix(parent_os)
    return os.path.join(parent_os, name)


def is_link_st(st):
    """True for symlinks and Windows junctions/mount points (not for cloud placeholders)."""
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(st, "st_file_attributes", 0) & 0x400:
        return getattr(st, "st_reparse_tag", 0) in (0xA000000C, 0xA0000003)
    return False


def _heif_like(src, ext):
    """True when a file that looks like an MP4 is a HEIC / HEIF / AVIF image container (see _HEIF_BRANDS)."""
    if ext in _HEIF_EXTS:
        return True
    head = src.read_at(0, 16)
    if len(head) >= 16 and head[4:8] == b"ftyp":
        size = struct.unpack(">I", head[:4])[0]
        box = src.read_at(0, min(size if size >= 16 else 16, 1 << 16))
        brands = [box[8:12]] + [box[i:i + 4] for i in range(16, len(box) - 3, 4)]       # (12:16 is the minor version)
        if any(b in _HEIF_BRANDS for b in brands):
            return True
    pos, n = 0, 0
    while pos + 8 <= src.size and n < 64:
        hdr = src.read_at(pos, 16)
        size, typ, hl = struct.unpack(">I", hdr[:4])[0], hdr[4:8], 8
        if size == 1 and len(hdr) >= 16:
            size, hl = struct.unpack(">Q", hdr[8:16])[0], 16
        elif size == 0:
            size = src.size - pos
        if size < hl:
            break
        if typ == b"meta":
            end = min(pos + size, src.size)
            peek = src.read_at(pos + hl, 8)
            first = pos + hl + (0 if peek[4:8] in (b"hdlr", b"keys", b"ilst") else 4)
            for ct, ps, _pl in _mp4_children(src, first, end, limit=8):
                if ct == b"hdlr" and src.read_at(ps + 8, 4) == b"pict":
                    return True
        pos += size
        n += 1
    return False


def sniff(head):
    if head.startswith(PNG_SIG):
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if len(head) >= 12 and head[4:8] in _MP4_FIRST:
        return "mp4"
    s = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if s[:1] in (b"{", b"["):
        return "json"
    if head.startswith(_UNSUPPORTED_MAGIC):
        return "unsupported"
    return None


def open_regular(path):
    """Open for reading without following a last-moment symlink or blocking on a FIFO; the type is
    re-checked on the open handle (the lstat in scan_file can be raced)."""
    p = fs_path(path)
    if os.name == "nt":
        f = open(p, "rb")
    else:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        f = os.fdopen(os.open(p, flags), "rb")
    try:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("not a regular file")
    except BaseException:
        f.close()
        raise
    return f


def scan_file(path, rp, max_bytes, use_ffprobe, explicit, real=None):
    """`path` is the name shown in reports; `real` (default: the same) is what the OS is asked to open."""
    real = path if real is None else real
    try:
        st = os.lstat(fs_path(real))
    except OSError:
        rp.error(path, "unreadable")
        return
    if not stat.S_ISREG(st.st_mode):
        if explicit:
            rp.error(path, "not_a_regular_file")
        else:
            rp.skip(path, False)
        return
    size = st.st_size
    ext = os.path.splitext(path)[1].lower()
    try:
        f = open_regular(real)
    except OSError:
        rp.error(path, "unreadable")
        return
    with f:
        try:
            head = f.read(32)
        except OSError:
            rp.error(path, "unreadable")
            return
        kind = sniff(head)
        if kind == "mp4" and _heif_like(FileSrc(f, size), ext):
            kind = "unsupported"                                # an image in an MP4-style container: not opened
        if kind is None and ext == ".json":
            kind = "json"
        if kind is None:
            if ext in _UNSUPPORTED_EXTS:
                rp.unsupported += 1
                rp.error(path, "unsupported_media")
            elif explicit or ext in _RENDER_EXTS:
                rp.error(path, "unrecognized_content" if size else "empty_file")
            else:
                rp.skip(path, False)
            return
        if kind == "unsupported":
            rp.unsupported += 1
            rp.error(path, "unsupported_media")
            return
        if size > max_bytes:
            rp.error(path, "too_big")
            return
        if kind == "json" and size > JSON_FILE_CAP:
            rp.error(path, "too_big")
            return
        rp.files_scanned += 1
        sink = Sink(rp, path)
        budget_start()
        try:
            src = FileSrc(f, size)
            if kind == "png":
                scan_png(src, sink)
            elif kind == "jpeg":
                scan_jpeg(src, sink)
            elif kind == "mp4":
                scan_mp4(src, sink)
                if use_ffprobe:
                    ffprobe_scan(path, sink, real)
            else:
                f.seek(0)
                process_blob(sink, "json:file", "file", f.read(JSON_FILE_CAP))
        except ScanBudget:
            rp.error(path, "time_budget")
        except MemoryError:
            rp.error(path, "out_of_memory")
        except RecursionError:
            rp.error(path, "recursion_limit")
        except OSError:
            rp.error(path, "read_error")
        except Exception as ex:                        # never leak a traceback / exception text
            rp.error(path, "internal_error_" + type(ex).__name__)
        finally:
            _BUDGET["deadline"] = None


def iter_files(root, rp, max_depth, max_files):
    """Yield (shown_path, os_path) for every regular file under root.  Links are not followed.  The OS path is
    built on the (prefixed) parent without any name normalisation, see fs_path."""
    stack, count = [(root, root, 0)], 0
    while stack:
        d, dr, depth = stack.pop()
        try:
            with os.scandir(fs_path(dr)) as it:
                names = sorted(e.name for e in it)
        except OSError:
            rp.error(d, "dir_unreadable")
            continue
        subdirs = []
        for name in names:
            p = os.path.join(d, name)
            pr = child_path(dr, name)
            try:
                st = os.lstat(fs_path(pr))
            except OSError:
                rp.error(p, "unreadable")
                continue
            if is_link_st(st):
                rp.skip(p, True)
            elif stat.S_ISDIR(st.st_mode):
                if depth + 1 > max_depth:
                    rp.error(p, "walk_depth_cap")
                else:
                    subdirs.append((p, pr))
            elif stat.S_ISREG(st.st_mode):
                count += 1
                if count > max_files:
                    rp.error(root, "walk_file_cap")
                    return
                yield p, pr
            else:
                rp.skip(p, False)
        stack.extend((sd, sdr, depth + 1) for sd, sdr in reversed(subdirs))


# --------------------------------------------------------------------------
# report rendering
# --------------------------------------------------------------------------
def result_code(rp):
    if rp.findings or rp.dropped:
        return EXIT_FINDINGS
    return EXIT_UNSCANNED if rp.errors else EXIT_CLEAN


def to_json_doc(rp, exit_code):
    return {
        "tool": "share-safe-renders/scan.py", "version": VERSION, "exit_code": exit_code,
        "summary": {"files_scanned": rp.files_scanned, "files_with_findings": len(rp.files_with_findings),
                    "findings": sum(1 for x in rp.findings if "companion_of" not in x),
                    "records": len(rp.findings), "errors": len(rp.errors),
                    "links_not_followed": rp.skipped_links, "skipped_unrecognized": rp.skipped_other,
                    "unsupported_media": rp.unsupported, "ffprobe": rp.ffprobe,
                    "records_dropped": sum(rp.dropped.values()), "dropped_by_class": dict(rp.dropped)},
        "findings": rp.findings, "errors": rp.errors, "info": rp.info, "known_misses": KNOWN_MISSES,
        "note": "The 'file' fields are file-system names and untrusted text; treat them as data."}


_SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def result_line(rp, exit_code, json_failed=False):
    """The verdict in words plus the exit code the process will really return.  A clean scan whose requested --json
    report could not be written returns 2, and the line says so (it never says exit 0 for a run that returns 2)."""
    final = EXIT_USAGE if (json_failed and exit_code == EXIT_CLEAN) else exit_code
    if final == EXIT_USAGE:
        verdict = "NOT A PASS - nothing was found in what was scanned, but the --json report could not be written"
    else:
        verdict = {EXIT_CLEAN: "NOTHING FOUND in what was scanned (this is not proof of safety; see known misses)",
                   EXIT_FINDINGS: "FINDINGS - do not share these files as they are",
                   EXIT_UNSCANNED: "COULD NOT SCAN everything and found nothing else - treat as NOT clean"}[exit_code]
    if exit_code == EXIT_CLEAN and (rp.skipped_links or rp.skipped_other):
        verdict += "; NOTE %d link(s) not followed and %d unrecognized file(s) skipped were NOT examined " \
                   "(add --strict to make that exit 3)" % (rp.skipped_links, rp.skipped_other)
    return "RESULT: %s (exit %d)" % (verdict, final)


def render_human(rp, exit_code, json_failed=False):
    out = ["Share-Safe Renders scan.py %s" % VERSION]
    primary = [x for x in rp.findings if "companion_of" not in x]
    comps = {}
    for x in rp.findings:
        if "companion_of" in x:
            comps.setdefault((x["file"], x["carrier"], x["location"], x["sha256_prefix"], x["length"]),
                             []).append(x["class"])
    dropped = sum(rp.dropped.values())
    out.append("Scanned %d file(s): %d with findings, %d finding(s), %d problem(s); %d link(s) not followed, "
               "%d unrecognized file(s) skipped; ffprobe: %s."
               % (rp.files_scanned, len(rp.files_with_findings), len(primary) + dropped, len(rp.errors),
                  rp.skipped_links, rp.skipped_other, rp.ffprobe))
    if json_failed:
        out.append("REPORT NOT WRITTEN: the --json file was not created or updated. Do not read it (it is missing, or "
                   "it is left over from an earlier run); use this printed report and pick another report name.")
    # the verdict is printed twice, here and as the last line, so output that is cut off at either end still shows it
    result = result_line(rp, exit_code, json_failed)
    out.append(result)
    if primary:
        out.append("")
        out.append("FINDINGS (values are never printed: only class, place, length and a hash prefix)")
        shown = sorted(primary, key=lambda x: _SEV_RANK.get(x["severity"], 1))     # stable: high severity first
        for x in shown[:MAX_PRINT_FINDINGS]:
            extra = comps.get((x["file"], x["carrier"], x["location"], x["sha256_prefix"], x["length"]), [])
            cls = x["class"] + "".join("+" + t for t in sorted(set(extra)))
            out.append("  [%s] %s  file=%s  carrier=%s  location=%s  node=%s  bypassed=%s  length=%d  sha256=%s%s"
                       % (x["severity"].upper(), cls, disp_path(x["file"]), x["carrier"], x["location"],
                          x["node_id"] if x["node_id"] is not None else "-", "yes" if x["bypassed"] else "no",
                          x["length"], x["sha256_prefix"], ("  (%s)" % x["detail"]) if x["detail"] else ""))
        if len(shown) > MAX_PRINT_FINDINGS or dropped:
            per = {}
            for x in shown[MAX_PRINT_FINDINGS:]:
                per[x["class"]] = per.get(x["class"], 0) + 1
            for c, k in rp.dropped.items():
                per[c] = per.get(c, 0) + k
            out.append("  ... %d more finding(s) not listed here (by class: %s); the --json report has %s"
                       % (len(shown) - min(len(shown), MAX_PRINT_FINDINGS) + dropped,
                          ", ".join("%s=%d" % (c, per[c]) for c in sorted(per)),
                          ("the first %d of them" % len(shown)) if dropped else "all of them"))
    if rp.errors:
        out.append("")
        out.append("COULD NOT FULLY SCAN (never treat these as clean)")
        for e in rp.errors[:MAX_PRINT_FINDINGS]:
            out.append("  ERROR %s  file=%s%s" % (e["code"], disp_path(e["file"]),
                                                   ("  carrier=%s" % e["carrier"]) if e["carrier"] else ""))
        if len(rp.errors) > MAX_PRINT_FINDINGS:
            out.append("  ... %d more problem(s) in the --json report" % (len(rp.errors) - MAX_PRINT_FINDINGS))
    if rp.info:
        out.append("")
        out.append("NOTES")
        for n in rp.info[:MAX_PRINT_FINDINGS]:
            out.append("  %s  file=%s" % (n["code"], disp_path(n["file"])))
        if len(rp.info) > MAX_PRINT_FINDINGS:
            out.append("  ... %d more note(s) in the --json report" % (len(rp.info) - MAX_PRINT_FINDINGS))
    out.append("")
    out.append("KNOWN MISSES (not detected by design)")
    for m in KNOWN_MISSES:
        out.append("  - " + m)
    out.append("")
    out.append(result)
    return "\n".join(out)


def _mute_std(which):
    try:
        setattr(sys, which, open(os.devnull, "w"))
    except Exception:
        pass


def _setup_stdio():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
        except Exception:
            pass


def _write_out(text):
    """Write the report; a closed or broken stdout (reader gone, closed with >&-) never changes the exit code."""
    out = sys.stdout
    if out is None:
        return False
    try:
        out.write(text)
        out.flush()
        return True
    except (OSError, ValueError, AttributeError, UnicodeError):
        _mute_std("stdout")
        return False


def _quiet_flush():
    """Flush both streams; a stream that cannot be flushed is swapped for the null device so that interpreter
    shutdown does not turn a good exit code into 120."""
    for which in ("stdout", "stderr"):
        s = getattr(sys, which, None)
        if s is None:
            continue
        try:
            s.flush()
        except Exception:
            _mute_std(which)


_FIXED_USAGE = frozenset([
    "at least one PATH is required", "empty PATH", "--max-bytes must be a positive integer",
    "--max-depth must be a positive integer", "--max-files must be a positive integer",
    "--time-limit must be a number of seconds (0 = no limit)",
    "--json target is a directory or its folder does not exist", "--json would overwrite a scanned file",
    "--json target already exists and is not an earlier report of this program",
    "--json target is inside a scanned folder"])
_OPT_ERR = re.compile(r"argument (--?[a-z][a-z-]*(?:/--?[a-z][a-z-]*)*): (expected one argument)")


class _Parser(argparse.ArgumentParser):
    """Usage errors never echo what was typed: with a shell glob, file names would end up in stderr."""

    def error(self, message):
        self.print_usage(sys.stderr)
        if message in _FIXED_USAGE:
            msg = message
        elif message.startswith("unrecognized arguments"):
            msg = "unrecognized argument(s); put every option first, then a lone '--', then any file name that starts with '-'"
        else:
            m = _OPT_ERR.fullmatch(message)
            msg = ("argument %s: %s" % (m.group(1), m.group(2))) if m else "invalid value for an option"
        sys.stderr.write("scan.py: error: %s\n" % msg)
        sys.exit(EXIT_USAGE)


def build_parser():
    ap = _Parser(prog="scan.py", allow_abbrev=False,
                 description="Find what a ComfyUI-style render (PNG, JPEG, MP4/MOV, workflow JSON) leaks "
                             "before you share it.  Exit: 0 nothing found, 1 findings, 2 usage error, "
                             "3 could not scan something (and nothing else found).")
    ap.add_argument("paths", nargs="*", metavar="PATH", help="file or directory (directories are walked; "
                    "symlinks and junctions are not followed); put '--' before a name that starts with '-'")
    ap.add_argument("--json", dest="json_out", metavar="OUT.json", help="also write a JSON report")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, metavar="N",
                    help="skip (and report as unscanned) files larger than N bytes (default %d)" % DEFAULT_MAX_BYTES)
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, metavar="N", help="directory depth cap")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, metavar="N",
                    help="files visited per directory argument")
    ap.add_argument("--time-limit", type=float, default=DEFAULT_TIME_LIMIT, metavar="SECONDS",
                    help="wall-clock budget per file; a file that runs out is reported as unscanned "
                         "(default %d, 0 = no limit)" % DEFAULT_TIME_LIMIT)
    ap.add_argument("--no-ffprobe", action="store_true", help="do not call ffprobe even if it is on PATH")
    ap.add_argument("--follow-root-links", action="store_true",
                    help="allow a PATH argument that is itself a symlink or junction")
    ap.add_argument("--strict", action="store_true",
                    help="exit 3 when links or unrecognized files were skipped, not only when a scan failed")
    ap.add_argument("--full-names", action="store_true",
                    help="print complete file names in the human report (default: names longer than 40 characters "
                         "are shortened, because a file name can carry text aimed at a reader)")
    return ap


def scan_path(p, rp, args, use_ffprobe):
    try:
        st = os.lstat(fs_path(p))
    except OSError:
        rp.error(p, "not_found")
        return
    if is_link_st(st):
        if not args.follow_root_links:
            rp.error(p, "link_not_followed")
            return
        p = os.path.realpath(p)
    if os.path.isdir(fs_path(p)):
        for shown, real in iter_files(p, rp, args.max_depth, args.max_files):
            scan_file(shown, rp, args.max_bytes, use_ffprobe, False, real)
    else:
        scan_file(p, rp, args.max_bytes, use_ffprobe, True)


_REPORT_MARK = b'"tool": "share-safe-renders/scan.py"'


def _replaceable_report(path):
    """True when `path` may be replaced by a new --json report: it is empty, or it is an earlier report written by
    this program.  Any other existing file is refused (usage error), so a wrong --json argument cannot destroy a
    user's file."""
    try:
        if not os.path.isfile(path):
            return False
        if os.path.getsize(path) == 0:
            return True
        with open(path, "rb") as fh:
            return _REPORT_MARK in fh.read(512)
    except OSError:
        return False


def _inside(child, folder):
    """True when `child` is a path below `folder`, under any spelling of either path.  Two tests: the resolved text of
    the two paths (links resolved, case ignored where the file system ignores it), and the folders themselves: each parent
    of `child` is compared with `folder` by identity (same_dir), which sees through spellings that text comparison does not
    (a \\\\?\\ prefix, a \\\\localhost\\C$ share path, a short name, a junction)."""
    try:
        c = os.path.normcase(os.path.realpath(child))
        f = os.path.normcase(os.path.realpath(folder))
        if c != f and os.path.commonpath([c, f]) == f:
            return True
    except (ValueError, OSError):
        pass
    cur = os.path.dirname(os.path.abspath(child))
    for _ in range(128):
        if same_dir(cur, folder):
            return True
        up = os.path.dirname(cur)
        if up == cur:
            break
        cur = up
    return False


def _write_json_report(path, doc):
    """Write the report to a new file made beside its final name and rename it into place, so a reader (or a second scan
    writing the same path) never sees half a file.  The temporary file is created by tempfile.mkstemp: exclusively (it can
    never be an existing file, a hard link or a symbolic link that somebody placed there), under a random name that cannot be
    guessed in advance, and readable by its owner only where the file system keeps permissions (the report keeps that
    mode after the rename).  The target is looked at
    again just before the rename, because the first look was made before the scan.  If writing fails, the partial
    `<report>.tmp-<random>` file is left next to the report: this program never deletes a file, so removing it is up to
    the user."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=os.path.basename(path) + ".tmp-")
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
    except BaseException:
        os.close(fd)
        raise
    with fh:
        json.dump(doc, fh, ensure_ascii=True, indent=2)
        fh.write("\n")
    if os.path.lexists(path) and not _replaceable_report(path):
        raise OSError("the --json target is no longer an earlier report of this program")
    os.replace(tmp, path)


def main(argv=None):
    global TIME_LIMIT
    _setup_stdio()
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.paths:
        ap.error("at least one PATH is required")
    for name in ("max_bytes", "max_depth", "max_files"):
        if getattr(args, name) < 1:
            ap.error("--%s must be a positive integer" % name.replace("_", "-"))
    if not (args.time_limit >= 0):
        ap.error("--time-limit must be a number of seconds (0 = no limit)")
    if any(p == "" for p in args.paths):
        ap.error("empty PATH")
    if args.json_out:
        jp = os.path.abspath(args.json_out)
        if os.path.isdir(jp) or not os.path.isdir(os.path.dirname(jp)):
            ap.error("--json target is a directory or its folder does not exist")
        for p in args.paths:
            try:
                if os.path.exists(jp) and os.path.samefile(jp, p):
                    ap.error("--json would overwrite a scanned file")
            except OSError:
                pass
        for p in args.paths:
            if os.path.isdir(p) and _inside(jp, p):
                ap.error("--json target is inside a scanned folder")
        if os.path.exists(jp) and not _replaceable_report(jp):
            ap.error("--json target already exists and is not an earlier report of this program")
    TIME_LIMIT = args.time_limit
    FULL_NAMES[0] = bool(args.full_names)
    use_ffprobe = not args.no_ffprobe
    rp = Report()
    rp.ffprobe = "disabled" if not use_ffprobe else "not needed"
    for p in args.paths:
        try:
            scan_path(p, rp, args, use_ffprobe)
        except Exception as ex:                       # a crash must never read as "findings" or "clean"
            rp.error(p, "internal_error_" + type(ex).__name__)
    if not rp.files_scanned and not rp.findings and (rp.skipped_links or rp.skipped_other or not rp.errors):
        rp.error("(all paths)", "nothing_scannable")  # an empty folder, or one of links / unknown files, is not a clean folder
    elif args.strict and (rp.skipped_links or rp.skipped_other):
        rp.error("(all paths)", "strict_skipped_entries")
    code = result_code(rp)                            # decided before anything is printed
    json_failed = False
    if args.json_out:
        try:
            _write_json_report(args.json_out, to_json_doc(rp, code))
        except OSError:
            json_failed = True
            try:
                sys.stderr.write("scan.py: error: could not write the --json report\n")
            except Exception:
                pass
    _write_out(render_human(rp, code, json_failed) + "\n")
    if json_failed and code == EXIT_CLEAN:
        return EXIT_USAGE                             # a clean scan whose requested report is missing is not a pass
    return code


def _entry():
    try:
        return main()
    except SystemExit:
        raise
    except BaseException as ex:                       # never a traceback, never exit 0 or 1 by accident
        try:
            sys.stderr.write("scan.py: aborted (%s); nothing can be concluded about the inputs\n"
                             % type(ex).__name__)
        except Exception:
            pass
        return EXIT_UNSCANNED


if __name__ == "__main__":
    _code = _entry()
    _quiet_flush()
    sys.exit(_code)
