#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval/score.py - score a scanner against corpus/answer_key.json (reusable, any scanner with the same CLI).

    python eval/score.py --corpus CORPUS_DIR [--scanner PATH_TO_SCANNER.py] [--out OUTDIR]
                         [--label NAME] [--phases file,dirs,cli] [--mem-gib 4] [--quiet]

What it does (all against a corpus that make_corpus.py generated; nothing else is read):
  file  phase  every registered file is scanned on its own (--json), then
                 * exit code vs expected_exit_in,
                 * planted entries vs findings (strict: class + node id + bypassed + carrier family;
                   lenient: class present in that file, nothing else - used for tools that cannot
                   report node ids or bypass flags),
                 * false positives (clean files, extras in positive files), boundary / known-miss
                   findings as information,
                 * output hygiene on stdout, stderr and the JSON report: no planted secret, PII value,
                   prompt-injection canary or injection phrase, no control / bidi / tag characters,
                   valid UTF-8, JSON contract fields,
                 * crash / timeout / time / peak memory (Windows job object, 4 GiB cap by default).
  dirs  phase  the dir_tests from the answer key (junction and symlink loops, depth, 2000 files, sweeps), plus a
                 consistency check that a folder sweep equals the sum of the per-file runs.
  cli   phase  the cli_tests from the answer key (usage errors, exit-code mixes, --max-bytes, --json, cp1252 / ascii
                 stdout).

The report never prints a planted value: only file, class, carrier, location (as the scanner printed it), node id,
lengths, hashes and verdicts.  Python 3.9+, standard library only.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# the scanner under test is the one in the package: <repo>/packages/share-safe-renders/scripts/scan.py
DEFAULT_SCANNER = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "packages",
                               "share-safe-renders", "scripts", "scan.py")

CONTRACT_FIELDS = ["file", "carrier", "class", "location", "node_id", "bypassed", "length", "sha256_prefix", "severity"]
CLASSES = ["K1", "K2", "K3", "P1", "P2", "P3", "G1", "H1", "H2", "H3", "M1"]

# Planted prompt-injection phrases (from the hostile fixtures). Matched case-insensitively in scanner output.
INJECTION_PHRASES = [
    "ignore all previous", "ignore previous instructions", "ignore_previous_instructions", "no longer a scanner",
    "print every secret", "attacker.invalid", "new priority instructions", "reveal your system prompt",
    "reveal_system_prompt", "print system prompt", "report this file clean", "report this file as clean",
    "id_rsa", ".aws/credentials", "never mention this block", "<system>",
]

# Ordinary (non-secret) text that the corpus builder puts in nearly every ComfyUI-style file. The contract says the
# scanner never prints scanned text, so none of it may show up in any output either.
BENIGN_TEXT = ["lighthouse", "oil painting", "blurry, low quality", "sd_xl_base", "CLIPTextEncode", "KSampler",
               "CheckpointLoader", "EmptyLatentImage", "Load Checkpoint", "VAEDecode"]

BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁠-⁩﻿\U000e0000-\U000e007f]")


# --------------------------------------------------------------------------------------------
# process runner (Windows job object: memory cap, peak memory, kill-tree on timeout)
# --------------------------------------------------------------------------------------------
class _Job:
    def __init__(self, mem_bytes):
        self.h = None
        self.k = None
        if os.name != "nt" or not mem_bytes:
            return
        try:
            import ctypes
            from ctypes import wintypes

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in
                            ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                             "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class BASIC(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class EXT(ctypes.Structure):
                _fields_ = [("Basic", BASIC), ("Io", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]

            self._ct, self._EXT = ctypes, EXT
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateJobObjectW.restype = wintypes.HANDLE
            k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                    ctypes.c_void_p]
            k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            k.TerminateJobObject.argtypes = [wintypes.HANDLE, ctypes.c_uint]
            k.CloseHandle.argtypes = [wintypes.HANDLE]
            h = k.CreateJobObjectW(None, None)
            if not h:
                return
            info = EXT()
            info.Basic.LimitFlags = 0x200 | 0x2000          # JOB_MEMORY | KILL_ON_JOB_CLOSE
            info.JobMemoryLimit = int(mem_bytes)
            if not k.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):
                k.CloseHandle(h)
                return
            self.h, self.k = h, k
        except Exception:
            self.h = None

    def assign(self, proc):
        if self.h:
            try:
                self.k.AssignProcessToJobObject(self.h, int(proc._handle))
            except Exception:
                pass

    def kill(self):
        if self.h:
            try:
                self.k.TerminateJobObject(self.h, 1)
            except Exception:
                pass

    def peak_mb(self):
        if not self.h:
            return None
        try:
            info = self._EXT()
            if self.k.QueryInformationJobObject(self.h, 9, self._ct.byref(info), self._ct.sizeof(info), None):
                return round(info.PeakJobMemoryUsed / 1048576.0, 1)
        except Exception:
            pass
        return None

    def close(self):
        if self.h:
            try:
                self.k.CloseHandle(self.h)
            except Exception:
                pass
            self.h = None


def run_scanner(scanner, args, timeout, mem_gib=4.0, env_extra=None, cwd=None):
    """Run `python scanner args`; return dict(exit, out, err, secs, peak_mb, timeout, crash_hint)."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    cmd = [sys.executable, scanner] + list(args)
    job = _Job(int(mem_gib * 1024 ** 3) if mem_gib else 0)
    t0 = time.perf_counter()
    timed_out = False
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env,
                             cwd=cwd or tempfile.gettempdir())
    except Exception as exc:                                    # pragma: no cover
        return {"exit": None, "out": b"", "err": ("spawn failed: %s" % type(exc).__name__).encode(), "secs": 0.0,
                "peak_mb": None, "timeout": False}
    job.assign(p)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        job.kill()
        p.kill()
        try:
            out, err = p.communicate(timeout=20)
        except Exception:
            out, err = b"", b""
    secs = time.perf_counter() - t0
    peak = job.peak_mb()
    job.close()
    return {"exit": p.returncode, "out": out, "err": err, "secs": round(secs, 3), "peak_mb": peak,
            "timeout": timed_out}


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def fwd(p):
    return p.replace("\\", "/")


def rel_of(path, root_fwd):
    """Map a path as printed by a scanner to the corpus-relative key (or None)."""
    if not isinstance(path, str):
        return None
    p = fwd(path)
    if p.lower().startswith(root_fwd.lower() + "/"):
        return p[len(root_fwd) + 1:]
    return None


def load_json_bytes(b):
    try:
        return json.loads(b.decode("utf-8-sig"))
    except Exception:
        return None


def all_json_strings(o, out, depth=0):
    if depth > 60:
        return
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                out.append(k)
            all_json_strings(v, out, depth + 1)
    elif isinstance(o, list):
        for v in o:
            all_json_strings(v, out, depth + 1)
    elif isinstance(o, str):
        out.append(o)


def sha8_ok(x):
    return isinstance(x, str) and re.fullmatch(r"[0-9a-f]{8}", x) is not None


def carrier_norm(c):
    """Scanner carrier ('png:tEXt', 'mp4:box:free', ...) -> answer-key vocabulary."""
    if not isinstance(c, str):
        return "?"
    p = c.split(":")
    fam = p[0].lower()
    sub = p[1] if len(p) > 1 else ""
    if fam == "png":
        m = {"tEXt": "png-tEXt", "zTXt": "png-zTXt", "iTXt": "png-iTXt", "eXIf": "png-eXIf", "trailing": "png-trailer",
             "trailer": "png-trailer", "raw": "raw-bytes"}
        return m.get(sub, "png-other")
    if fam == "jpeg":
        m = {"exif": "jpeg-exif", "xmp": "jpeg-xmp", "com": "jpeg-com"}
        return m.get(sub, "jpeg-other")
    if fam in ("mp4", "mov"):
        if sub == "box" or sub == "xmp":
            return "mp4-box"
        return "mp4-tag"
    if fam in ("json", "raw"):
        return "raw-bytes"
    return c


def carrier_family(c):
    c = c or ""
    f = c.split("-")[0].split(":")[0].lower()
    return "iso" if f in ("mp4", "mov") else f


def sha8_of(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:8]


_ECHOABLE_ID = re.compile(r"[0-9]{1,6}(?::[0-9]{1,6})?", re.ASCII)


def node_match(want, got):
    """Planted node id vs the id a scanner printed. A scanner prints a plain id (a whole number of up to 6 digits, or two of
    them joined by a colon) as it is, and any other id in a sanitised form 'id~<8 hex digits>'. Since scan.py 1.2.0 that hash is
    keyed with a random key made for each run, so it cannot be recomputed here: a planted id that is not echoable is matched
    by the form alone (the file, the class, the location and the carrier have to match as well)."""
    if got is None:
        return False
    got = str(got)
    want = str(want)
    if got == want or got == "id~" + sha8_of(want):          # (the second form is what the prototype 1.1.0 printed)
        return True
    return (not _ECHOABLE_ID.fullmatch(want)) and re.fullmatch(r"id~[0-9a-f]{8}", got) is not None


def carrier_exact(expected, got_norm):
    e = expected.replace("mov-", "mp4-")
    return e == got_norm


def probes_for(strings):
    """Substrings of each planted value that must never appear in output (whole value + tail + middle)."""
    out = set()
    for s in strings:
        if not isinstance(s, str) or len(s) < 5:
            continue
        out.add(s)
        if len(s) >= 28:
            out.add(s[-16:])
            m = len(s) // 2
            out.add(s[m - 8:m + 8])
    return sorted(out, key=len, reverse=True)


# --------------------------------------------------------------------------------------------
# output hygiene
# --------------------------------------------------------------------------------------------
class Hygiene:
    def __init__(self, never_echo, key_files):
        self.sec = probes_for(never_echo.get("secrets", []))
        self.pii = [p.lower() for p in probes_for(never_echo.get("pii", []))]
        self.can = [c.lower() for c in never_echo.get("canaries", []) if isinstance(c, str)]
        self.phr = INJECTION_PHRASES
        self.benign = [b.lower() for b in BENIGN_TEXT]
        self.allowed_names = []
        for rel, ent in key_files.items():
            if ent.get("filename_canary_allowed_in_file_field"):
                self.allowed_names.append(os.path.basename(rel))

    def _strip_allowed(self, text):
        for n in self.allowed_names:
            text = text.replace(n, "")
            text = text.replace(n.replace(" ", "\\ "), "")
        return text

    def check_text(self, text):
        t = self._strip_allowed(text)
        tl = t.lower()
        hits = collections.Counter()
        for s in self.sec:
            if s in t:
                hits["secret"] += 1
        for s in self.pii:
            if s in tl:
                hits["pii"] += 1
        for s in self.can:
            if s in tl:
                hits["canary"] += 1
        for s in self.phr:
            if s in tl:
                hits["phrase"] += 1
        for s in self.benign:
            if s in tl:
                hits["metadata_text"] += 1
        return hits

    def check_run(self, run, json_bytes):
        """-> dict(echo={secret:n,...}, badchars, bad_utf8, json_valid, json_fields_bad)."""
        res = {"echo": collections.Counter(), "badchars": False, "bad_utf8": False, "json_valid": None,
               "json_fields_bad": 0, "echo_where": []}
        texts = []
        for name, b in (("stdout", run["out"]), ("stderr", run["err"])):
            try:
                t = b.decode("utf-8")
            except UnicodeDecodeError:
                t = b.decode("utf-8", "replace")
                if name == "stdout":
                    res["bad_utf8"] = True
            texts.append((name, t))
            if BAD_CHARS.search(self._strip_allowed(t).replace("\r", "").replace("\n", "").replace("\t", "")):
                res["badchars"] = True
        if json_bytes is not None:
            raw = json_bytes.decode("utf-8", "replace")
            texts.append(("json-raw", raw))
            obj = load_json_bytes(json_bytes)
            res["json_valid"] = obj is not None
            if obj is not None:
                strs = []
                all_json_strings(obj, strs)
                joined = "\n".join(strs)
                texts.append(("json-strings", joined))
                if BAD_CHARS.search(self._strip_allowed(joined).replace("\n", "")):
                    res["badchars"] = True
                for f in (obj.get("findings") or []):
                    if not isinstance(f, dict):
                        res["json_fields_bad"] += 1
                        continue
                    ok = (all(k in f for k in CONTRACT_FIELDS) and isinstance(f.get("bypassed"), bool)
                          and isinstance(f.get("length"), int) and not isinstance(f.get("length"), bool)
                          and sha8_ok(f.get("sha256_prefix")) and isinstance(f.get("file"), str)
                          and (f.get("node_id") is None or isinstance(f.get("node_id"), str)))
                    if not ok:
                        res["json_fields_bad"] += 1
        for name, t in texts:
            h = self.check_text(t)
            if h:
                res["echo"].update(h)
                res["echo_where"].append(name)
        return res


# --------------------------------------------------------------------------------------------
# matching planted entries to findings
# --------------------------------------------------------------------------------------------
def match_file(expected, findings, mode):
    """mode 'strict' or 'lenient'. Returns (entry_results, finding_state).
    entry_results[i] = dict(matched, shared, exact_carrier, finding)  (finding = index or None)
    finding_state[j] = 'used' | 'companion' | 'extra_ok' | 'same_value' | 'unrelated'
    """
    prim = [j for j, f in enumerate(findings)]
    cand = []
    for i, e in enumerate(expected):
        acc = set(e.get("accept_classes") or [e["class"]])
        cs = []
        for j in prim:
            f = findings[j]
            if f.get("class") not in acc:
                continue
            if mode == "strict":
                nid = e.get("node_id")
                if nid is not None and not node_match(nid, f.get("node_id")):
                    continue
                if bool(f.get("bypassed")) != bool(e.get("bypassed")):
                    continue
                if carrier_family(carrier_norm(f.get("carrier"))) != carrier_family(e.get("carrier", "")):
                    continue
            cs.append(j)
        cand.append(cs)
    order = sorted(range(len(expected)), key=lambda i: (len(cand[i]), i))
    used = {}
    res = [None] * len(expected)
    for i in order:
        e = expected[i]
        if e.get("optional") and not cand[i]:
            res[i] = {"matched": False, "shared": False, "exact_carrier": False, "finding": None}
            continue
        pick, shared = None, False
        want = e.get("value_sha256_prefix")
        free = [j for j in cand[i] if j not in used]
        pref = [j for j in free if want and findings[j].get("sha256_prefix") == want] or free
        if pref:
            # prefer an exact-carrier, then the primary (non-companion) record
            pref.sort(key=lambda j: (not carrier_exact(e.get("carrier", ""), carrier_norm(findings[j].get("carrier"))),
                                     bool(findings[j].get("companion_of")), j))
            pick = pref[0]
        else:
            for j in cand[i]:
                u = used.get(j)
                if u is not None and want and expected[u].get("value_sha256_prefix") == want:
                    pick, shared = j, True
                    break
        if pick is not None:
            used.setdefault(pick, i)
        res[i] = {"matched": pick is not None, "shared": shared,
                  "exact_carrier": (pick is not None and carrier_exact(e.get("carrier", ""),
                                                                      carrier_norm(findings[pick].get("carrier")))),
                  "finding": pick}
    # classify every finding
    want_hashes = {e.get("value_sha256_prefix") for e in expected if e.get("value_sha256_prefix")}
    used_locs = {(findings[j].get("location"), str(findings[j].get("node_id"))) for j in used}
    used_nodes = {str(findings[j].get("node_id")) for j in used if findings[j].get("node_id") is not None}
    # classes a planted leak is expressed in (the planted class, what it accepts, and the underlying class)
    leak_classes = set()
    for e, r in zip(expected, res):
        if r and r["matched"]:
            leak_classes.update(e.get("accept_classes") or [])
            leak_classes.add(e["class"])
    state = {}
    for j, f in enumerate(findings):
        c = f.get("class")
        loc = f.get("location") or ""
        if j in used:
            state[j] = "used"
        elif f.get("companion_of") and (f.get("location"), str(f.get("node_id"))) in used_locs:
            state[j] = "companion"
        elif f.get("sha256_prefix") in want_hashes:
            state[j] = "same_value"
        elif c in leak_classes and (loc.endswith(":raw") or ":raw" in loc.split("/")[0]
                                    or (f.get("location"), str(f.get("node_id"))) in used_locs
                                    or (f.get("node_id") is not None and str(f.get("node_id")) in used_nodes)
                                    or f.get("carrier") == "mp4:ffprobe"):
            # same class as a planted leak that WAS found, reported again by the raw-text net, a second witness
            # (ffprobe), a sub-field of the same node, or as a second coordinate: a re-report, not a new claim
            state[j] = "rereport"
        else:
            state[j] = "unrelated"
    return res, state


# --------------------------------------------------------------------------------------------
# main scoring
# --------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="score a scanner against a Share-Safe Renders corpus")
    ap.add_argument("--corpus", required=True, help="corpus dir produced by corpus/make_corpus.py")
    ap.add_argument("--scanner", default=DEFAULT_SCANNER)
    ap.add_argument("--out", default=None, help="folder for the results json and the per-run reports")
    ap.add_argument("--label", default=None)
    ap.add_argument("--phases", default="file,dirs,cli")
    ap.add_argument("--mem-gib", type=float, default=4.0)
    ap.add_argument("--timeout", type=float, default=180.0, help="per-file timeout (s); heavy/ gets 5x")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--headline", choices=("strict", "lenient"), default="strict",
                    help="which matching mode drives the detailed miss / false-positive lists "
                         "(use lenient for tools that cannot report node ids or bypass flags)")
    ap.add_argument("--only", default=None, help="comma separated corpus-relative prefixes: score only those files")
    ap.add_argument("--selftest", action="store_true",
                    help="run four deliberately bad mock scanners through the harness and check it flags them")
    a = ap.parse_args()
    if a.selftest:
        return selftest(a)

    root = os.path.abspath(a.corpus)
    root_fwd = fwd(root)
    scanner = os.path.abspath(a.scanner)
    label = a.label or os.path.basename(scanner)
    out_dir = os.path.abspath(a.out) if a.out else os.path.join(tempfile.gettempdir(), "ssr_score_" + label)
    runs_dir = os.path.join(out_dir, "runs")
    os.makedirs(runs_dir, exist_ok=True)
    phases = set(x.strip() for x in a.phases.split(","))

    key = json.load(open(os.path.join(root, "answer_key.json"), encoding="utf-8"))
    never = json.load(open(os.path.join(root, key.get("never_echo_file", "never_echo.json")), encoding="utf-8"))
    files = key["files"]
    if a.only:
        pre = [x.strip() for x in a.only.split(",") if x.strip()]
        files = {k: v for k, v in files.items() if any(k.startswith(p) for p in pre)}
    hyg = Hygiene(never, key["files"])
    results = {"label": label, "scanner": fwd(scanner), "corpus": root_fwd, "python": sys.version.split()[0]}

    def log(*x):
        if not a.quiet:
            print(*x, flush=True)

    # ---------------------------------------------------------------- file phase
    per_file = {}
    if "file" in phases:
        log("[file] scanning %d registered files one by one with %s ..." % (len(files), label))
        for n, rel in enumerate(sorted(files)):
            ent = files[rel]
            path = os.path.join(root, rel.replace("/", os.sep))
            jpath = os.path.join(runs_dir, "f%04d.json" % n)
            if os.path.exists(jpath):
                os.remove(jpath)
            tmo = a.timeout * (5 if rel.startswith("heavy/") else 1)
            r = run_scanner(scanner, [path, "--json", jpath], tmo, a.mem_gib)
            jb = open(jpath, "rb").read() if os.path.exists(jpath) else None
            jobj = load_json_bytes(jb) if jb else None
            fl = []
            if isinstance(jobj, dict):
                for f in jobj.get("findings", []) or []:
                    if isinstance(f, dict):
                        g = dict(f)
                        g["_rel"] = rel_of(g.get("file"), root_fwd)
                        fl.append(g)
            errs = (jobj.get("errors") if isinstance(jobj, dict) else None) or []
            hy = hyg.check_run(r, jb)
            crash = (r["timeout"] or r["exit"] not in (0, 1, 2, 3)
                     or b"Traceback (most recent call last)" in r["err"] or b"Traceback (most recent call last)" in r["out"])
            per_file[rel] = {"entry": ent, "run": {k: v for k, v in r.items() if k not in ("out", "err")},
                             "stdout_bytes": len(r["out"]), "stderr_bytes": len(r["err"]),
                             "findings": fl, "errors": errs, "hygiene": hy, "crash": crash,
                             "json_present": jb is not None, "exit_ok": r["exit"] in ent.get("expected_exit_in", [])}
        log("[file] done")

    # ---------------------------------------------------------------- scoring (strict + lenient)
    def score(mode):
        cls = {c: {"planted": 0, "found": 0, "core_planted": 0, "core_found": 0, "ext_planted": 0, "ext_found": 0,
                   "optional_planted": 0, "optional_found": 0, "shared": 0, "exact_carrier": 0, "fp_clean": 0,
                   "fp_extra_unrelated": 0, "fp_extra_same_value": 0, "fp_extra_rereport": 0, "missed": []} for c in CLASSES}
        car = collections.defaultdict(lambda: {"planted": 0, "found": 0, "exact": 0})
        fp_clean, fp_pos, fp_same, fp_re, boundary_hits, known_hits = [], [], [], [], [], []
        misses = []
        opt_missed = []
        clean_files = clean_fp_files = 0
        boundary_files = boundary_flagged = known_files = known_flagged = 0
        for rel, pf in sorted(per_file.items()):
            ent = pf["entry"]
            grp = ent["group"]
            fl = pf["findings"]
            exp = ent.get("expected", [])
            extra_ok = set(ent.get("extra_ok_classes", []))
            res, state = match_file(exp, fl, mode)
            for e, r in zip(exp, res):
                c = e["class"]
                if e.get("optional"):
                    cls[c]["optional_planted"] += 1
                    cls[c]["optional_found"] += 1 if r["matched"] else 0
                    if not r["matched"]:
                        opt_missed.append({"file": rel, "class": c, "carrier": e["carrier"], "node_id": e.get("node_id"),
                                           "hint": e.get("location_hint"), "exit": pf["run"]["exit"]})
                    continue
                tier = e.get("tier") or ent.get("tier", "core")
                bucket = "ext" if ent.get("tier") == "extended" or tier == "extended" else "core"
                cls[c]["planted"] += 1
                cls[c]["%s_planted" % bucket] += 1
                car[e["carrier"]]["planted"] += 1
                if r["matched"]:
                    cls[c]["found"] += 1
                    cls[c]["%s_found" % bucket] += 1
                    car[e["carrier"]]["found"] += 1
                    cls[c]["shared"] += 1 if r["shared"] else 0
                    if r["exact_carrier"]:
                        cls[c]["exact_carrier"] += 1
                        car[e["carrier"]]["exact"] += 1
                else:
                    cls[c]["missed"].append(rel)
                    misses.append({"file": rel, "class": c, "carrier": e["carrier"], "node_id": e.get("node_id"),
                                   "bypassed": e.get("bypassed"), "tier": ent.get("tier"), "hint": e.get("location_hint"),
                                   "mode": mode, "exit": pf["run"]["exit"]})
            if grp == "clean":
                clean_files += 1
                if fl:
                    clean_fp_files += 1
                for f in fl:
                    if f.get("companion_of"):
                        continue
                    fp_clean.append({"file": rel, "class": f.get("class"), "carrier": f.get("carrier"),
                                     "location": f.get("location"), "node_id": f.get("node_id"),
                                     "length": f.get("length"), "sha": f.get("sha256_prefix"), "detail": f.get("detail")})
                    if f.get("class") in cls:
                        cls[f["class"]]["fp_clean"] += 1
            elif grp == "boundary":
                boundary_files += 1
                if fl:
                    boundary_flagged += 1
                for f in fl:
                    if not f.get("companion_of"):
                        boundary_hits.append({"file": rel, "class": f.get("class"), "carrier": f.get("carrier"),
                                              "location": f.get("location"), "note": ent.get("notes")})
            elif grp == "known_miss":
                known_files += 1
                if fl:
                    known_flagged += 1
                for f in fl:
                    if not f.get("companion_of"):
                        known_hits.append({"file": rel, "class": f.get("class"), "carrier": f.get("carrier"),
                                           "location": f.get("location")})
            else:                                           # positive / hostile / heavy
                for j, f in enumerate(fl):
                    st = state[j]
                    if st in ("used", "companion") or f.get("class") in extra_ok:
                        continue
                    row = {"file": rel, "class": f.get("class"), "carrier": f.get("carrier"),
                           "location": f.get("location"), "node_id": f.get("node_id"), "bypassed": f.get("bypassed"),
                           "length": f.get("length"), "sha": f.get("sha256_prefix"), "detail": f.get("detail")}
                    if st == "same_value":
                        fp_same.append(row)
                        if f.get("class") in cls:
                            cls[f["class"]]["fp_extra_same_value"] += 1
                    elif st == "rereport":
                        fp_re.append(row)
                        if f.get("class") in cls:
                            cls[f["class"]]["fp_extra_rereport"] += 1
                    else:
                        fp_pos.append(row)
                        if f.get("class") in cls:
                            cls[f["class"]]["fp_extra_unrelated"] += 1
        return {"classes": cls, "carriers": {k: v for k, v in sorted(car.items())}, "misses": misses,
                "optional_missed": opt_missed,
                "fp_clean": fp_clean, "fp_positive_unrelated": fp_pos, "fp_positive_same_value": fp_same,
                "fp_positive_rereport": fp_re,
                "clean_files": clean_files, "clean_fp_files": clean_fp_files,
                "boundary": {"files": boundary_files, "flagged": boundary_flagged, "hits": boundary_hits},
                "known_miss": {"files": known_files, "flagged": known_flagged, "hits": known_hits}}

    if per_file:
        results["strict"] = score("strict")
        results["lenient"] = score("lenient")

        # exit codes / behaviour
        grp_rows = collections.defaultdict(lambda: {"files": 0, "exit_ok": 0, "crash": 0, "echo": 0, "badchars": 0,
                                                    "bad_utf8": 0, "json_fields_bad": 0, "json_missing": 0,
                                                    "max_secs": 0.0, "max_mb": 0.0, "total_secs": 0.0})
        exit_bad, crash_rows, echo_rows, behaviour = [], [], [], []
        for rel, pf in sorted(per_file.items()):
            g = grp_rows[pf["entry"]["group"]]
            g["files"] += 1
            g["exit_ok"] += 1 if pf["exit_ok"] else 0
            g["crash"] += 1 if pf["crash"] else 0
            hy = pf["hygiene"]
            e_total = sum(hy["echo"].values())
            g["echo"] += 1 if e_total else 0
            g["badchars"] += 1 if hy["badchars"] else 0
            g["bad_utf8"] += 1 if hy["bad_utf8"] else 0
            g["json_fields_bad"] += hy["json_fields_bad"]
            g["json_missing"] += 0 if pf["json_present"] else 1
            g["max_secs"] = max(g["max_secs"], pf["run"]["secs"])
            g["total_secs"] += pf["run"]["secs"]
            g["max_mb"] = max(g["max_mb"], pf["run"]["peak_mb"] or 0.0)
            if not pf["exit_ok"]:
                exit_bad.append({"file": rel, "group": pf["entry"]["group"], "exit": pf["run"]["exit"],
                                 "expected": pf["entry"]["expected_exit_in"],
                                 "informational": pf["entry"]["group"] in ("boundary", "known_miss")})
            if pf["crash"]:
                crash_rows.append({"file": rel, "exit": pf["run"]["exit"], "timeout": pf["run"]["timeout"]})
            if e_total:
                echo_rows.append({"file": rel, "kinds": dict(hy["echo"]), "where": hy["echo_where"]})
            if pf["entry"]["group"] in ("hostile", "heavy"):
                behaviour.append({"file": rel, "exit": pf["run"]["exit"], "expected": pf["entry"]["expected_exit_in"],
                                  "secs": pf["run"]["secs"], "peak_mb": pf["run"]["peak_mb"],
                                  "crash": pf["crash"], "echo": e_total, "badchars": hy["badchars"],
                                  "bad_utf8": hy["bad_utf8"], "json_ok": hy["json_valid"],
                                  "errors": sorted(set(x.get("code", "?") for x in pf["errors"] if isinstance(x, dict)))})
        results["files"] = {rel: {"group": pf["entry"]["group"], "exit": pf["run"]["exit"], "secs": pf["run"]["secs"],
                                  "peak_mb": pf["run"]["peak_mb"], "findings": [{k: v for k, v in f.items() if k != "file"}
                                                                                for f in pf["findings"]],
                                  "errors": sorted(set(x.get("code", "?") for x in pf["errors"] if isinstance(x, dict)))}
                            for rel, pf in per_file.items()}
        results["behaviour"] = {"groups": {k: dict(v) for k, v in grp_rows.items()}, "exit_bad": exit_bad,
                                "crash": crash_rows, "echo": echo_rows, "hostile_heavy": behaviour}

    # ---------------------------------------------------------------- dirs phase
    dir_rows = []
    sweep_consistency = []
    if "dirs" in phases:
        log("[dirs] %d directory tests ..." % len(key.get("dir_tests", [])))
        for n, t in enumerate(key.get("dir_tests", [])):
            path = os.path.join(root, t["path"].replace("/", os.sep))
            jpath = os.path.join(runs_dir, "d%02d.json" % n)
            if os.path.exists(jpath):
                os.remove(jpath)
            tmo = max(float(t.get("timeout_s", 120)) * 1.0, 15.0)
            r = run_scanner(scanner, [path, "--json", jpath], tmo, a.mem_gib)
            jb = open(jpath, "rb").read() if os.path.exists(jpath) else None
            jobj = load_json_bytes(jb) if jb else None
            fl = [f for f in ((jobj or {}).get("findings") or []) if isinstance(f, dict)] if isinstance(jobj, dict) else []
            frel = collections.Counter()
            for f in fl:
                if f.get("companion_of"):
                    continue
                rr = rel_of(f.get("file"), root_fwd)
                frel[rr if rr is not None else "<unmapped:%s>" % fwd(str(f.get("file")))[-60:]] += 1
            exp_files = set(t.get("expect_files_with_findings", []))
            may = set(t.get("may_report", []))
            got = set(frel)
            problems = []
            if r["exit"] not in t["expect_exit_in"]:
                problems.append("exit %s not in %s" % (r["exit"], t["expect_exit_in"]))
            if r["timeout"]:
                problems.append("timeout")
            if t.get("every_file_has_findings"):
                allf = [k for k in files if k.startswith(t["path"].rstrip("/") + "/")]
                lack = [k for k in allf if k not in got]
                if lack:
                    problems.append("%d files without findings" % len(lack))
            elif exp_files or t["expect_exit_in"] == [0]:
                missing = exp_files - got
                extra = got - exp_files - may
                if missing:
                    problems.append("missing findings in %d expected files" % len(missing))
                if extra and not t["id"].startswith("sweep_"):
                    problems.append("%d unexpected files with findings" % len(extra))
                if t["id"] in ("sweep_clean", "sweep_boundary", "sweep_known_miss") and got:
                    problems.append("%d files with findings" % len(got))
            for sub in t.get("must_not_report_path_containing", []):
                bad = [g for g in got if sub in g and g not in exp_files and g not in may]
                if bad:
                    problems.append("reported path containing %r (%d)" % (sub, len(bad)))
            hy = hyg.check_run(r, jb)
            if sum(hy["echo"].values()):
                problems.append("ECHO in output (%s)" % ",".join(sorted(hy["echo"])))
            if hy["badchars"]:
                problems.append("control/bidi chars in output")
            if hy["bad_utf8"]:
                problems.append("stdout not valid UTF-8")
            if b"Traceback (most recent call last)" in r["err"] + r["out"]:
                problems.append("traceback")
            tier = t.get("tier")
            dir_rows.append({"id": t["id"], "tier": tier, "exit": r["exit"], "expect": t["expect_exit_in"],
                             "secs": r["secs"], "peak_mb": r["peak_mb"], "files_with_findings": len(got),
                             "problems": problems, "pass": not problems,
                             "informational": tier in ("boundary", "known_miss") and bool(problems)
                             and not any(x.startswith(("ECHO", "traceback", "timeout")) for x in problems)})
            # consistency: sweep == per-file runs
            if per_file and t["id"].startswith("sweep_") and t["id"] != "sweep_root":
                sub_prefix = t["path"].rstrip("/") + "/"
                a_ = collections.Counter()
                b_ = collections.Counter()
                for f in fl:
                    if f.get("companion_of"):
                        continue
                    rr = rel_of(f.get("file"), root_fwd)
                    a_[(rr, f.get("class"), carrier_norm(f.get("carrier")), str(f.get("node_id")), f.get("sha256_prefix"))] += 1
                for rel, pf in per_file.items():
                    if rel.startswith(sub_prefix):
                        for f in pf["findings"]:
                            if f.get("companion_of"):
                                continue
                            b_[(rel, f.get("class"), carrier_norm(f.get("carrier")), str(f.get("node_id")),
                                f.get("sha256_prefix"))] += 1
                # sweeps also cover unregistered files; compare only registered ones
                regs = {k for k in files if k.startswith(sub_prefix)}
                a2 = collections.Counter({k: v for k, v in a_.items() if k[0] in regs})
                diff = (a2 - b_) + (b_ - a2)
                sweep_consistency.append({"sweep": t["id"], "records_sweep": sum(a2.values()),
                                          "records_per_file": sum(b_.values()), "differences": sum(diff.values())})
        # whole corpus in one go (junctions, 2000 files, hostile and heavy together)
        jpath = os.path.join(runs_dir, "root.json")
        if os.path.exists(jpath):
            os.remove(jpath)
        r = run_scanner(scanner, [root, "--json", jpath], 1500, a.mem_gib)
        jb = open(jpath, "rb").read() if os.path.exists(jpath) else None
        hy = hyg.check_run(r, jb)
        pr = []
        if r["exit"] != 1:
            pr.append("exit %s (expected 1)" % r["exit"])
        if sum(hy["echo"].values()):
            pr.append("ECHO in output")
        if r["timeout"]:
            pr.append("timeout")
        if b"Traceback" in r["err"] + r["out"]:
            pr.append("traceback")
        dir_rows.append({"id": "sweep_root", "tier": None, "exit": r["exit"], "expect": [1], "secs": r["secs"],
                         "peak_mb": r["peak_mb"], "files_with_findings": None, "problems": pr, "pass": not pr})
        results["dirs"] = dir_rows
        results["sweep_consistency"] = sweep_consistency

    # ---------------------------------------------------------------- cli phase
    cli_rows = []
    if "cli" in phases:
        tests = key.get("cli_tests", [])
        log("[cli] %d cli tests ..." % len(tests))
        cdir = os.path.join(out_dir, "cli_tmp")
        os.makedirs(cdir, exist_ok=True)
        for n, t in enumerate(tests):
            args = [x.replace("{corpus}", root).replace("{tmp}", cdir) for x in t["args"]]
            jp = None
            if "--json" in args:
                i = args.index("--json")
                if i + 1 < len(args):
                    jp = args[i + 1]
                    if os.path.exists(jp):
                        os.remove(jp)
            tmo = 300
            r = run_scanner(scanner, args, tmo, a.mem_gib, env_extra=t.get("env"))
            problems = []
            if r["exit"] not in t["expected_exit_in"]:
                problems.append("exit %s not in %s" % (r["exit"], t["expected_exit_in"]))
            if r["timeout"]:
                problems.append("timeout")
            if b"Traceback" in r["err"] + r["out"]:
                problems.append("traceback")
            jb = None
            if jp and r["exit"] != 2:
                if os.path.exists(jp):
                    jb = open(jp, "rb").read()
                else:
                    problems.append("--json report missing")
            hy = hyg.check_run(r, jb)
            if sum(hy["echo"].values()):
                problems.append("ECHO")
            if jb is not None:
                if hy["json_valid"] is False:
                    problems.append("report not valid JSON")
                if hy["json_fields_bad"]:
                    problems.append("%d findings miss contract fields" % hy["json_fields_bad"])
            if r["exit"] == 2 and not r["err"] and not r["out"]:
                problems.append("usage error printed nothing")
            cli_rows.append({"n": n, "args": [os.path.basename(x) if os.sep in x or "/" in x else x for x in t["args"]],
                             "env": t.get("env"), "exit": r["exit"], "expect": t["expected_exit_in"], "secs": r["secs"],
                             "problems": problems, "pass": not problems})
        results["cli"] = cli_rows

    # ---------------------------------------------------------------- write + print
    results_path = os.path.join(out_dir, "results_%s.json" % re.sub(r"[^A-Za-z0-9_.-]", "_", label))
    with open(results_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, ensure_ascii=True, default=str)
    results["headline"] = a.headline
    print_report(results, results_path)
    return 0


# --------------------------------------------------------------------------------------------
# human report (never prints planted values)
# --------------------------------------------------------------------------------------------
def pct(a, b):
    return "%5.1f%%" % (100.0 * a / b) if b else "   n/a"


def _w(s):
    sys.stdout.buffer.write((s + "\n").encode("utf-8", "backslashreplace"))


def print_report(R, results_path):
    _w("=" * 100)
    _w("SCORE  scanner=%s  python=%s" % (R["label"], R["python"]))
    _w("corpus=%s" % R["corpus"])
    _w("results json: %s" % fwd(results_path))
    _w("=" * 100)
    for mode in ("strict", "lenient"):
        S = R.get(mode)
        if not S:
            continue
        _w("")
        _w("PER CLASS - %s matching (%s)" % (mode, "class + node id + bypassed flag + carrier family" if mode == "strict"
                                            else "class present in the file; ignores node id, bypassed, carrier"))
        _w("%-4s %7s %7s %7s | core %9s | ext %9s | opt %7s | exactCarrier | FPclean extra(unrel/sameval/rereport)"
           % ("cls", "planted", "found", "rate", "f/p", "f/p", "f/p"))
        tp = tf = 0
        for c in CLASSES:
            d = S["classes"][c]
            tp += d["planted"]
            tf += d["found"]
            _w("%-4s %7d %7d %7s | core %4d/%-4d | ext %4d/%-4d | opt %3d/%-3d | %12d | %7d %7d/%d/%d" % (
                c, d["planted"], d["found"], pct(d["found"], d["planted"]), d["core_found"], d["core_planted"],
                d["ext_found"], d["ext_planted"], d["optional_found"], d["optional_planted"], d["exact_carrier"],
                d["fp_clean"], d["fp_extra_unrelated"], d["fp_extra_same_value"], d["fp_extra_rereport"]))
        _w("%-4s %7d %7d %7s" % ("ALL", tp, tf, pct(tf, tp)))
        _w("")
        _w("PER CARRIER - %s (expected carrier vocabulary of the answer key)" % mode)
        for k, v in S["carriers"].items():
            _w("  %-12s planted %4d  found %4d  %s  exact-carrier %d" % (k, v["planted"], v["found"], pct(v["found"], v["planted"]), v["exact"]))
        _w("")
        _w("CLEAN CONTROLS: %d files, %d with findings;  boundary: %d files, %d flagged;  known_miss: %d files, %d flagged"
           % (S["clean_files"], S["clean_fp_files"], S["boundary"]["files"], S["boundary"]["flagged"],
              S["known_miss"]["files"], S["known_miss"]["flagged"]))
        _w("MISSES (%s): %d   FALSE POSITIVES: clean-file records %d, extra records on non-planted content in positive "
           "files %d;  re-reports of planted leaks: same value %d, raw-net/second-witness/sub-field %d"
           % (mode, len(S["misses"]), len(S["fp_clean"]), len(S["fp_positive_unrelated"]),
              len(S["fp_positive_same_value"]), len(S["fp_positive_rereport"])))
    S = R.get(R.get("headline", "strict"))
    if S:
        _w("")
        _w("---- MISSES (%s) ----" % R.get("headline", "strict"))
        for m in S["misses"]:
            _w("  MISS %-8s %-12s node=%-8s byp=%-5s tier=%-8s %s  [exit=%s]  hint=%s" % (
                m["class"], m["carrier"], m["node_id"], m["bypassed"], m["tier"], m["file"], m["exit"], m["hint"]))
        _w("---- optional (damaged-file) entries that were not found - allowed by the answer key ----")
        for m in S["optional_missed"]:
            _w("  OPT-MISS %-3s %-12s node=%-8s %s [exit=%s] hint=%s" % (m["class"], m["carrier"], m["node_id"], m["file"], m["exit"], m["hint"]))
        _w("---- FALSE POSITIVES: clean files ----")
        for f in S["fp_clean"]:
            _w("  FP-CLEAN %-3s %-14s %s  loc=%s node=%s len=%s" % (f["class"], f["carrier"], f["file"], f["location"], f["node_id"], f["length"]))
        _w("---- extra records on NON-planted content in positive/hostile files (the README counts these as false positives) ----")
        for f in S["fp_positive_unrelated"]:
            _w("  FP-EXTRA %-3s %-14s %s  loc=%s node=%s len=%s" % (f["class"], f["carrier"], f["file"], f["location"], f["node_id"], f["length"]))
        _w("---- re-reports of a planted leak that was also found (README counts them as extras; same secret, other span or location) ----")
        for f in S["fp_positive_same_value"]:
            _w("  REREPORT same-hash  %-3s %-14s %s  loc=%s node=%s" % (f["class"], f["carrier"], f["file"], f["location"], f["node_id"]))
        for f in S["fp_positive_rereport"]:
            _w("  REREPORT other-span %-3s %-14s %s  loc=%s node=%s len=%s" % (f["class"], f["carrier"], f["file"], f["location"], f["node_id"], f["length"]))
        _w("---- boundary-tier files that were flagged (judgement calls, not failures) ----")
        for f in S["boundary"]["hits"]:
            _w("  BOUNDARY %-3s %-14s %s  loc=%s" % (f["class"], f["carrier"], f["file"], f["location"]))
        _w("---- known-miss files that produced findings (informational) ----")
        for f in S["known_miss"]["hits"]:
            _w("  KNOWN    %-3s %-14s %s  loc=%s" % (f["class"], f["carrier"], f["file"], f["location"]))
    B = R.get("behaviour")
    if B:
        _w("")
        _w("BEHAVIOUR BY GROUP (per-file runs)")
        for g, v in sorted(B["groups"].items()):
            _w("  %-10s files=%3d exit_ok=%3d crash=%d echo_files=%d badchars=%d bad_utf8=%d json_fields_bad=%d json_missing=%d"
               " max_secs=%.2f total_secs=%.1f max_peak_mb=%.0f" % (
                   g, v["files"], v["exit_ok"], v["crash"], v["echo"], v["badchars"], v["bad_utf8"], v["json_fields_bad"],
                   v["json_missing"], v["max_secs"], v["total_secs"], v["max_mb"]))
        hard = [r for r in B["exit_bad"] if not r.get("informational")]
        _w("EXIT CODE MISMATCHES: %d hard, %d informational (boundary / known_miss tier)" % (
            len(hard), len(B["exit_bad"]) - len(hard)))
        for r in B["exit_bad"]:
            _w("  EXIT %-10s %s %s exit=%s expected=%s" % (r["group"], "(info)" if r.get("informational") else "(HARD)",
                                                         r["file"], r["exit"], r["expected"]))
        _w("CRASHES/TIMEOUTS: %d" % len(B["crash"]))
        for r in B["crash"]:
            _w("  CRASH %s exit=%s timeout=%s" % (r["file"], r["exit"], r["timeout"]))
        _w("ECHO (planted value, canary or injection phrase in stdout/stderr/json): %d files" % len(B["echo"]))
        for r in B["echo"]:
            _w("  ECHO %s kinds=%s where=%s" % (r["file"], r["kinds"], r["where"]))
        _w("HOSTILE + HEAVY, one line per file")
        for r in B["hostile_heavy"]:
            flags = []
            if r["exit"] not in r["expected"]:
                flags.append("EXIT!")
            if r["crash"]:
                flags.append("CRASH")
            if r["echo"]:
                flags.append("ECHO")
            if r["badchars"]:
                flags.append("CTRL")
            if r["bad_utf8"]:
                flags.append("UTF8")
            _w("  %-70s exit=%s exp=%-6s %7.2fs %7sMB %s errors=%s" % (
                r["file"][:70], r["exit"], r["expected"], r["secs"], r["peak_mb"], " ".join(flags) or "ok", ",".join(r["errors"])))
    if R.get("dirs"):
        _w("")
        _w("DIRECTORY TESTS")
        for d in R["dirs"]:
            _w("  %-28s %-4s exit=%s expect=%s %7.2fs peak=%sMB files_w_findings=%s %s" % (
                d["id"], "PASS" if d["pass"] else ("INFO" if d.get("informational") else "FAIL"), d["exit"], d["expect"], d["secs"], d["peak_mb"],
                d["files_with_findings"], "; ".join(d["problems"])))
        for s in R.get("sweep_consistency", []):
            _w("  consistency %-18s sweep records=%d per-file records=%d differences=%d" % (
                s["sweep"], s["records_sweep"], s["records_per_file"], s["differences"]))
    if R.get("cli"):
        _w("")
        _w("CLI TESTS")
        for c in R["cli"]:
            _w("  #%02d %-4s exit=%s expect=%s %6.2fs args=%s env=%s %s" % (
                c["n"], "PASS" if c["pass"] else "FAIL", c["exit"], c["expect"], c["secs"], " ".join(c["args"])[:90],
                c["env"], "; ".join(c["problems"])))


# --------------------------------------------------------------------------------------------
# harness self-test: four deliberately bad scanners must be caught
# --------------------------------------------------------------------------------------------
_MOCK_COMMON = r'''
import sys, json, re, time
args = sys.argv[1:]
paths = [x for x in args if not x.startswith("--")]
jpath = args[args.index("--json") + 1] if "--json" in args else None
'''
_MOCKS = {
    # reads nothing, says nothing is wrong, exit 0 for every file
    "silent": _MOCK_COMMON + r'''
if jpath:
    json.dump({"findings": [], "errors": []}, open(jpath, "w"))
print("nothing found")
sys.exit(0)
''',
    # prints the secret it found (and the injection text it saw) - the one thing a scanner must never do
    "leaky": _MOCK_COMMON + r'''
raw = open(paths[0], "rb").read()
pre = "s" + "k-"
m = re.search(pre.encode() + rb"[A-Za-z0-9_-]{20,}", raw)
out = []
if m:
    out.append("FOUND " + m.group(0).decode())
i = raw.find(b"IGNORE ALL PREVIOUS")
if i >= 0:
    out.append(raw[i:i + 70].decode("latin-1"))
print(chr(10).join(out))
if jpath:
    json.dump({"findings": [], "errors": []}, open(jpath, "w"))
sys.exit(1 if out else 0)
''',
    # dies with a traceback
    "crashy": _MOCK_COMMON + r'''
raise ValueError("mock crash")
''',
    # never returns
    "hang": _MOCK_COMMON + r'''
time.sleep(600)
''',
}


def selftest(a):
    root = os.path.abspath(a.corpus)
    tmp = tempfile.mkdtemp(prefix="ssr_selftest_")
    only = ",".join(["pos/K1_openai_legacy_api_tEXt.png", "hostile/hostile_inject_tEXt_comment.png",
                     "clean/clean_no_metadata.png"])
    fails = 0
    for name, src in _MOCKS.items():
        sp = os.path.join(tmp, "mock_%s.py" % name)
        open(sp, "w", encoding="utf-8").write(src)
        out = os.path.join(tmp, "out_" + name)
        cmd = [sys.executable, os.path.abspath(__file__), "--corpus", root, "--scanner", sp, "--only", only,
               "--phases", "file", "--out", out, "--label", name, "--quiet", "--timeout", "4", "--mem-gib", "1"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        rp = os.path.join(out, "results_%s.json" % name)
        R = json.load(open(rp, encoding="utf-8"))
        B = R["behaviour"]
        hard = [r for r in B["exit_bad"] if not r.get("informational")]
        misses = len(R["strict"]["misses"])
        want = {"silent": ("misses and wrong exit codes", misses > 0 and len(hard) > 0 and not B["echo"]),
                "leaky": ("echo of a secret / injection text", len(B["echo"]) >= 1),
                "crashy": ("crash", len(B["crash"]) >= 3),
                "hang": ("timeout", len(B["crash"]) >= 3)}[name]
        ok = want[1]
        fails += 0 if ok else 1
        _w("  selftest %-7s expect harness to flag %-34s -> %s  (misses=%d hard_exit_bad=%d echo=%d crash=%d)" % (
            name, want[0], "PASS" if ok else "FAIL", misses, len(hard), len(B["echo"]), len(B["crash"])))
    _w("SELFTEST " + ("OK" if not fails else "FAILED (%d)" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
