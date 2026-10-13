#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval/h2h.py - head-to-head of leak-finding approaches on the SYNTHETIC Share-Safe Renders corpus.

    A    scan.py (the prototype)                         python scan.py FILE --json OUT
    B1   trufflehog filesystem on the file as it is      (trufflehog skips PNG / JPEG / MP4 by sniffed type: see report)
    B1w  trufflehog on a copy with a 5-byte text prefix  (workaround that defeats that skip; not a supported mode)
    B2p  exiftool dump (no -b)  -> trufflehog on the dump text
    B2b  exiftool dump (-b)     -> trufflehog on the dump text   (-b prints raw values only: no tag names)
    B2u  B2p + B2b together (union of findings and of visibility)
    Bx   B1w + B2u together, visibility also counting the raw file bytes (the strongest baseline built from the two tools)

    python h2h.py --corpus CORPUS_DIR --workdir WORKDIR --exiftool EXE --trufflehog EXE
                  [--scanner PATH/scan.py] [--phases run,score] [--only PREFIX,PREFIX] [--mem-gib 4]
                  [--timeout 120] [--dirmode] [--reuse]

Phases
    run    execute every tool on every registered file of the corpus (sequentially, so wall times are comparable) and
           cache per-file facts in WORKDIR/facts.json.  Raw tool output is never stored: only counts, exit codes,
           timings, detector names and SHA-256 prefixes of the planted values a finding covers.  Run it as a normal
           foreground process or a proper background task (a shell-detached child is killed with its shell).
    score  read facts.json + answer_key.json and print the plain-text tables (and write WORKDIR/h2h_results.json).

Safety
    * trufflehog is always run with --no-verification --no-update --json --results=verified,unverified,unknown and with
      HTTP(S)_PROXY / ALL_PROXY pointed at a dead local port, so an accidental connection fails.
    * every child runs inside a Windows job object (default 4 GiB memory cap, kill-tree on timeout) with its cwd set to
      WORKDIR; nothing is run from inside the corpus.
    * the printed tables contain no planted value: classes, counts, file names, vendor names and hashes only.

What is and is not scored for B1 / B1w / B2* / Bx (trufflehog classifies vendor secrets only, exiftool classifies nothing):
    span     = trufflehog reported a finding whose Raw / RawV2 / secret-part text covers the planted value (substring either
               way, >= 16 chars for the reverse direction, URL path segments accepted).  Meaningful for K1 and K3 only; for
               every other class it is incidental.  Entries are tied to values by the answer key's value_sha256_prefix;
               P1 / P2 / P3 entries without a hash use the planted user names / e-mails / hosts found in that file.
    family   = the file has any trufflehog finding from a K1 / K3 detector family (class-present-in-file).
    visible  = the planted value is present in clear in the exiftool dump (literal, or JSON-escaped up to 3 levels).
    rawvis   = the planted value is present in clear in the raw bytes of the file (what a text scanner sees).
    G1 / M1 have no stored value: G1 is visible when the dump shows GPS latitude and longitude (DMS or decimal) and as a
    value when the decimal matches a planted coordinate; M1 is visible when its inner secret, or else a ComfyUI workflow
    marker, is visible in the dump.  None of B can attribute a node id or a bypass flag, so only class-present-in-file
    is scored for them.  "False clean" = a file with >= 1 required leak for which the approach printed no finding.
Python 3.9+, standard library only.  Reuses eval/score.py for the job object, the output-hygiene check and the strict /
lenient planted-entry matcher (so the A columns equal score.py's own numbers).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score as S                      # noqa: E402  (eval/score.py: _Job, Hygiene, match_file, carrier_norm)

# the scanner under test is the one in the package: <repo>/packages/share-safe-renders/scripts/scan.py
DEFAULT_SCANNER = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "packages",
                               "share-safe-renders", "scripts", "scan.py")
CLASSES = ["K1", "K2", "K3", "P1", "P2", "P3", "G1", "H1", "H2", "H3", "M1"]
APPROACHES = ["A", "B1", "B1w", "B2p", "B2b", "B2u", "Bx"]   # B2u = B2p + B2b; Bx = B1w + B2u (every baseline tool at once)
TF_FLAGS = ["--no-verification", "--no-update", "--json", "--results=verified,unverified,unknown"]
ET_OPTS = ["-a", "-u", "-G1", "-s", "-ee3", "-api", "LargeFileSupport=1"]
TEXT_PREFIX = b"text\n"                 # makes MIME sniffing say text/plain instead of image/png | video/mp4
BIG_DUMP = 96 << 20                     # dumps above this are searched head + tail only
HEADTAIL = 48 << 20
DEAD_PROXY = "http://127.0.0.1:9"
WORKDIR = None                          # set in main(): children run with this cwd (never inside the corpus)

# trufflehog detector-name -> class family (checked against the names actually seen; see 'detector_names' in results)
K1_FAMILY = ("openai", "anthropic", "github", "aws", "gcp", "google", "slack", "stripe", "huggingface", "claude")
K3_FAMILY = ("discord", "slackwebhook", "webhook")


# --------------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------------
def lp(path):
    """Extended-length path on Windows so odd names and long paths open."""
    p = os.path.abspath(path)
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        return "\\\\?\\" + p
    return p


def sha8(s):
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:8]


def esc_variants(v):
    """The value as it would be spelled inside 0..3 levels of JSON string encoding (ascii and unicode forms)."""
    outs, cur = [v], [v]
    for _ in range(3):
        nxt = []
        for x in cur:
            for ea in (True, False):
                y = json.dumps(x, ensure_ascii=ea)[1:-1]
                if y not in outs:
                    outs.append(y)
                    nxt.append(y)
        cur = nxt or cur
        if not nxt:
            break
    return outs


class Needles:
    def __init__(self, never):
        self.vals = {}                  # sha8 -> value
        for k in ("secrets", "pii"):
            for v in never.get(k, []):
                if isinstance(v, str) and len(v) >= 5:
                    self.vals[sha8(v)] = v
        self.variants = {h: [x.encode("utf-8", "surrogatepass") for x in esc_variants(v)] for h, v in self.vals.items()}
        self.tokens = {}                # sha8 -> substrings that identify the value inside a trufflehog Raw
        for h, v in self.vals.items():
            toks = [v]
            if "/" in v:
                toks += [t for t in v.replace("?", "/").split("/") if len(t) >= 20]
            self.tokens[h] = toks
        self.kind = {}
        for h, v in self.vals.items():
            if "@" in v:
                k = "email"
            elif re.fullmatch(r"\d{1,3}\.\d{3}", v):
                k = "gps"
            elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v) or re.search(r"\.(local|lan|internal)$", v):
                k = "lan"
            elif re.fullmatch(r"fx[a-z0-9_.]*", v):
                k = "user"
            else:
                k = "secret"
            self.kind[h] = k

    def find_in(self, data):
        """data: bytes.  -> {sha8: 'lit'|'esc'}"""
        out = {}
        for h, vs in self.variants.items():
            for i, b in enumerate(vs):
                if b in data:
                    out[h] = "lit" if i == 0 else "esc"
                    break
        return out


def read_headtail(path, limit=BIG_DUMP, part=HEADTAIL):
    size = os.path.getsize(lp(path))
    with open(lp(path), "rb") as fh:
        if size <= limit:
            return fh.read(), size, False
        head = fh.read(part)
        fh.seek(size - part)
        tail = fh.read(part)
    return head + b"\n" + tail, size, True


def png_inflated(data, cap=8 << 20):
    """Independent mini decoder: inflate zTXt / compressed iTXt payloads (used only to learn what a file plants)."""
    out = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return b""
    i, n, seen = 8, len(data), 0
    while i + 8 <= n and seen < 4000:
        seen += 1
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln] if ln <= n else data[i + 8:]
        payload = None
        if typ == b"zTXt":
            p = body.split(b"\0", 1)
            if len(p) == 2 and len(p[1]) > 1:
                payload = p[1][1:]
        elif typ == b"iTXt":
            p = body.split(b"\0", 1)
            if len(p) == 2 and len(p[1]) > 2 and p[1][0] == 1:
                rest = p[1][2:].split(b"\0", 2)
                if len(rest) == 3:
                    payload = rest[2]
        if payload:
            try:
                d = zlib.decompressobj()
                out.append(d.decompress(payload, cap))
            except Exception:
                pass
        if ln > n:
            break
        i += 12 + ln
    return b"\n".join(out)


GPS_RE = re.compile(r"GPS(Latitude|Longitude)\s*:\s*(\d+) deg (\d+)' ([\d.]+)\"")
GPS_DEC = re.compile(r"GPS(Latitude|Longitude)\s*:\s*(-?\d+\.\d+)\s*$", re.M)


def gps_from_dump(text):
    lat, lon = set(), set()
    for m in GPS_RE.finditer(text):
        x = int(m.group(2)) + int(m.group(3)) / 60.0 + float(m.group(4)) / 3600.0
        (lat if m.group(1) == "Latitude" else lon).add(round(abs(x), 6))
    for m in GPS_DEC.finditer(text):
        (lat if m.group(1) == "Latitude" else lon).add(round(abs(float(m.group(2))), 6))
    return sorted(lat), sorted(lon)


MARKERS = (b'"class_type"', b"widgets_values", b'\\"class_type\\"')


# --------------------------------------------------------------------------------------------
# process runner (job object: memory cap, peak memory, kill-tree on timeout)
# --------------------------------------------------------------------------------------------
def run(cmd, timeout, mem_gib, env=None, stdout_path=None, cwd=None):
    job = S._Job(int(mem_gib * 1024 ** 3) if mem_gib else 0)
    t0 = time.perf_counter()
    fh = open(stdout_path, "wb") if stdout_path else None
    timed_out = False
    try:
        p = subprocess.Popen(cmd, stdout=fh if fh else subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=env, cwd=cwd or WORKDIR)
    except Exception as exc:
        if fh:
            fh.close()
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
            out, err = p.communicate(timeout=30)
        except Exception:
            out, err = b"", b""
    secs = time.perf_counter() - t0
    peak = job.peak_mb()
    job.close()
    if fh:
        fh.close()
    return {"exit": p.returncode, "out": out or b"", "err": err or b"", "secs": round(secs, 3), "peak_mb": peak,
            "timeout": timed_out}


def tool_env():
    env = dict(os.environ)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[k] = DEAD_PROXY
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    return env


# --------------------------------------------------------------------------------------------
# trufflehog result parsing
# --------------------------------------------------------------------------------------------
def parse_tf(out_bytes, err_bytes, needles):
    findings, bad_lines = [], 0
    for line in out_bytes.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            bad_lines += 1
            continue
        if not isinstance(d, dict) or "DetectorName" not in d:
            continue
        texts = [str(d.get("Raw") or ""), str(d.get("RawV2") or "")]
        sp = d.get("SecretParts")
        if isinstance(sp, dict):
            texts += [str(x) for x in sp.values()]
        texts = [t for t in texts if t]
        matched = []
        for h, toks in needles.tokens.items():
            hit = False
            for t in texts:
                for tok in toks:
                    if tok in t:
                        hit = True
                        break
                    if len(t) >= 16 and t in tok:
                        hit = True
                        break
                if hit:
                    break
            if hit:
                matched.append(h)
        findings.append({"det": d.get("DetectorName"), "verified": bool(d.get("Verified")), "matched": sorted(matched),
                         "rawlen": max([len(t) for t in texts] or [0])})
    chunks = byt = None
    nerr = 0
    for line in err_bytes.decode("utf-8", "replace").splitlines():
        if '"finished scanning"' in line:
            try:
                d = json.loads(line)
                chunks, byt = d.get("chunks"), d.get("bytes")
            except Exception:
                pass
        if '"level":"error"' in line:
            nerr += 1
    return findings, {"chunks": chunks, "bytes": byt, "log_errors": nerr, "bad_json_lines": bad_lines}


def tf_run(tf_exe, path, timeout, mem_gib, needles, hyg, env):
    r = run([tf_exe, "filesystem", path] + TF_FLAGS, timeout, mem_gib, env=env)
    findings, meta = parse_tf(r["out"], r["err"], needles)
    echo = collections.Counter()
    for b in (r["out"], r["err"]):
        echo.update(hyg.check_text(b.decode("utf-8", "replace")))
    crash = bool(r["timeout"] or r["exit"] not in (0,) or b"panic:" in r["err"] or b"fatal error" in r["err"])
    return {"exit": r["exit"], "secs": r["secs"], "peak_mb": r["peak_mb"], "timeout": r["timeout"], "crash": crash,
            "chunks": meta["chunks"], "bytes": meta["bytes"], "log_errors": meta["log_errors"],
            "stdout_bytes": len(r["out"]), "findings": findings, "echo": dict(echo)}


# --------------------------------------------------------------------------------------------
# run phase
# --------------------------------------------------------------------------------------------
def run_phase(a, key, never):
    root = os.path.abspath(a.corpus)
    work = os.path.abspath(a.workdir)
    os.makedirs(work, exist_ok=True)
    for sub in ("A", "dumps_p", "dumps_b", "w", "asc"):
        os.makedirs(os.path.join(work, sub), exist_ok=True)
    needles = Needles(never)
    hyg = S.Hygiene(never, key["files"])
    env = tool_env()
    facts_path = os.path.join(work, "facts.json")
    facts = json.load(open(facts_path, encoding="utf-8")) if (a.reuse and os.path.exists(facts_path)) else {}
    files = sorted(key["files"])
    if a.only:
        pre = [x.strip() for x in a.only.split(",") if x.strip()]
        files = [f for f in files if any(f.startswith(p) for p in pre)]
    scanner = os.path.abspath(a.scanner)

    def log(*x):
        print(*x, flush=True)

    t_all = time.perf_counter()
    for n, rel in enumerate(files):
        if rel in facts and a.reuse:
            continue
        ent = key["files"][rel]
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(lp(path)):
            facts[rel] = {"missing": True}
            continue
        heavy = rel.startswith("heavy/")
        tmo = a.timeout * (5 if heavy else 1)
        f = {"group": ent["group"], "size": os.path.getsize(lp(path))}
        data = open(lp(path), "rb").read()
        f["rawvis"] = needles.find_in(data)
        blob = data + b"\n" + png_inflated(data) if not heavy else data
        f["planted_in_file"] = sorted(needles.find_in(blob)) if not heavy else []

        # ---- A: scan.py -------------------------------------------------------------------
        jpath = os.path.join(work, "A", "f%04d.json" % n)
        if os.path.exists(jpath):
            os.remove(jpath)
        r = run([sys.executable, scanner, path, "--json", jpath], tmo, a.mem_gib, env=dict(os.environ))
        jb = open(jpath, "rb").read() if os.path.exists(jpath) else None
        jobj = S.load_json_bytes(jb) if jb else None
        fl = []
        if isinstance(jobj, dict):
            for x in jobj.get("findings", []) or []:
                if isinstance(x, dict):
                    fl.append({k: x.get(k) for k in ("class", "carrier", "location", "node_id", "bypassed", "length",
                                                    "sha256_prefix", "severity", "companion_of", "detail")})
        errs = sorted(set(x.get("code", "?") for x in ((jobj or {}).get("errors") or []) if isinstance(x, dict)))
        hy = hyg.check_run(r, jb)
        f["A"] = {"exit": r["exit"], "secs": r["secs"], "peak_mb": r["peak_mb"], "timeout": r["timeout"],
                  "crash": bool(r["timeout"] or r["exit"] not in (0, 1, 2, 3) or b"Traceback" in r["err"] + r["out"]),
                  "findings": fl, "errors": errs, "echo": dict(hy["echo"]), "badchars": hy["badchars"],
                  "json_valid": hy["json_valid"]}

        # ---- B1: trufflehog on the file as it is --------------------------------------------
        f["B1"] = tf_run(a.trufflehog, path, tmo, a.mem_gib, needles, hyg, env)

        # ---- B1w: trufflehog on a copy with a text prefix ---------------------------------
        wpath = os.path.join(work, "w", "%04d.dat" % n)
        with open(wpath, "wb") as fh:
            fh.write(TEXT_PREFIX + data)
        f["B1w"] = tf_run(a.trufflehog, wpath, tmo, a.mem_gib, needles, hyg, env)
        os.remove(wpath)

        # ---- B2: exiftool dump -> trufflehog on the dump -----------------------------------
        src = path
        fallback = False
        for tag, extra, dsub in (("B2p", [], "dumps_p"), ("B2b", ["-b"], "dumps_b")):
            dpath = os.path.join(work, dsub, "%04d.txt" % n)
            r = run([a.exiftool] + ET_OPTS + extra + [src], tmo, a.mem_gib, env=dict(os.environ), stdout_path=dpath)
            if (r["exit"] not in (0,) and os.path.getsize(dpath) == 0 and b"No matching files" in r["err"]
                    and not fallback):
                # exiftool.exe cannot open a name with an astral-plane character: retry through an ASCII-named copy
                ext = os.path.splitext(path)[1]
                asc = os.path.join(work, "asc", "%04d%s" % (n, ext))
                shutil.copyfile(lp(path), lp(asc))
                src, fallback = asc, True
                r = run([a.exiftool] + ET_OPTS + extra + [src], tmo, a.mem_gib, env=dict(os.environ), stdout_path=dpath)
            dsize = os.path.getsize(dpath)
            dd, _, partial = read_headtail(dpath)
            vis = needles.find_in(dd)
            text = dd[:4 << 20].decode("utf-8", "replace")
            lat, lon = gps_from_dump(text)
            echo = collections.Counter(hyg.check_text(dd.decode("utf-8", "replace")))
            et = {"exit": r["exit"], "secs": r["secs"], "peak_mb": r["peak_mb"], "timeout": r["timeout"],
                  "oom": b"Out of memory" in r["err"], "dump_bytes": dsize, "partial_search": partial,
                  "fallback_ascii_copy": fallback, "stderr_lines": len(r["err"].splitlines()),
                  "echo": dict(echo), "vis": vis, "gps_lat": lat, "gps_lon": lon,
                  "marker": any(m in dd for m in MARKERS),
                  "stderr_echo": dict(hyg.check_text(r["err"].decode("utf-8", "replace")))}
            tf = tf_run(a.trufflehog, dpath, tmo * (2 if heavy else 1), a.mem_gib, needles, hyg, env)
            f[tag] = {"et": et, "tf": tf, "secs": round(et["secs"] + tf["secs"], 3)}
            if dsize > (64 << 20):
                os.remove(dpath)
        facts[rel] = f
        if n % 10 == 0:
            log("[run] %3d/%d %s  A=%.1fs B1=%.1fs B1w=%.1fs B2p=%.1fs B2b=%.1fs" % (
                n + 1, len(files), rel[:50], f["A"]["secs"], f["B1"]["secs"], f["B1w"]["secs"], f["B2p"]["secs"],
                f["B2b"]["secs"]))
            json.dump(facts, open(facts_path, "w", encoding="utf-8"))
    facts["_meta"] = {"corpus": root, "wall_total_s": round(time.perf_counter() - t_all, 1),
                      "tools": {"exiftool": os.path.basename(os.path.dirname(a.exiftool)), "trufflehog": "see --version"},
                      "python": sys.version.split()[0]}

    if a.dirmode:
        facts["_dirmode"] = dirmode(a, key, root, work, needles, hyg, env)
    json.dump(facts, open(facts_path, "w", encoding="utf-8"))
    log("[run] done in %.0fs; facts -> %s" % (time.perf_counter() - t_all, facts_path))
    return facts


def dirmode(a, key, root, work, needles, hyg, env):
    """One invocation per approach over a mirror of every registered file except heavy/ (no links, no 2000 tiny files)."""
    mir, mirw = os.path.join(work, "mirror"), os.path.join(work, "mirror_w")
    for d in (mir, mirw):
        if os.path.isdir(lp(d)):
            shutil.rmtree(lp(d))
    n = 0
    for rel in key["files"]:
        if rel.startswith("heavy/"):
            continue
        src = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(lp(src)):
            continue
        for base, pre in ((mir, b""), (mirw, TEXT_PREFIX)):
            dst = os.path.join(base, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(lp(dst)), exist_ok=True)
            if pre:
                with open(lp(src), "rb") as fi, open(lp(dst) + ".dat", "wb") as fo:
                    fo.write(pre)
                    shutil.copyfileobj(fi, fo)
            else:
                shutil.copyfile(lp(src), lp(dst))
        n += 1
    res = {"files": n}
    r = run([sys.executable, os.path.abspath(a.scanner), mir, "--json", os.path.join(work, "dir_A.json")], 1500, a.mem_gib,
            env=dict(os.environ))
    res["A"] = {"exit": r["exit"], "secs": r["secs"], "peak_mb": r["peak_mb"], "timeout": r["timeout"]}
    for tag, d in (("B1", mir), ("B1w", mirw)):
        r = run([a.trufflehog, "filesystem", d] + TF_FLAGS, 1500, a.mem_gib, env=env)
        fnd, meta = parse_tf(r["out"], r["err"], needles)
        res[tag] = {"exit": r["exit"], "secs": r["secs"], "peak_mb": r["peak_mb"], "timeout": r["timeout"],
                    "chunks": meta["chunks"], "bytes": meta["bytes"], "findings": len(fnd)}
    for tag, extra in (("B2p", []), ("B2b", ["-b"])):
        dpath = os.path.join(work, "dir_%s.txt" % tag)
        r = run([a.exiftool] + ET_OPTS + extra + ["-r", mir], 1500, a.mem_gib, env=dict(os.environ), stdout_path=dpath)
        r2 = run([a.trufflehog, "filesystem", dpath] + TF_FLAGS, 1500, a.mem_gib, env=env)
        fnd, meta = parse_tf(r2["out"], r2["err"], needles)
        res[tag] = {"exiftool_exit": r["exit"], "exiftool_secs": r["secs"], "tf_secs": r2["secs"],
                    "secs": round(r["secs"] + r2["secs"], 3), "dump_bytes": os.path.getsize(dpath),
                    "chunks": meta["chunks"], "findings": len(fnd), "timeout": r["timeout"] or r2["timeout"]}
        os.remove(dpath)
    for d in (mir, mirw):
        shutil.rmtree(lp(d), ignore_errors=True)
    return res


# --------------------------------------------------------------------------------------------
# score phase
# --------------------------------------------------------------------------------------------
def merge_b2(f):
    """B2u: both exiftool dumps (names+values, and -b raw values) scanned by trufflehog; findings and visibility are the union."""
    p, b = f["B2p"], f["B2b"]
    echo_et = collections.Counter(p["et"]["echo"])
    echo_et.update(b["et"]["echo"])
    echo_tf = collections.Counter(p["tf"]["echo"])
    echo_tf.update(b["tf"]["echo"])
    vis = dict(p["et"]["vis"])
    vis.update(b["et"]["vis"])

    def mx(*x):
        return max([y or 0 for y in x])

    et = {"exit": mx(p["et"]["exit"], b["et"]["exit"]), "secs": round(p["et"]["secs"] + b["et"]["secs"], 3),
          "peak_mb": mx(p["et"]["peak_mb"], b["et"]["peak_mb"]), "timeout": p["et"]["timeout"] or b["et"]["timeout"],
          "oom": p["et"]["oom"] or b["et"]["oom"], "dump_bytes": p["et"]["dump_bytes"] + b["et"]["dump_bytes"],
          "partial_search": p["et"]["partial_search"] or b["et"]["partial_search"],
          "fallback_ascii_copy": p["et"]["fallback_ascii_copy"] or b["et"]["fallback_ascii_copy"],
          "echo": dict(echo_et), "vis": vis, "gps_lat": sorted(set(p["et"]["gps_lat"]) | set(b["et"]["gps_lat"])),
          "gps_lon": sorted(set(p["et"]["gps_lon"]) | set(b["et"]["gps_lon"])), "marker": p["et"]["marker"] or b["et"]["marker"]}
    tf = {"exit": mx(p["tf"]["exit"], b["tf"]["exit"]), "secs": round(p["tf"]["secs"] + b["tf"]["secs"], 3),
          "peak_mb": mx(p["tf"]["peak_mb"], b["tf"]["peak_mb"]), "timeout": p["tf"]["timeout"] or b["tf"]["timeout"],
          "crash": p["tf"]["crash"] or b["tf"]["crash"], "chunks": (p["tf"]["chunks"] or 0) + (b["tf"]["chunks"] or 0),
          "findings": p["tf"]["findings"] + b["tf"]["findings"], "echo": dict(echo_tf)}
    return {"et": et, "tf": tf, "secs": round(p["secs"] + b["secs"], 3)}


def merge_bx(f):
    """Bx: the strongest baseline, i.e. trufflehog on the prefixed raw copy AND trufflehog on both exiftool dumps."""
    u, w = f["B2u"], f["B1w"]
    vis = dict(u["et"]["vis"])
    for h, v in f["rawvis"].items():
        vis.setdefault(h, v)
    et = dict(u["et"])
    et["vis"] = vis
    echo = collections.Counter(u["tf"]["echo"])
    echo.update(w["echo"])
    tf = {"exit": max(u["tf"]["exit"] or 0, w["exit"] or 0), "secs": round(u["tf"]["secs"] + w["secs"], 3),
          "peak_mb": max(u["tf"]["peak_mb"] or 0, w["peak_mb"] or 0), "timeout": u["tf"]["timeout"] or w["timeout"],
          "crash": u["tf"]["crash"] or w["crash"], "chunks": (u["tf"]["chunks"] or 0) + (w["chunks"] or 0),
          "findings": u["tf"]["findings"] + w["findings"], "echo": dict(echo)}
    return {"et": et, "tf": tf, "secs": round(u["secs"] + w["secs"], 3)}


def vendor_of(v):
    """Vendor label of a K1 / K3 value from its public prefix or host only (no secret part is ever returned)."""
    if "://" in v:
        if "hooks.slack" in v:
            return "slack-webhook"
        if "discord" in v:
            return "discord-webhook"
        return None
    for pre, name in (("sk-ant-", "anthropic"), ("sk-proj-", "openai-project"), ("sk-svcacct-", "openai-service"),
                      ("sk_live_", "stripe-live"), ("rk_live_", "stripe-restricted"), ("sk-", "openai-legacy"),
                      ("github_pat_", "github-fine-grained"), ("ghp_", "github-classic"), ("gho_", "github-oauth"),
                      ("ghu_", "github-user"), ("ghs_", "github-server"), ("ghr_", "github-refresh"),
                      ("AKIA", "aws-access-key-id"), ("ASIA", "aws-access-key-id"), ("AIza", "google-api-key"),
                      ("xox" + "b-", "slack-bot"), ("xox" + "p-", "slack-user"), ("xapp-", "slack-app"), ("xox", "slack-other"),
                      ("hf_", "huggingface"), ("api_org_", "huggingface")):
        if v.startswith(pre):
            return name
    return None


def family_of(det):
    d = (det or "").lower()
    if "webhook" in d and ("discord" in d or "slack" in d):
        return "K3"
    if d.startswith("discord") and "bot" not in d:
        return "K3"
    if any(d.startswith(x) for x in K1_FAMILY):
        return "K1"
    return None


def entry_values(rel, e, needles, planted):
    """sha8 set the entry's planted value(s) stands for, or None when it cannot be tied to a stored value."""
    h = e.get("value_sha256_prefix")
    if h and h in needles.vals:
        return {h}
    cls = e.get("underlying_class") or e["class"]
    shape = {"P1": "user", "P2": "email", "P3": "lan"}.get(cls)
    if shape:
        s = {x for x in planted if needles.kind.get(x) == shape}
        return s or None
    return None


def pct(a, b):
    return "%d/%d" % (a, b)


def score_phase(a, key, never):
    work = os.path.abspath(a.workdir)
    facts = json.load(open(os.path.join(work, "facts.json"), encoding="utf-8"))
    needles = Needles(never)
    meta = facts.pop("_meta", {})
    dirm = facts.pop("_dirmode", None)
    for f0 in facts.values():
        if not f0.get("missing"):
            f0["B2u"] = merge_b2(f0)
            f0["Bx"] = merge_bx(f0)
    files = {k: v for k, v in key["files"].items() if k in facts and not facts[k].get("missing")}
    R = {"meta": meta, "files_scored": len(files)}

    # ------------------------------------------------------------------ entries
    # per entry: A strict / A lenient, and for B approaches span / family / visible / rawvis
    per_class = {c: collections.Counter() for c in CLASSES}
    per_carrier = collections.defaultdict(collections.Counter)
    per_tier = collections.defaultdict(collections.Counter)
    per_vendor = collections.defaultdict(collections.Counter)
    misses = {"A_strict": [], "A_lenient": []}
    fp = {"A": {"clean_files": 0, "findings": 0, "files": []}}
    for ap in APPROACHES[1:]:
        fp[ap] = {"clean_files": 0, "findings": 0, "files": [], "detectors": collections.Counter()}
    false_clean = {ap: [] for ap in APPROACHES}
    extra_unmatched = {ap: 0 for ap in APPROACHES[1:]}
    detectors_seen = collections.Counter()
    clean_n = boundary_n = 0
    boundary_flag = {ap: 0 for ap in APPROACHES}

    def tf_of(f, ap):
        return f[ap]["tf"] if ap in ("B2p", "B2b", "B2u", "Bx") else f[ap]

    for rel, ent in sorted(files.items()):
        f = facts[rel]
        exp = ent.get("expected", [])
        grp = ent["group"]
        fl = f["A"]["findings"]
        resS, _ = S.match_file(exp, fl, "strict")
        resL, _ = S.match_file(exp, fl, "lenient")
        planted = set(f.get("planted_in_file", []))
        tfs = {ap: tf_of(f, ap) for ap in APPROACHES[1:]}
        for ap, t in tfs.items():
            for x in t["findings"]:
                detectors_seen[x["det"]] += 1
        # ---- false positives / clean controls
        if grp == "clean":
            clean_n += 1
            nA = len([x for x in fl if not x.get("companion_of")])
            if nA:
                fp["A"]["clean_files"] += 1
                fp["A"]["findings"] += nA
                fp["A"]["files"].append(rel)
            for ap, t in tfs.items():
                if t["findings"]:
                    fp[ap]["clean_files"] += 1
                    fp[ap]["findings"] += len(t["findings"])
                    fp[ap]["files"].append(rel)
                    for x in t["findings"]:
                        fp[ap]["detectors"][x["det"]] += 1
        elif grp == "boundary":
            boundary_n += 1
            if [x for x in fl if not x.get("companion_of")]:
                boundary_flag["A"] += 1
            for ap, t in tfs.items():
                if t["findings"]:
                    boundary_flag[ap] += 1
        # ---- false-clean: required leaks present, approach reported nothing and exited 0
        req = [e for e in exp if not e.get("optional")]
        if req:
            if f["A"]["exit"] == 0 and not fl:
                false_clean["A"].append(rel)
            for ap, t in tfs.items():
                if not t["findings"] and t["exit"] == 0:
                    false_clean[ap].append(rel)
        # ---- entries
        found_vals = {ap: set(x for fnd in tfs[ap]["findings"] for x in fnd["matched"]) for ap in tfs}
        fam = {ap: {family_of(x["det"]) for x in tfs[ap]["findings"]} - {None} for ap in tfs}
        for i, e in enumerate(exp):
            if e.get("optional"):
                continue
            c = e["class"]
            tier = e.get("tier") or ent.get("tier", "core")
            keyc = c
            cc = per_class[c]
            cc["planted"] += 1
            car = per_carrier[e["carrier"]]
            car["planted"] += 1
            tt = per_tier[(c, "ext" if (ent.get("tier") == "extended" or tier == "extended") else "core")]
            tt["planted"] += 1
            for tag, resx in (("A_strict", resS), ("A_lenient", resL)):
                if resx[i]["matched"]:
                    cc[tag] += 1
                    car[tag] += 1
                    tt[tag] += 1
                else:
                    misses[tag].append((rel, c, e["carrier"], e.get("node_id")))
            vals = entry_values(rel, e, needles, planted)
            under = e.get("underlying_class") or c
            if vals:
                cc["has_value"] += 1
                car["has_value"] += 1
                cc["has_vis"] += 1
                car["has_vis"] += 1
                if under in ("K1", "K3"):
                    cc["kk_value"] += 1
                    car["kk_value"] += 1
                for ap in tfs:
                    if vals & found_vals[ap]:
                        cc["span_" + ap] += 1
                        car["span_" + ap] += 1
                        if under in ("K1", "K3"):
                            cc["kkspan_" + ap] += 1
                            car["kkspan_" + ap] += 1
                    if under in ("K1", "K3") and under in fam[ap]:
                        cc["fam_" + ap] += 1
                        car["fam_" + ap] += 1
                if all(v in f["rawvis"] for v in vals):
                    cc["rawvis"] += 1
                    car["rawvis"] += 1
                for ap in ("B2p", "B2b", "B2u", "Bx"):
                    if all(v in f[ap]["et"]["vis"] for v in vals):
                        cc["vis_" + ap] += 1
                        car["vis_" + ap] += 1
                if under in ("K1", "K3"):
                    vend = vendor_of(needles.vals[next(iter(vals))]) if len(vals) == 1 else None
                    if vend:
                        vd = per_vendor[vend]
                        vd["planted"] += 1
                        vd["A_strict"] += 1 if resS[i]["matched"] else 0
                        vd["A_lenient"] += 1 if resL[i]["matched"] else 0
                        vd["rawvis"] += 1 if all(v in f["rawvis"] for v in vals) else 0
                        for ap in tfs:
                            vd["span_" + ap] += 1 if (vals & found_vals[ap]) else 0
            elif c == "G1":
                cc["has_vis"] += 1
                car["has_vis"] += 1
                gp = [float(v) for h, v in needles.vals.items() if needles.kind[h] == "gps"]
                gps_hashes = {h for h in needles.vals if needles.kind[h] == "gps"}
                for ap in ("B2p", "B2b", "B2u", "Bx"):
                    et = f[ap]["et"]
                    dec_hit = bool(gps_hashes & set(et["vis"]))              # the -b dump prints plain decimals
                    tag_vis = dec_hit or bool(et["gps_lat"] and et["gps_lon"]
                                              and (max(et["gps_lat"]) > 0 or max(et["gps_lon"]) > 0))
                    val_vis = dec_hit or (tag_vis and any(abs(math.floor(x * 1000) / 1000.0 - p) < 0.0015
                                                          for x in et["gps_lat"] + et["gps_lon"] for p in gp))
                    if tag_vis:
                        cc["vis_" + ap] += 1
                        car["vis_" + ap] += 1
                    if val_vis:
                        cc["visval_" + ap] += 1
                        car["visval_" + ap] += 1
                cc["rawvis"] += 0
            elif c == "M1":
                cc["has_vis"] += 1
                car["has_vis"] += 1
                inner = [x for x in exp if x is not e and not x.get("optional") and x["class"] in ("K1", "K2", "K3", "P2")
                         and x.get("value_sha256_prefix") in needles.vals]
                for ap in ("B2p", "B2b", "B2u", "Bx"):
                    et = f[ap]["et"]
                    if inner:
                        ok = any(x["value_sha256_prefix"] in et["vis"] for x in inner)
                    else:
                        ok = et["marker"]
                    if ok:
                        cc["vis_" + ap] += 1
                        car["vis_" + ap] += 1
                # raw bytes: the text is in the file in clear for tags and for free/uuid payloads
                if inner:
                    if any(x["value_sha256_prefix"] in f["rawvis"] for x in inner):
                        cc["rawvis"] += 1
                        car["rawvis"] += 1
            else:
                cc["no_value"] += 1
        # unmatched trufflehog findings in positive-ish files
        if grp in ("positive", "hostile", "heavy"):
            allvals = set()
            for e in exp:
                v = entry_values(rel, e, needles, planted)
                if v:
                    allvals |= v
            for ap in tfs:
                for x in tfs[ap]["findings"]:
                    if not (set(x["matched"]) & allvals):
                        extra_unmatched[ap] += 1

    R["classes"] = {c: dict(v) for c, v in per_class.items()}
    R["carriers"] = {k: dict(v) for k, v in sorted(per_carrier.items())}
    R["tiers"] = {"%s/%s" % k: dict(v) for k, v in sorted(per_tier.items())}
    R["k1_by_vendor"] = {k: dict(v) for k, v in sorted(per_vendor.items())}
    R["misses"] = misses
    R["clean_files"] = clean_n
    R["boundary_files"] = boundary_n
    R["boundary_flagged"] = boundary_flag
    R["fp"] = {k: {"clean_files": v["clean_files"], "findings": v["findings"], "files": v["files"],
                   "detectors": dict(v.get("detectors", {}))} for k, v in fp.items()}
    R["false_clean"] = {k: v for k, v in false_clean.items()}
    R["extra_unmatched_findings"] = extra_unmatched
    R["detector_names"] = dict(detectors_seen)

    # ------------------------------------------------------------------ value-level visibility in the exiftool dump
    allv = collections.Counter()
    vis_any = {"B2p": set(), "B2b": set(), "B2u": set(), "Bx": set()}
    vis_own = {"B2p": set(), "B2b": set(), "B2u": set(), "Bx": set()}
    planted_any = set()
    for rel, f in facts.items():
        if f.get("missing"):
            continue
        for h in f.get("planted_in_file", []):
            planted_any.add(h)
        for ap in ("B2p", "B2b", "B2u", "Bx"):
            vis_any[ap] |= set(f[ap]["et"]["vis"])
    # a value planted in a heavy file is known through the answer key only
    for rel, ent in files.items():
        for e in ent.get("expected", []):
            h = e.get("value_sha256_prefix")
            if h and h in needles.vals:
                planted_any.add(h)
                for ap in ("B2p", "B2b", "B2u", "Bx"):
                    if h in facts[rel][ap]["et"]["vis"]:
                        vis_own[ap].add(h)
    for rel, f in facts.items():
        if f.get("missing"):
            continue
        for h in f.get("planted_in_file", []):
            for ap in ("B2p", "B2b", "B2u", "Bx"):
                if h in f[ap]["et"]["vis"]:
                    vis_own[ap].add(h)
    by_kind = collections.defaultdict(lambda: collections.Counter())
    for h in needles.vals:
        k = needles.kind[h]
        by_kind[k]["values"] += 1
        if h in planted_any:
            by_kind[k]["located_in_a_file"] += 1
        for ap in ("B2p", "B2b", "B2u", "Bx"):
            if h in vis_own[ap]:
                by_kind[k]["own_" + ap] += 1
            if h in vis_any[ap]:
                by_kind[k]["any_" + ap] += 1
    R["value_visibility"] = {"total_values": len(needles.vals), "by_kind": {k: dict(v) for k, v in by_kind.items()},
                             "own_file": {ap: len(vis_own[ap]) for ap in vis_own},
                             "any_dump": {ap: len(vis_any[ap]) for ap in vis_any},
                             "located": len(planted_any)}

    # ------------------------------------------------------------------ behaviour: timing, exits, echo
    beh = {}
    for ap in APPROACHES:
        tot = 0.0
        grp_t = collections.Counter()
        exits = collections.Counter()
        crashes, timeouts, echo_files, echo_kinds = [], [], 0, collections.Counter()
        skipped_chunks0 = 0
        peak = 0.0
        for rel, f in facts.items():
            if f.get("missing"):
                continue
            g = f["group"]
            if ap == "A":
                t = f["A"]
                secs, ex, tmo, crash, echo = t["secs"], t["exit"], t["timeout"], t["crash"], t["echo"]
                pk = t["peak_mb"] or 0
            elif ap in ("B1", "B1w"):
                t = f[ap]
                secs, ex, tmo, crash, echo = t["secs"], t["exit"], t["timeout"], t["crash"], t["echo"]
                pk = t["peak_mb"] or 0
                if t["chunks"] in (0, None):
                    skipped_chunks0 += 1
            else:
                t = f[ap]
                secs = t["secs"]
                ex = (t["et"]["exit"], t["tf"]["exit"])
                tmo = t["et"]["timeout"] or t["tf"]["timeout"]
                crash = t["et"]["oom"] or t["tf"]["crash"] or t["et"]["timeout"] or t["et"]["exit"] not in (0,)
                echo = collections.Counter(t["tf"]["echo"])
                echo.update(t["et"]["echo"])
                echo = dict(echo)
                pk = max(t["et"]["peak_mb"] or 0, t["tf"]["peak_mb"] or 0)
            tot += secs
            grp_t[g] += secs
            peak = max(peak, pk)
            exits[str(ex)] += 1
            if crash:
                crashes.append(rel)
            if tmo:
                timeouts.append(rel)
            if echo:
                echo_files += 1
                echo_kinds.update(echo.keys())
        beh[ap] = {"total_s": round(tot, 1), "by_group_s": {k: round(v, 1) for k, v in grp_t.items()},
                   "exit_counts": dict(exits), "crash_files": crashes, "timeouts": timeouts, "files_with_echo": echo_files,
                   "echo_kinds": dict(echo_kinds), "chunks0_files": skipped_chunks0, "peak_mb": peak}
    R["behaviour"] = beh
    # echo detail split: tool output only (trufflehog stdout/stderr, scan stdout/json) vs exiftool dump
    echo_tf = collections.Counter()
    echo_et = collections.Counter()
    for rel, f in facts.items():
        if f.get("missing"):
            continue
        for k, v in f["B2u"]["tf"]["echo"].items():
            echo_tf[k] += 1
        for k, v in f["B2u"]["et"]["echo"].items():
            echo_et[k] += 1
    R["echo_b2u_files_by_kind"] = {"trufflehog_output": dict(echo_tf), "exiftool_dump": dict(echo_et)}

    # hostile + heavy table
    hh = []
    for rel, ent in sorted(files.items()):
        if ent["group"] not in ("hostile", "heavy"):
            continue
        f = facts[rel]
        hh.append({"file": rel, "group": ent["group"], "expected_exit_in": ent["expected_exit_in"],
                   "A": [f["A"]["exit"], f["A"]["secs"], f["A"]["peak_mb"], f["A"]["crash"], sum(f["A"]["echo"].values()),
                         len(f["A"]["findings"])],
                   "B1": [f["B1"]["exit"], f["B1"]["secs"], f["B1"]["peak_mb"], f["B1"]["chunks"], sum(f["B1"]["echo"].values()),
                          len(f["B1"]["findings"])],
                   "B1w": [f["B1w"]["exit"], f["B1w"]["secs"], f["B1w"]["peak_mb"], f["B1w"]["chunks"],
                           sum(f["B1w"]["echo"].values()), len(f["B1w"]["findings"])],
                   "B2b": [f["B2b"]["et"]["exit"], f["B2b"]["et"]["secs"], f["B2b"]["et"]["peak_mb"],
                           f["B2b"]["et"]["oom"], f["B2b"]["et"]["dump_bytes"], f["B2b"]["tf"]["exit"], f["B2b"]["tf"]["secs"],
                           f["B2b"]["tf"]["timeout"], sum(f["B2b"]["et"]["echo"].values()),
                           sum(f["B2b"]["tf"]["echo"].values()), len(f["B2b"]["tf"]["findings"])],
                   "B2p": [f["B2p"]["et"]["exit"], f["B2p"]["et"]["secs"], f["B2p"]["et"]["peak_mb"],
                           f["B2p"]["et"]["oom"], f["B2p"]["et"]["dump_bytes"], f["B2p"]["tf"]["exit"], f["B2p"]["tf"]["secs"],
                           f["B2p"]["tf"]["timeout"], sum(f["B2p"]["et"]["echo"].values()),
                           sum(f["B2p"]["tf"]["echo"].values()), len(f["B2p"]["tf"]["findings"])]})
    R["hostile_heavy"] = hh
    # exit-code honesty: files whose right answer is 'could not scan' (exit 3 only) or that hold a required leak
    unscannable = [rel for rel, ent in files.items() if ent["expected_exit_in"] == [3]]
    R["unscannable_expected_exit3"] = {
        "files": unscannable,
        "A_exit": {r: facts[r]["A"]["exit"] for r in unscannable},
        "B1_exit": {r: facts[r]["B1"]["exit"] for r in unscannable},
        "B2u_exit": {r: [facts[r]["B2u"]["et"]["exit"], facts[r]["B2u"]["tf"]["exit"]] for r in unscannable}}
    if dirm:
        R["dirmode"] = dirm
    # exiftool facts
    et_stats = {}
    for ap in ("B2p", "B2b"):
        c = collections.Counter()
        for rel, f in facts.items():
            if f.get("missing"):
                continue
            et = f[ap]["et"]
            c["files"] += 1
            c["exit_nonzero"] += 1 if et["exit"] not in (0,) else 0
            c["oom"] += 1 if et["oom"] else 0
            c["fallback_ascii_copy"] += 1 if et["fallback_ascii_copy"] else 0
            c["partial_search"] += 1 if et["partial_search"] else 0
            c["dump_over_64MiB"] += 1 if et["dump_bytes"] > (64 << 20) else 0
        et_stats[ap] = dict(c)
    R["exiftool_stats"] = et_stats
    out = os.path.join(work, "h2h_results.json")
    json.dump(R, open(out, "w", encoding="utf-8"), indent=1, default=str)
    print_tables(R)
    print("\nresults json: %s" % out)
    return R


def print_tables(R):
    C = R["classes"]
    B = ("B1", "B1w", "B2p", "B2b", "B2u", "Bx")

    def g(c, k):
        return C.get(c, {}).get(k, 0)

    print("=" * 110)
    print("files scored: %d   clean controls: %d   boundary files: %d" % (R["files_scored"], R["clean_files"], R["boundary_files"]))
    print("approaches: A = scan.py | B1 = trufflehog on the file | B1w = trufflehog on a text-prefixed copy |")
    print("            B2p = exiftool dump -> trufflehog | B2b = exiftool -b dump -> trufflehog | B2u = B2p + B2b |")
    print("            Bx = B1w + B2u (every baseline tool at once; visibility also counts the raw file bytes)")

    print("\nTABLE 1 - required planted entries FOUND (per class, all folders). A = class/carrier/node/bypass match;")
    print("          B columns = trufflehog flagged that exact planted value ('-' = no value stored, nothing to match)")
    print("%-5s %7s | %8s %8s | %6s %6s %6s %6s %6s %6s" % ("class", "planted", "A-strict", "A-lenient", *B))
    tot = collections.Counter()
    for c in CLASSES:
        hv = g(c, "has_value")
        bs = [("%d/%d" % (g(c, "span_" + ap), hv)) if hv else "-" for ap in B]
        print("%-5s %7d | %8d %8d | %6s %6s %6s %6s %6s %6s" % (c, g(c, "planted"), g(c, "A_strict"), g(c, "A_lenient"), *bs))
        for k in ("planted", "A_strict", "A_lenient"):
            tot[k] += g(c, k)
    print("%-5s %7d | %8d %8d |" % ("ALL", tot["planted"], tot["A_strict"], tot["A_lenient"]))

    print("\nTABLE 2 - the two classes trufflehog has detectors for: value-level span match, then family-level (any K1/K3-family")
    print("          finding in the entry's file)")
    print("%-5s %7s | span: %s | family: %s" % ("class", "planted", "  ".join("%5s" % x for x in B), "  ".join("%5s" % x for x in B)))
    for c in ("K1", "K3"):
        print("%-5s %7d | span: %s | family: %s" % (c, g(c, "planted"), "  ".join("%5d" % g(c, "span_" + ap) for ap in B),
                                                    "  ".join("%5d" % g(c, "fam_" + ap) for ap in B)))
    print("\nTABLE 2b - K1 / K3 by vendor (underlying class, H1-H3 included; public prefix or host only): planted | A strict | rawvis | trufflehog span %s" % " ".join(B))
    for k, v in R.get("k1_by_vendor", {}).items():
        print("   %-20s %3d | %3d | %3d | %s" % (k, v.get("planted", 0), v.get("A_strict", 0), v.get("rawvis", 0),
                                                 " ".join("%3d" % v.get("span_" + ap, 0) for ap in B)))

    print("\nTABLE 3 - VISIBILITY in clear: rawvis = literal in the file bytes; B2p / B2b / B2u = in the exiftool dump(s)")
    print("%-5s %7s %10s | %6s %6s %6s %6s %6s" % ("class", "planted", "measurable", "rawvis", "B2p", "B2b", "B2u", "Bx"))
    for c in CLASSES:
        print("%-5s %7d %10d | %6d %6d %6d %6d %6d" % (c, g(c, "planted"), g(c, "has_vis"), g(c, "rawvis"), g(c, "vis_B2p"),
                                                         g(c, "vis_B2b"), g(c, "vis_B2u"), g(c, "vis_Bx")))
    print("   G1 visible as a decimal value matching a planted coordinate: B2p %d  B2b %d  B2u %d (of %d)" % (
        g("G1", "visval_B2p"), g("G1", "visval_B2b"), g("G1", "visval_B2u"), g("G1", "planted")))
    V = R["value_visibility"]
    print("\nVALUE-LEVEL visibility of the %d fake values in never_echo.json (located in a corpus file: %d)" % (V["total_values"], V["located"]))
    print("   in the dump of the file that plants them: B2p %d  B2b %d  B2u %d | anywhere in any dump: B2p %d  B2b %d  B2u %d" % (
        V["own_file"]["B2p"], V["own_file"]["B2b"], V["own_file"]["B2u"], V["any_dump"]["B2p"], V["any_dump"]["B2b"],
        V["any_dump"]["B2u"]))
    for k, v in sorted(V["by_kind"].items()):
        print("   %-7s values=%-3d located=%-3d | own p=%-3d b=%-3d u=%-3d | any p=%-3d b=%-3d u=%-3d" % (
            k, v.get("values", 0), v.get("located_in_a_file", 0), v.get("own_B2p", 0), v.get("own_B2b", 0), v.get("own_B2u", 0),
            v.get("any_B2p", 0), v.get("any_B2b", 0), v.get("any_B2u", 0)))

    print("\nTABLE 4 - per carrier: planted | A strict | A lenient | K1/K3 entries kk | trufflehog span on kk: B1w B2p B2b B2u | visible B2p B2b B2u")
    for k, v in R["carriers"].items():
        print("%-12s %4d | %4d %4d | kk=%-3d  %3d %3d %3d %3d | %3d %3d %3d" % (
            k, v.get("planted", 0), v.get("A_strict", 0), v.get("A_lenient", 0), v.get("kk_value", 0), v.get("kkspan_B1w", 0),
            v.get("kkspan_B2p", 0), v.get("kkspan_B2b", 0), v.get("kkspan_B2u", 0), v.get("vis_B2p", 0), v.get("vis_B2b", 0),
            v.get("vis_B2u", 0)))

    print("\nFALSE POSITIVES on the %d clean controls (files with >= 1 finding / findings)" % R["clean_files"])
    for ap in APPROACHES:
        d = R["fp"][ap]
        extra = ("  detectors: %s" % dict(d["detectors"])) if d.get("detectors") else ""
        print("   %-4s %2d files / %3d findings%s" % (ap, d["clean_files"], d["findings"], extra))
    print("   boundary files flagged (of %d): %s" % (R["boundary_files"], R["boundary_flagged"]))
    print("   trufflehog findings in positive/hostile/heavy files not tied to any planted value:", R["extra_unmatched_findings"])
    print("\nFALSE-CLEAN files (>= 1 required leak in the file; approach printed no finding and exited 0)")
    for ap in APPROACHES:
        print("   %-4s %d" % (ap, len(R["false_clean"][ap])))

    print("\nWALL TIME, sequential per-file invocations over %d registered files (seconds)" % R["files_scored"])
    for ap in APPROACHES:
        b = R["behaviour"][ap]
        print("   %-4s total %7.1f   by group %s" % (ap, b["total_s"], b["by_group_s"]))
        print("        exits %s  crash %d  timeouts %d  chunks0 %d  peak %.0f MB" % (
            b["exit_counts"], len(b["crash_files"]), len(b["timeouts"]), b["chunks0_files"], b["peak_mb"]))
    if "dirmode" in R:
        print("\nDIRECTORY MODE (one invocation per approach over a mirror without heavy/):", json.dumps(R["dirmode"]))
    print("\nECHO: files whose tool output contained planted text (secret / pii / canary / injection phrase / ordinary metadata)")
    for ap in APPROACHES:
        b = R["behaviour"][ap]
        print("   %-4s files %3d kinds %s" % (ap, b["files_with_echo"], b["echo_kinds"]))
    print("   B2u split (files by kind):", R["echo_b2u_files_by_kind"])
    print("\nexiftool stats:", R["exiftool_stats"])
    print("trufflehog detector names seen:", R["detector_names"])
    print("\nHOSTILE + HEAVY (exit, secs, peak MB, extra, echo-count, findings):")
    for h in R["hostile_heavy"]:
        print("   %-62s A=%s B1=%s B1w=%s B2b=%s" % (h["file"][:62], h["A"], h["B1"], h["B1w"], h["B2b"]))


def naive_on_dumps(a, key, never):
    """Supplementary (--naive-dumps): the repo's regex stand-in (eval/naive_baseline.py, NOT a real tool) run over the
    exiftool dumps that the run phase left in WORKDIR.  It answers 'what if the classification layer after exiftool were a
    handful of regexes instead of trufflehog?'.  Lenient matching (class present in the file); dumps above 64 MiB were
    deleted by the run phase and count as not scanned."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("naive_baseline", os.path.join(HERE, "naive_baseline.py"))
    nb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nb)
    work = os.path.abspath(a.workdir)
    root_fwd = S.fwd(os.path.abspath(a.corpus))
    facts = json.load(open(os.path.join(work, "facts.json"), encoding="utf-8"))
    order = sorted(key["files"])
    per = {c: collections.Counter() for c in CLASSES}
    fp_files = fp_find = missing = 0
    clean_n = 0
    for n, rel in enumerate(order):
        f = facts.get(rel)
        if not f or f.get("missing"):
            continue
        data = b""
        for sub in ("dumps_p", "dumps_b"):
            dp = os.path.join(work, sub, "%04d.txt" % n)
            if os.path.exists(dp):
                data += open(dp, "rb").read() + b"\n"
            else:
                missing += 1
        # exiftool adds the file's own absolute path (System:Directory) to every dump, which is a P1 leak the tool itself
        # creates; a real pipeline would add -x System:All.  Strip the corpus root so this check measures the content only.
        for variant in (root_fwd, root_fwd.replace("/", "\\")):
            data = data.replace(variant.encode("utf-8"), b"ROOT")
        seen, fl = set(), []
        for cls, off, text, det in nb.scan_bytes(data):
            if (cls, off) in seen:
                continue
            seen.add((cls, off))
            fl.append({"class": cls, "carrier": "raw-bytes", "location": "offset:%d" % off, "node_id": None,
                       "bypassed": False, "sha256_prefix": nb.sha8(text), "length": len(text), "severity": "high"})
        ent = key["files"][rel]
        if ent["group"] == "clean":
            clean_n += 1
            if fl:
                fp_files += 1
                fp_find += len(fl)
        res, _ = S.match_file(ent.get("expected", []), fl, "lenient")
        for e, r in zip(ent.get("expected", []), res):
            if e.get("optional"):
                continue
            per[e["class"]]["planted"] += 1
            per[e["class"]]["found"] += 1 if r["matched"] else 0
    print("\nSUPPLEMENTARY - regex stand-in (eval/naive_baseline.py, not a real tool) run over the exiftool dumps (p + b), lenient")
    tp = tf = 0
    for c in CLASSES:
        print("   %-3s %3d/%-3d" % (c, per[c]["found"], per[c]["planted"]))
        tp += per[c]["planted"]
        tf += per[c]["found"]
    print("   ALL %d/%d   clean controls with a finding: %d/%d (%d findings)   dump files missing (deleted >64 MiB): %d" % (
        tf, tp, fp_files, clean_n, fp_find, missing))
    return per


def main():
    ap = argparse.ArgumentParser(description="head-to-head: scan.py vs trufflehog vs exiftool+trufflehog")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--exiftool", required=True)
    ap.add_argument("--trufflehog", required=True)
    ap.add_argument("--scanner", default=DEFAULT_SCANNER)
    ap.add_argument("--phases", default="run,score")
    ap.add_argument("--only", default=None, help="comma separated corpus-relative prefixes")
    ap.add_argument("--mem-gib", type=float, default=4.0)
    ap.add_argument("--timeout", type=float, default=120.0, help="per-run timeout (s); heavy/ gets 5x")
    ap.add_argument("--dirmode", action="store_true", help="also time one directory-mode invocation per approach")
    ap.add_argument("--reuse", action="store_true", help="keep facts already in WORKDIR/facts.json")
    ap.add_argument("--naive-dumps", action="store_true", help="score phase: also run the regex stand-in over the exiftool dumps")
    a = ap.parse_args()
    global WORKDIR
    WORKDIR = os.path.abspath(a.workdir)
    os.makedirs(WORKDIR, exist_ok=True)
    root = os.path.abspath(a.corpus)
    key = json.load(open(os.path.join(root, "answer_key.json"), encoding="utf-8"))
    never = json.load(open(os.path.join(root, key.get("never_echo_file", "never_echo.json")), encoding="utf-8"))
    phases = set(x.strip() for x in a.phases.split(","))
    if "run" in phases:
        run_phase(a, key, never)
    if "score" in phases:
        score_phase(a, key, never)
        if a.naive_dumps:
            naive_on_dumps(a, key, never)
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(main())
