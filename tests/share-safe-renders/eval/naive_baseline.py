#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
naive_baseline.py - a deliberately simple STAND-IN for a "strings | regex" scanner.

    *** THIS IS NOT strings, trufflehog, gitleaks or exiftool. None of those is installed on the rig. ***
    It is a 100-line imitation of the cheapest possible approach, used only as the floor the real
    scanner has to beat:

        read the raw bytes of the file
        -> pull out every run of printable ASCII (what `strings -a -n 6` does)
        -> run a list of credential / PII regexes over each run

    What it does NOT do (on purpose):
        * no decompression         (zTXt / compressed iTXt are opaque)
        * no JSON parsing          (no node ids, no mode 4 / mode 2 bypass flag, no double-encoded JSON, no field
                                    names except what a regex sees on one line of text)
        * no container parsing     (PNG chunks, EXIF IFDs, MP4 boxes and tags are just bytes; GPS rationals in EXIF
                                    are binary, only an XMP attribute written as text can match)
        * no policy                (no placeholder e-mail rule, no trivial-value rule, no word boundaries, no
                                    length windows beyond what the regex itself says)
        * no "could not scan" state (an unreadable file prints a warning and counts as clean; exit codes are
                                    only 0 = no match, 1 = match, 2 = usage)

    Same CLI and the same JSON field names as scan.py so eval/score.py can score both:
        python naive_baseline.py PATH [PATH...] [--json OUT.json]
    Unlike the real tools it never prints the matched text either (class, byte offset, length, hash prefix only).

Python 3.9+, standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

LABEL = "naive-strings-regex-STANDIN"
MIN_RUN = 6


def J(*p):
    return "".join(p)


# --- K1: vendor key shapes (prefix fragments are joined so no credential-shaped literal sits in this file) --------
K1_RES = [
    ("openai", re.compile(J("s", "k", "-", "(?:proj-)?[A-Za-z0-9_-]{20,}"))),
    ("anthropic", re.compile(J("s", "k", "-ant-", "[A-Za-z0-9_-]{20,}"))),
    ("github", re.compile(J("gh", "[pousr]", "_", "[A-Za-z0-9]{30,}"))),
    ("github_pat", re.compile(J("github", "_pat_", "[A-Za-z0-9_]{40,}"))),
    ("aws", re.compile(J("AK", "IA", "[0-9A-Z]{16}"))),
    ("google", re.compile(J("AI", "za", "[0-9A-Za-z_-]{35}"))),
    ("slack", re.compile(J("xo", "x[baprs]-", "[0-9A-Za-z-]{10,}"))),
    ("stripe", re.compile(J("sk", "_live_", "[0-9a-zA-Z]{20,}"))),
    ("huggingface", re.compile(J("h", "f", "_", "[A-Za-z0-9]{30,}"))),
]
# --- K3: webhooks ---------------------------------------------------------------------------------------------
K3_RES = [
    re.compile(r"https?://(?:discord|discordapp)\.com/api(?:/v\d+)?/web" + r"hooks/\d{15,}/[A-Za-z0-9_-]{30,}"),
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
]
# --- K2: secret-named field with a value, on one line of text (quotes / backslashes tolerated) -------------------
K2_RE = re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret|token|password|passwd|"
                   r"authorization|bearer)[\\\"']*\s*[:=]\s*[\\\"']*([^\\\"'\s,}\]]{8,})")
K2_TRIVIAL = {"none", "null", "false", "true"}
# --- PII ------------------------------------------------------------------------------------------------------
P1_RES = [re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+([^\\/\"'\s]+)"), re.compile(r"/home/([^/\"'\s\\]+)/"),
          re.compile(r"/Users/([^/\"'\s\\]+)/")]
P2_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
P3_IP = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.]*\d)")
P3_HOST = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:local|lan|internal)\b")
# --- G1: only an XMP attribute written as text can show up in `strings` -----------------------------------------
G1_RE = re.compile(r"GPS(?:Latitude|Longitude)[\\\"'=:\s]{1,6}[-+0-9]")

RUN_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_RUN)


def sha8(s):
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:8]


def private_ip(a, b, c, d):
    if max(a, b, c, d) > 255:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def scan_bytes(data):
    """-> list of (class, offset, matched_text, detail). Matched text never leaves this function's caller."""
    out = []
    for m in RUN_RE.finditer(data):
        base = m.start()
        run = m.group(0).decode("ascii")
        for name, rx in K1_RES:
            for k in rx.finditer(run):
                out.append(("K1", base + k.start(), k.group(0), name))
        for rx in K3_RES:
            for k in rx.finditer(run):
                out.append(("K3", base + k.start(), k.group(0), "webhook"))
        for k in K2_RE.finditer(run):
            if k.group(1).lower() not in K2_TRIVIAL:
                out.append(("K2", base + k.start(1), k.group(1), "field"))
        for rx in P1_RES:
            for k in rx.finditer(run):
                out.append(("P1", base + k.start(1), k.group(1), "home"))
        for k in P2_RE.finditer(run):
            out.append(("P2", base + k.start(), k.group(0), "email"))
        for k in P3_IP.finditer(run):
            if private_ip(*[int(x) for x in k.groups()]):
                out.append(("P3", base + k.start(), k.group(0), "ipv4"))
        for k in P3_HOST.finditer(run):
            out.append(("P3", base + k.start(), k.group(0), "host"))
        for k in G1_RE.finditer(run):
            out.append(("G1", base + k.start(), k.group(0), "xmp-text"))
    return out


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for dp, dns, fns in os.walk(p, followlinks=False):
                # minimal loop guard so the stand-in cannot spin forever on a junction loop
                dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d))
                          and not (hasattr(os.path, "isjunction") and os.path.isjunction(os.path.join(dp, d)))]
                if dp[len(p):].count(os.sep) > 12:
                    dns[:] = []
                for fn in sorted(fns):
                    yield os.path.join(dp, fn)
        else:
            yield p


def main(argv):
    paths, jpath, i = [], None, 0
    while i < len(argv):
        a = argv[i]
        if a == "--json":
            if i + 1 >= len(argv):
                print("usage: naive_baseline.py PATH [PATH...] [--json OUT.json]", file=sys.stderr)
                return 2
            jpath = argv[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            if a in ("--max-bytes", "--max-depth", "--max-files") and i + 1 < len(argv):
                i += 2          # accepted and ignored: the stand-in has no limits
                continue
            print("unknown option", file=sys.stderr)
            return 2
        paths.append(a)
        i += 1
    if not paths:
        print("usage: naive_baseline.py PATH [PATH...] [--json OUT.json]", file=sys.stderr)
        return 2
    findings, nfiles = [], 0
    for f in iter_files(paths):
        try:
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError:
            print("warning: cannot read a file (counted as clean by this stand-in)", file=sys.stderr)
            continue
        nfiles += 1
        seen = set()
        for cls, off, text, det in scan_bytes(data):
            key = (cls, off)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"file": f, "carrier": "raw-bytes", "class": cls, "location": "offset:%d" % off,
                             "node_id": None, "bypassed": False, "length": len(text), "sha256_prefix": sha8(text),
                             "severity": "high", "detail": det, "tags": []})
    print("%s (STAND-IN for strings|regex, not a real tool): %d file(s), %d match(es)" % (LABEL, nfiles, len(findings)))
    for f in findings:
        print("  %s  file=%s  %s  length=%d  sha256=%s" % (f["class"], f["file"], f["location"], f["length"], f["sha256_prefix"]))
    if jpath:
        with open(jpath, "w", encoding="utf-8") as fh:
            json.dump({"tool": LABEL, "version": "0", "exit_code": 1 if findings else 0,
                       "summary": {"files_scanned": nfiles, "findings": len(findings)}, "findings": findings,
                       "errors": [], "info": [], "known_misses": ["everything a stand-in cannot see"]}, fh)
    return 1 if findings else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(main(sys.argv[1:]))
