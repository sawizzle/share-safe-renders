# -*- coding: utf-8 -*-
"""Shared test plumbing: repository paths, temp dirs, an in-process scan helper and a CLI runner.

Layout this file expects (the repository root is two folders above this folder):

    packages/share-safe-renders/       the package that is zipped for sale (SKILL.md, scripts/, ...)
    tests/share-safe-renders/          these tests (not part of the package)
    listing/share-safe-renders/        the listing text (not part of the package)
"""
import collections
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PKG = os.path.join(REPO, "packages", "share-safe-renders")
SCRIPTS = os.path.join(PKG, "scripts")
SCAN = os.path.join(SCRIPTS, "scan.py")
MAKE_DEMO = os.path.join(SCRIPTS, "make_demo.py")
LISTING = os.path.join(REPO, "listing", "share-safe-renders")
PRECHECK = os.path.join(REPO, "tools", "agensi_precheck_v3.py")
for _p in (HERE, SCRIPTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.dont_write_bytecode = True        # importing scan.py must not leave a __pycache__ inside the package
import scan  # noqa: E402
import _build as B  # noqa: E402

Run = collections.namedtuple("Run", "code out err doc raw")


def read_bytes(path, n=-1):
    """Read a file and close it (tests must not leave handles open)."""
    with open(path, "rb") as fh:
        return fh.read(n)


def read_text(path):
    return read_bytes(path).decode("utf-8")


def have_ffmpeg():
    """True when both ffmpeg and ffprobe are on PATH (tests that need them skip with a stated reason)."""
    return bool(scan.find_program("ffmpeg") and scan.find_program("ffprobe"))


class ScanCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="sharesafe_")
        self.dir = self._td.name
        self.addCleanup(self._td.cleanup)
        self.fake = B.Fake()
        self._n = 0

    # ---- files ----------------------------------------------------------
    def write(self, name, data):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    # ---- in-process scan ------------------------------------------------
    def inproc(self, path, ffprobe=False, max_bytes=1 << 30):
        rp = scan.Report()
        scan.scan_file(path, rp, max_bytes, ffprobe, True)
        return rp

    def code_of(self, rp):
        return scan.result_code(rp)

    @staticmethod
    def prim(rp, cls=None):
        return [f for f in rp.findings if "companion_of" not in f and (cls is None or f["class"] == cls)]

    @staticmethod
    def comp(rp, cls):
        return [f for f in rp.findings if f.get("companion_of") and f["class"] == cls]

    @staticmethod
    def classes(rp):
        return set(f["class"] for f in rp.findings)

    # ---- CLI --------------------------------------------------------------
    def cli(self, *args, env=None, json_out=True, ffprobe=False, pyargs=(), timeout=300):
        self._n += 1
        argv = list(args)
        jpath = None
        if json_out:
            jpath = os.path.join(self.dir, "_report_%d.json" % self._n)
            argv += ["--json", jpath]
        if not ffprobe:
            argv.append("--no-ffprobe")
        e = dict(os.environ)
        for k in ("PYTHONIOENCODING", "PYTHONUTF8"):
            e.pop(k, None)
        if env:
            e.update(env)
        p = subprocess.run([sys.executable] + list(pyargs) + [SCAN] + argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=e, timeout=timeout)
        doc = None
        if jpath and os.path.exists(jpath):
            with open(jpath, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        return Run(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), doc,
                   p.stdout + p.stderr)
