# -*- coding: utf-8 -*-
"""The release edits to scan.py and the package rules the scripts must keep.

The package copy of scan.py differs from the prototype in these ways, the first four tested here and the rest in
test_audit_fixes.py and test_package_fixes.py:
  1. it reads no environment variable of its own (the prototype had SHARE_SAFE_NO_FFPROBE); the one read is PATH, inside
     find_program(), which looks only in absolute PATH directories and never in the current folder,
  2. it deletes no file (the prototype removed its half-written temporary report),
  3. it has its own percent-decoder instead of importing urllib,
  4. --json refuses to replace an existing file that is not an earlier report of this program (and a path inside a scanned folder),
  5. HEIC/HEIF/AVIF are unsupported_media, the MP4 loci box is read, the verdict line is printed twice, and so on.
The static checks at the bottom keep the Agensi package rules true for every script in the package.
"""
import ast
import io
import json
import os
import random
import subprocess
import sys
import unittest

from _base import ScanCase, B, scan, SCAN, SCRIPTS, MAKE_DEMO, have_ffmpeg, read_bytes, read_text

PACKAGE_SCRIPTS = [SCAN, MAKE_DEMO]


class TestPercentDecode(unittest.TestCase):
    def test_matches_urllib_on_random_text(self):
        import urllib.parse
        rnd = random.Random(20261012)
        alphabet = ["%", "%", "%", "4", "1", "a", "F", "0", "e", "9", "2", "C", "3", "x", "z", " ", "\n", "-", "A", "b",
                    "é", "日", "\U0001F600", "\x00", "\x7f", "%c3%a9", "%e6%97%a5", "%F0%9F%98%80", "%ff", "%80", "%41%42"]
        for _ in range(4000):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
            self.assertEqual(scan.percent_decode(s), urllib.parse.unquote(s, errors="replace"), repr(s))

    def test_matches_urllib_on_realistic_text(self):
        import urllib.parse
        for s in ("https%3A%2F%2Fexample.test%2Fa%3Fb%3Dc", "api_key%3D%20abc%2B%2F", "100%", "%%41", "%4", "%zz%41",
                  "caf%C3%A9 %E2%82%AC", "bad%E2%82", "", "no escapes at all"):
            self.assertEqual(scan.percent_decode(s), urllib.parse.unquote(s, errors="replace"), s)

    def test_percent_encoded_webhook_still_found(self):
        url = B.Fake().discord_webhook()
        enc = "".join("%%%02X" % ord(c) if c in ":/" else c for c in url)
        rp = scan.Report()
        sink = scan.Sink(rp, "x")
        scan.process_blob(sink, "png:tEXt", "tEXt[comment]", ("see " + enc + " and " + enc).encode())
        self.assertTrue([f for f in rp.findings if f["class"] == "K3"])


class TestNoEnvironmentRead(ScanCase):
    def test_old_environment_switch_is_ignored(self):
        # the prototype skipped ffprobe when SHARE_SAFE_NO_FFPROBE=1; the package must not look at it
        if not have_ffmpeg():
            self.skipTest("ffmpeg/ffprobe not on PATH: cannot make an MP4 to see whether ffprobe is used")
        mp4 = self.write("t.mp4", B.make_mp4(meta=B.meta_ilst([B.ilst_item(b"\xa9cmt", "hello there")])))
        r = self.cli(mp4, ffprobe=True, env={"SHARE_SAFE_NO_FFPROBE": "1"})
        self.assertEqual(r.doc["summary"]["ffprobe"], "used")

    def test_no_environment_access_in_any_script(self):
        for path in PACKAGE_SCRIPTS:
            tree = ast.parse(read_text(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv", "putenv", "environb"):
                    self.fail("%s reads the environment (line %d)" % (os.path.basename(path), node.lineno))
                if isinstance(node, ast.Name) and node.id in ("environ", "getenv"):
                    self.fail("%s reads the environment (line %d)" % (os.path.basename(path), node.lineno))

    def test_path_is_read_in_one_function_only(self):
        # the one environment read the scripts make: os.get_exec_path() inside find_program(), to find ffprobe / ffmpeg
        for path in PACKAGE_SCRIPTS:
            tree = ast.parse(read_text(path))
            where = set()
            for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
                for n in ast.walk(fn):
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get_exec_path":
                        where.add(fn.name)
            self.assertEqual(where, {"find_program"}, os.path.basename(path))


class TestNoDeletion(ScanCase):
    DELETERS = {"remove", "unlink", "rmdir", "removedirs", "rmtree", "truncate", "rename"}

    def test_no_delete_calls_in_any_script(self):
        for path in PACKAGE_SCRIPTS:
            tree = ast.parse(read_text(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                    if name in self.DELETERS:
                        self.fail("%s calls %s (line %d)" % (os.path.basename(path), name, node.lineno))

    def test_a_failed_report_write_deletes_nothing_and_leaves_the_partial_temp_file(self):
        out = os.path.join(self.dir, "rep.json")
        real_dump = json.dump

        def boom(doc, fh, **kw):
            fh.write("{partial")
            raise OSError(28, "No space left on device")

        json.dump = boom
        try:
            with self.assertRaises(OSError):
                scan._write_json_report(out, {"tool": "x"})
        finally:
            json.dump = real_dump
        left = [n for n in os.listdir(self.dir) if ".tmp-" in n]
        self.assertEqual(len(left), 1, "the partial temporary report must still be there: nothing is deleted")
        self.assertFalse(os.path.exists(out))

    def test_failed_report_on_a_clean_scan_is_exit_2_not_0(self):
        p = self.write("clean.png", B.make_png())
        old = scan._write_json_report

        def fail(path, doc):
            raise OSError(5, "denied")

        scan._write_json_report = fail
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            code = scan.main([p, "--no-ffprobe", "--json", os.path.join(self.dir, "r.json")])
            printed = sys.stdout.getvalue()
        finally:
            scan._write_json_report = old
            sys.stdout, sys.stderr = old_out, old_err
        self.assertEqual(code, 2)
        self.assertNotIn("NOTHING FOUND", printed)             # the report is still printed, but it is not a pass ...
        self.assertTrue(printed.splitlines()[-1].startswith("RESULT: NOT A PASS"))
        self.assertTrue(printed.splitlines()[-1].endswith("(exit 2)"))      # ... and it says exit 2, the code the process returns
        self.assertIn("REPORT NOT WRITTEN", printed)


class TestJsonReportGuard(ScanCase):
    def target(self, name="rep.json"):
        return os.path.join(self.dir, name)

    def scan_to(self, report, png=None):
        png = png or self.write("c.png", B.make_png(B.t_text("Comment", "k " + self.fake.hf())))
        return subprocess.run([sys.executable, "-I", "-B", SCAN, png, "--no-ffprobe", "--json", report],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)

    def test_new_file_is_created(self):
        p = self.scan_to(self.target())
        self.assertEqual(p.returncode, 1)
        self.assertEqual(json.loads(read_text(self.target()))["tool"], "share-safe-renders/scan.py")

    def test_an_earlier_report_is_replaced(self):
        self.scan_to(self.target())
        first = read_bytes(self.target())
        self.assertEqual(self.scan_to(self.target(), self.write("d.png", B.make_png())).returncode, 0)
        self.assertNotEqual(read_bytes(self.target()), first)

    def test_an_empty_file_is_replaced(self):
        open(self.target(), "wb").close()
        self.assertEqual(self.scan_to(self.target()).returncode, 1)
        self.assertGreater(os.path.getsize(self.target()), 10)

    def test_someone_elses_file_is_refused_and_left_untouched(self):
        mine = self.write("notes.txt", b"my notes, not a report\n")
        p = self.scan_to(mine)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(read_bytes(mine), b"my notes, not a report\n")
        self.assertIn(b"not an earlier report", p.stderr)
        self.assertNotIn(b"notes.txt", p.stderr + p.stdout)    # usage errors never echo what was typed

    def test_another_json_file_is_refused_too(self):
        other = self.write("settings.json", b'{"tool": "something else"}\n')
        self.assertEqual(self.scan_to(other).returncode, 2)
        self.assertEqual(read_bytes(other), b'{"tool": "something else"}\n')

    def test_a_render_is_refused(self):
        png = self.write("keep.png", B.make_png())
        before = read_bytes(png)
        self.assertEqual(self.scan_to(png, self.write("o.png", B.make_png())).returncode, 2)
        self.assertEqual(read_bytes(png), before)


class TestPackageRules(unittest.TestCase):
    """Agensi package rules, checked on the source of every script in the package."""

    BANNED_IMPORTS = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "telnetlib", "requests", "xmlrpc",
                      "asyncio", "ctypes", "pickle", "marshal", "webbrowser", "multiprocessing"}

    def imports(self, path):
        tree = ast.parse(read_text(path))
        out = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                out.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                out.add(n.module.split(".")[0])
        return out

    def test_no_network_or_dangerous_imports(self):
        for path in PACKAGE_SCRIPTS:
            bad = self.imports(path) & self.BANNED_IMPORTS
            self.assertEqual(bad, set(), os.path.basename(path))

    def test_every_subprocess_call_is_an_argument_list_to_a_named_tool(self):
        allowed = {"scan.py": {"ffprobe"}, "make_demo.py": {"ffmpeg"}}
        for path in PACKAGE_SCRIPTS:
            src = read_text(path)
            tree = ast.parse(src)
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"]
            for c in calls:
                self.assertEqual(c.func.attr, "run", "only subprocess.run is used")
                first = c.args[0]
                if isinstance(first, ast.BinOp):                   # [exe] + args
                    first = first.left
                self.assertIsInstance(first, ast.List, "an argument list, never a shell string")
                for kw in c.keywords:
                    self.assertFalse(kw.arg == "shell", "no shell")
            # the program names that appear as string constants passed to find_program(): only the allowed tool; the
            # library lookup (which searches the current folder first on Windows) is not used at all
            names = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "find_program":
                    names.update(a.value for a in n.args if isinstance(a, ast.Constant))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "which":
                    self.fail("%s uses a which() lookup, which searches the current folder on Windows" % os.path.basename(path))
            self.assertEqual(names, allowed[os.path.basename(path)], os.path.basename(path))
            for banned in ("os.system", "os.popen", "os.spawn", "os.exec", "shell=True", "eval(", "exec(", "__import__"):
                self.assertNotIn(banned, src, "%s uses %s" % (os.path.basename(path), banned))

    def test_scripts_start_with_a_shebang_and_a_purpose_comment(self):
        for path in PACKAGE_SCRIPTS:
            head = read_bytes(path, 2000).decode('utf-8')
            self.assertTrue(head.startswith("#!/usr/bin/env python3"), os.path.basename(path))
            self.assertIn('"""', head, os.path.basename(path))

    def test_files_are_opened_for_writing_only_in_the_places_documented(self):
        expect = {"scan.py": {"_write_json_report", "_mute_std"},          # the report; the null device
                  "make_demo.py": {"build_mp4_05", "main"}}                # the hidden box; the demo files
        for path in PACKAGE_SCRIPTS:
            tree = ast.parse(read_text(path))
            where = set()
            for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
                for n in ast.walk(fn):
                    is_open = isinstance(n.func, ast.Name) and n.func.id == "open" if isinstance(n, ast.Call) else False
                    is_fdopen = isinstance(n.func, ast.Attribute) and n.func.attr == "fdopen" if isinstance(n, ast.Call) else False
                    if is_open or is_fdopen:                    # (the report is written through os.fdopen on a tempfile.mkstemp descriptor)
                        modes = [a.value for a in n.args[1:2] if isinstance(a, ast.Constant)]
                        if modes and any(ch in modes[0] for ch in "wax+"):
                            where.add(fn.name)
            self.assertEqual(where, expect[os.path.basename(path)], os.path.basename(path))


if __name__ == "__main__":
    unittest.main()
