# -*- coding: utf-8 -*-
"""SKILL.md tells the agent to put double quotes around every path and warns about a trailing backslash inside quotes on
Windows. Run the documented command text through the real shells (PowerShell and cmd on Windows, sh elsewhere), in folders
whose names contain spaces, and check what the doc claims."""
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from _base import PKG, MAKE_DEMO, read_text, have_ffmpeg
import doc_commands as DC

SKILL = read_text(os.path.join(PKG, "SKILL.md"))
CMDS = DC.extract("SKILL.md", SKILL)
FFMPEG = {re.search(r"<IN\.(\w+)>", c.text).group(1): c for c in CMDS if c.text.startswith("ffmpeg ")}
WIN_FORM = [c for c in CMDS if c.text.startswith('py -3 -I -B "<SKILL_DIR>')][0]
POSIX_FORM = [c for c in CMDS if c.text.startswith('python3 -I -B "<SKILL_DIR>')][0]


class Spaced(object):
    """A workspace whose every folder name contains a space."""

    def __init__(self):
        self._td = tempfile.TemporaryDirectory(prefix="ssr quoting ")
        root = self._td.name
        self.skill_dir = os.path.join(root, "my skills", "share-safe-renders")
        shutil.copytree(PKG, self.skill_dir, ignore=shutil.ignore_patterns("__pycache__"))
        self.demo = os.path.join(root, "my renders", "demo out")
        subprocess.run([sys.executable, "-I", "-B", MAKE_DEMO, self.demo], check=True, stdout=subprocess.PIPE)
        self.copies = os.path.join(root, "my copies")
        os.makedirs(self.copies)
        self._n = 0
        self.report = os.path.join(root, "my reports", "rep.json")
        os.makedirs(os.path.dirname(self.report))

    def text(self, cmd, demo=None):
        t = cmd.text.replace("<SKILL_DIR>", self.skill_dir).replace("<PATH>", demo or self.demo).replace("<REPORT>", self.report)
        return t

    def export_text(self, ext, name):
        """The documented export command for `ext`, with a spaced input and a new spaced output; returns (text, out path)."""
        self._n += 1
        out = os.path.join(self.copies, "copy %d.%s" % (self._n, ext))
        src = os.path.join(self.demo, name)
        return FFMPEG[ext].text.replace("<IN.%s>" % ext, src).replace("<OUT.%s>" % ext, out), out

    def close(self):
        self._td.cleanup()


DEMO_FILES = {"png": "01_png_api_key_and_username.png", "jpg": "06_jpeg_exif_gps.jpg", "mp4": "05_mp4_prompt_tag_and_free_box.mp4"}

# Legal POSIX file names that carry a command substitution: (label, file name, flag the substitution creates). The flag is a bare name
# (no slash, so the file name stays a single path component); the shell must run with cwd = the folder that should receive it.
SH_SUBSTITUTIONS = (("$(...)", "a$(touch FLAG_DOLLAR).png", "FLAG_DOLLAR"),
                    ("a backtick", "a`touch FLAG_BACKTICK`.png", "FLAG_BACKTICK"))


@unittest.skipUnless(os.name == "nt" and shutil.which("py") and DC.alias_works("py -3"),
                     "the Windows form needs Windows, PowerShell or cmd, and the py launcher")
class TestWindowsShells(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = Spaced()
        cls.w_ffmpeg = bool(have_ffmpeg())

    @classmethod
    def tearDownClass(cls):
        cls.w.close()

    def run_ps(self, text):
        # -EncodedCommand hands PowerShell the exact text, so the quotes in the doc's command are the quotes it parses
        enc = base64.b64encode((text + "; exit $LASTEXITCODE").encode("utf-16-le")).decode("ascii")      # PowerShell reports $? unless told
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    def run_cmd(self, text):
        # one command-line string: cmd /c "<the set command SKILL.md gives for cmd>& <the doc's command>" (cmd strips the outer
        # pair of quotes and keeps the inner ones); "Where to run them" in SKILL.md allows cmd only after that set command
        guard = re.search(r"first run `(set [^`]+)` in the same cmd session", " ".join(SKILL.split()))
        self.assertIsNotNone(guard, "SKILL.md no longer gives the set command for cmd")
        p = subprocess.run('cmd /d /c "' + guard.group(1) + '& ' + text + '"', stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=300)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    def test_documented_command_in_powershell_and_cmd_with_spaces_in_every_path(self):
        text = self.w.text(WIN_FORM)
        for shell in (self.run_ps, self.run_cmd):
            if os.path.exists(self.w.report):
                os.utime(self.w.report)                      # (an earlier report of this program may be replaced)
            code, out = shell(text)
            self.assertEqual(code, 1, out[-600:])
            self.assertIn("RESULT: FINDINGS", out)
            self.assertTrue(os.path.exists(self.w.report))

    def test_documented_export_commands_in_powershell_and_cmd_with_spaces_in_every_path(self):
        if not self.w_ffmpeg:
            self.skipTest("ffmpeg is not on PATH")
        for ext, name in DEMO_FILES.items():
            if not os.path.exists(os.path.join(self.w.demo, name)):
                continue
            for shell in (self.run_ps, self.run_cmd):
                text, out = self.w.export_text(ext, name)
                code, printed = shell(text)
                self.assertEqual((code, printed.strip()), (0, ""), "%s: %s" % (ext, printed[-300:]))
                self.assertTrue(os.path.exists(out), text)

    def test_the_control_without_the_quotes_the_same_command_fails_on_a_spaced_path(self):
        if not self.w_ffmpeg:
            self.skipTest("ffmpeg is not on PATH")
        text, out = self.w.export_text("png", DEMO_FILES["png"])
        unquoted = text.replace('"', "")
        code, printed = self.run_ps(unquoted)
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(out))

    def test_a_trailing_backslash_inside_quotes_breaks_the_command_exactly_as_skill_md_says(self):
        self.assertIn('write `"D:\\My Renders"`, not `"D:\\My Renders\\"`', SKILL)
        text = self.w.text(WIN_FORM, demo=self.w.demo + "\\")
        for shell in (self.run_ps, self.run_cmd):
            code, out = shell(text)
            self.assertEqual(code, 3, out[-600:])
            self.assertIn("ERROR not_found", out)
            self.assertIn("COULD NOT SCAN", out)
            self.assertNotIn("NOTHING FOUND", out)


@unittest.skipIf(os.name == "nt", "the POSIX form is run through sh on macOS and Linux; this machine is Windows")
@unittest.skipUnless(shutil.which("sh") and DC.alias_works("python3"), "needs sh and python3")
class TestPosixShell(unittest.TestCase):
    def test_documented_command_in_sh_with_spaces_in_every_path(self):
        w = Spaced()
        try:
            p = subprocess.run(["sh", "-c", w.text(POSIX_FORM)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=300)
            self.assertEqual(p.returncode, 1, p.stdout.decode()[-600:])
            self.assertIn(b"RESULT: FINDINGS", p.stdout)
        finally:
            w.close()


@unittest.skipIf(os.name == "nt", "the POSIX forms are run through sh on macOS and Linux; this machine is Windows")
@unittest.skipUnless(shutil.which("sh") and have_ffmpeg(), "needs sh and ffmpeg")
class TestPosixExportCommands(unittest.TestCase):
    """SKILL.md: double quotes around every path, and a name with a dollar sign, a backtick or a quote is never pasted at all
    (\"Names in commands\"; the tests of that rule are in test_review_fixes.py). This test is the sh half of the evidence for it: sh
    runs a command substitution (`$(...)` and a backtick) inside double quotes, so such a name must not reach a command; single quotes
    would keep it literal in sh, but they are not the documented answer, because Windows PowerShell 5.1 ends a single-quoted string at a
    typographic quote.

    A file name cannot hold a slash, so the command inside the hostile name is `touch <flag>` with a bare relative flag name, and sh is
    started with cwd = the folder where the flag must appear. (A flag given as a full path puts slashes in the name, which is then a
    path into folders that do not exist, and the file cannot even be created.)"""

    def sh(self, text, cwd=None):
        return subprocess.run(["sh", "-c", text], cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)

    def test_spaces_and_the_single_quote_rule(self):
        w = Spaced()
        try:
            # (1) the documented double-quoted command, for a plain name in folders whose names contain spaces
            text, out = w.export_text("png", DEMO_FILES["png"])
            p = self.sh(text)
            self.assertEqual((p.returncode, p.stdout), (0, b""))
            self.assertTrue(os.path.exists(out))
            src = os.path.join(w.demo, DEMO_FILES["png"])
            template = FFMPEG["png"].text
            for n, (label, name, flag_name) in enumerate(SH_SUBSTITUTIONS, 1):
                with self.subTest(label):
                    flag = os.path.join(w.copies, flag_name)
                    hostile = os.path.join(w.copies, name)           # one file in the spaced folder: the name holds no slash
                    shutil.copyfile(src, hostile)
                    self.assertFalse(os.path.exists(flag), "the flag must not exist before the control runs, or the control proves nothing")
                    o1 = os.path.join(w.copies, "o1_%d.png" % n)
                    o2 = os.path.join(w.copies, "o2_%d.png" % n)
                    # (2) the control: the documented double quotes do NOT stop the substitution in the name; sh ran it and the name that
                    # reached ffmpeg is not the name of the file, so ffmpeg fails and writes nothing
                    double = template.replace("<IN.png>", hostile).replace("<OUT.png>", o1)
                    p = self.sh(double, cwd=w.copies)
                    self.assertTrue(os.path.exists(flag), "the control: double quotes do not stop %s in a file name" % label)
                    self.assertNotEqual(p.returncode, 0, "sh rewrote the name, so the file it names does not exist: " + repr(p.stdout))
                    self.assertFalse(os.path.exists(o1))
                    os.remove(flag)
                    # (3) single quotes keep the name literal: nothing runs and the command succeeds on the real file
                    single = template.replace('"<IN.png>"', "'%s'" % hostile).replace("<OUT.png>", o2)
                    p = self.sh(single, cwd=w.copies)
                    self.assertEqual((p.returncode, p.stdout), (0, b""))
                    self.assertTrue(os.path.exists(o2))
                    self.assertFalse(os.path.exists(flag), "single quotes keep the name literal")
        finally:
            w.close()


class TestTheDocumentedFormsExist(unittest.TestCase):
    def test_the_export_templates_are_quoted_and_quiet(self):
        self.assertEqual(sorted(FFMPEG), ["jpg", "mp4", "png"])
        for ext, c in FFMPEG.items():
            self.assertRegex(c.text, r'^ffmpeg -loglevel error -n -i "<IN\.%s>" .* "<OUT\.%s>"$' % (ext, ext))

    def test_both_forms_are_in_skill_md(self):
        self.assertRegex(WIN_FORM.text, r'^py -3 -I -B "<SKILL_DIR>\\scripts\\scan\.py" "<PATH>" --json "<REPORT>"$')
        self.assertRegex(POSIX_FORM.text, r'^python3 -I -B "<SKILL_DIR>/scripts/scan\.py" "<PATH>" --json "<REPORT>"$')


if __name__ == "__main__":
    unittest.main()
