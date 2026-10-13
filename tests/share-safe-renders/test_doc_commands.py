# -*- coding: utf-8 -*-
"""Every command line written in SKILL.md, README.md and references/ runs as written (in a throw-away workspace
that holds a COPY of the package, so the tests are not needed next to it), exits with a code the doc allows, and does
what the doc says it does."""
import json
import os
import re
import subprocess
import sys
import unittest

from _base import PKG, read_text, read_bytes, have_ffmpeg
import doc_commands as DC

DOCS = {"SKILL.md": os.path.join(PKG, "SKILL.md"), "README.md": os.path.join(PKG, "README.md")}
for _n in sorted(os.listdir(os.path.join(PKG, "references"))):
    DOCS["references/" + _n] = os.path.join(PKG, "references", _n)
COMMANDS = {name: DC.extract(name, read_text(path)) for name, path in DOCS.items()}

UNITTEST_LINE = "python -I -B -m unittest discover -s tests/share-safe-renders"


def kind_of(argv):
    """What a command is, from its arguments: scan | demo | version | pycode | ffmpeg | other."""
    joined = " ".join(argv[1:])
    if argv[0].lower().endswith(("ffmpeg", "ffmpeg.exe")):
        return "ffmpeg"
    if "scan.py" in joined:
        return "scan"
    if "make_demo.py" in joined:
        return "demo"
    if argv[1:] == ["--version"]:
        return "version"
    if argv[1:2] == ["-c"]:
        return "pycode"
    return "other"


class TestExtraction(unittest.TestCase):
    def test_the_docs_contain_commands_and_every_one_is_understood(self):
        for name, cmds in COMMANDS.items():
            for c in cmds:
                if c.text == UNITTEST_LINE:
                    continue
                argv = c.argv_template()
                self.assertIn(argv[0], DC.COMMAND_WORDS, c)
                self.assertEqual(DC.unknown_placeholders(c), [], "%r uses a placeholder the tests cannot fill" % c)
        self.assertGreaterEqual(len(COMMANDS["SKILL.md"]), 8)
        self.assertGreaterEqual(len(COMMANDS["README.md"]), 5)
        self.assertGreaterEqual(len(COMMANDS["references/how-to-export-clean.md"]), 5)

    def test_the_extractor_and_the_runner_can_fail(self):
        # negative controls: an unfillable placeholder is reported, a wrong command is not extracted as fine, a failing command fails
        bad = DC.extract("fake.md", "```sh\npython \"<SKILL_DIR>/scripts/scan.py\" \"<NOWHERE>\" --json \"<REPORT>\"\n```\n")
        self.assertEqual(DC.unknown_placeholders(bad[0]), ["<NOWHERE>"])
        good = DC.extract("fake.md", "```sh\npython \"<SKILL_DIR>/scripts/scan.py\" \"<PATH>\" --json \"<REPORT>\"\n```\n")
        self.assertEqual(DC.unknown_placeholders(good[0]), [])
        self.assertEqual(DC.extract("fake.md", "Use `python` or `ffmpeg` here, and `-c copy` too."), [])
        ws = DC.Workspace()
        try:
            wrong = DC.extract("fake.md", "```sh\npython \"<SKILL_DIR>/scripts/no_such_script.py\"\n```\n")[0]
            code, out, argv = ws.run(wrong)
            self.assertNotEqual(code, 0)
            self.assertNotIn("RESULT:", out)
        finally:
            ws.close()

    def test_the_only_command_that_is_not_run_is_the_suite_itself(self):
        skipped = [c for cmds in COMMANDS.values() for c in cmds if c.text == UNITTEST_LINE]
        self.assertEqual([c.doc for c in skipped], ["README.md"])


class TestReadmeTryIt(unittest.TestCase):
    """The README commands write into a folder the reader names (<WORK>), never into the skill folder (finding N6). Run them in order,
    with <WORK> a different folder from the skill folder, and check that the skill folder is untouched."""

    @classmethod
    def setUpClass(cls):
        cls.ws = DC.Workspace()
        cls.cmds = [c for c in COMMANDS["README.md"] if c.text != UNITTEST_LINE and c.kind == "fenced"]

    @classmethod
    def tearDownClass(cls):
        cls.ws.close()

    def test_the_commands_in_order(self):
        ws = self.ws
        texts = [c.text for c in self.cmds]
        self.assertEqual(texts[:3], ['python "<SKILL_DIR>/scripts/make_demo.py" "<WORK>/demo"',
                                     'python "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo" --json "<WORK>/demo_report.json"',
                                     'python "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo/04_clean.png"'])
        want = {texts[0]: 0, texts[1]: 1, texts[2]: 0}
        before = sorted(os.listdir(ws.skill_dir)), sorted(os.listdir(os.path.join(ws.skill_dir, "scripts")))
        self.assertNotEqual(os.path.normcase(ws.try_it), os.path.normcase(ws.skill_dir))
        for c in self.cmds:
            if DC.needs_ffmpeg(c) and not have_ffmpeg():
                continue
            if c.text.startswith("ffmpeg"):
                want[c.text] = 0
            if c.text.endswith('"<WORK>/demo_copy.mp4"') and c.text.startswith("python"):
                want[c.text] = 0
            self.assertIn(c.text, want, "README command with no expectation: %s" % c.text)
            code, out, argv = ws.run(c, cwd=ws.work)
            self.assertEqual(code, want[c.text], "%s\n%s" % (c.text, out))
            if "scan.py" in c.text:
                self.assertIn("RESULT:", out.splitlines()[-1])
        # what the README says the commands leave behind: files in <WORK>, and nothing new in the skill folder
        demo = os.path.join(ws.try_it, "demo")
        self.assertTrue(os.path.isdir(demo))
        names = sorted(os.listdir(demo))
        self.assertIn("04_clean.png", names)
        self.assertIn("DEMO_EXPECTED.md", names)
        doc = json.loads(read_text(os.path.join(ws.try_it, "demo_report.json")))
        self.assertEqual(doc["exit_code"], 1)
        self.assertGreater(doc["summary"]["findings"], 0)
        if have_ffmpeg():
            self.assertTrue(os.path.exists(os.path.join(ws.try_it, "demo_copy.mp4")))
            self.assertEqual(len(names), 7)
        else:
            self.assertEqual(len(names), 6)
        after = sorted(os.listdir(ws.skill_dir)), sorted(os.listdir(os.path.join(ws.skill_dir, "scripts")))
        self.assertEqual(after, before, "the README commands must not write into the skill folder")

    def test_a_command_run_inside_the_skill_folder_does_leave_files_there_so_the_snapshot_check_can_fail(self):
        # negative control for the test above (the harness, not the README): the demo command with a relative name, run with the skill
        # folder as the working folder, as the old README told the reader to do, leaves demo/ there
        ws = DC.Workspace()
        try:
            c = DC.extract("old.md", "```sh\npython scripts/make_demo.py demo --no-mp4\n```\n")[0]
            code, out, argv = ws.run(c, cwd=ws.skill_dir)
            self.assertEqual(code, 0, out)
            self.assertTrue(os.path.isdir(os.path.join(ws.skill_dir, "demo")))
        finally:
            ws.close()


class TestSkillCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = DC.Workspace()

    @classmethod
    def tearDownClass(cls):
        cls.ws.close()

    def runnable(self):
        for c in COMMANDS["SKILL.md"]:
            argv = c.argv_template()
            if argv[0] in ("python3",) and argv[1:] != ["--version"] and not DC.alias_works("python3"):
                continue
            yield c

    def test_every_skill_md_command_runs_from_another_folder(self):
        ws, ran = self.ws, 0
        for c in COMMANDS["SKILL.md"]:
            argv = c.argv_template()
            if c.windows_form and os.name != "nt":
                continue                                    # a Windows form is only run on Windows
            if argv[1:] == ["--version"] or argv[:3] == ["py", "-3", "--version"]:
                continue                                    # alias checks: see TestAliases
            if argv[0] == "ffmpeg" and not have_ffmpeg():
                continue
            code, out, real = ws.run(c)
            kind = kind_of(real)
            ran += 1
            if kind == "scan":
                self.assertIn(code, (0, 1), "%s\n%s" % (c.text, out))
                self.assertEqual(out.splitlines()[-1].split("(exit ")[-1].rstrip(")"), str(code))
                script = os.path.normpath(real[1])
                self.assertTrue(os.path.isabs(script))
                self.assertEqual(os.path.dirname(script), os.path.normpath(os.path.join(ws.skill_dir, "scripts")))
                self.assertNotEqual(os.path.normpath(ws.work), os.path.normpath(ws.skill_dir))
            else:
                self.assertEqual(code, 0, "%s\n%s" % (c.text, out))
        self.assertGreaterEqual(ran, 5)

    def test_the_relative_form_only_works_inside_the_skill_folder(self):
        # SKILL.md says a relative scripts/scan.py works only from inside the skill folder
        ws = self.ws
        p = subprocess.run([sys.executable, "scripts/scan.py", ws.demo], cwd=ws.work, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(b"RESULT:", p.stdout)
        p = subprocess.run([sys.executable, "scripts/scan.py", ws.demo], cwd=ws.skill_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 1)

    def test_exit_code_of_a_missing_python_script_is_not_a_scanner_exit_code(self):
        # SKILL.md: without a RESULT line, treat the run as exit 3. Python reports a missing script as exit 2,
        # which would read as "usage error"; either way there is no RESULT line.
        p = subprocess.run([sys.executable, "no_such_scan.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotIn(b"RESULT:", p.stdout)
        self.assertNotEqual(p.returncode, 0)


class TestAliases(unittest.TestCase):
    """The alias forms are run as written when they exist on this machine."""

    def test_python_version_forms(self):
        ran = 0
        for alias in ("python", "python3", "py -3"):
            if not DC.alias_works(alias):
                continue
            ran += 1
        self.assertGreaterEqual(ran, 1, "no python alias works")
        skill = [c.text for c in COMMANDS["SKILL.md"]]
        for form in ("python --version", "python3 --version", "py -3 --version"):
            self.assertIn(form, skill)

    @unittest.skipUnless(DC.alias_works("python3"), "python3 is not a working alias on this machine")
    def test_python3_form_of_the_scan_command_as_written(self):
        ws = DC.Workspace()
        try:
            c = [c for c in COMMANDS["SKILL.md"] if c.text.startswith("python3 ") and "scan.py" in c.text][0]
            toks = c.argv_template()
            argv = ["python3"] + [ws.subst(t) for t in toks[1:]]
            code, out, _ = ws.run(c, argv=argv)
            self.assertEqual(code, 1, out)
        finally:
            ws.close()

    @unittest.skipUnless(os.name == "nt" and DC.alias_works("py -3"), "py -3 exists on Windows with the Python launcher only")
    def test_py_launcher_form_of_the_scan_command_as_written(self):
        ws = DC.Workspace()
        try:
            c = [c for c in COMMANDS["SKILL.md"] if c.text.startswith("py -3 ") and "scan.py" in c.text][0]
            toks = c.argv_template()
            argv = ["py", "-3"] + [ws.subst(t) for t in toks[2:]]
            code, out, _ = ws.run(c, argv=argv)
            self.assertEqual(code, 1, out)
        finally:
            ws.close()


class TestReferenceCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = DC.Workspace()

    @classmethod
    def tearDownClass(cls):
        cls.ws.close()

    def test_every_command_in_the_references_runs(self):
        ws, ran = self.ws, 0
        for name, cmds in COMMANDS.items():
            if not name.startswith("references/"):
                continue
            for c in cmds:
                if DC.needs_ffmpeg(c) and not have_ffmpeg():
                    continue
                if "PIL" in c.text and not DC.pillow_available():
                    continue
                code, out, real = ws.run(c)
                kind = kind_of(real)
                ran += 1
                if kind == "scan":
                    self.assertIn(code, (0, 1), "%s: %s\n%s" % (name, c.text, out))
                else:
                    self.assertEqual(code, 0, "%s: %s\n%s" % (name, c.text, out))
        self.assertGreaterEqual(ran, 1)

    def test_dash_n_keeps_an_existing_file_but_still_exits_0(self):
        # how-to-export-clean.md and SKILL.md warn about this: a reused output name looks like a success
        if not have_ffmpeg():
            self.skipTest("ffmpeg not on PATH")
        ws = self.ws
        cmd = [c for c in COMMANDS["references/how-to-export-clean.md"] if c.text.startswith("ffmpeg") and "<IN.mp4>" in c.text][0]
        argv = ws.argv(cmd)
        first = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(first.returncode, 0)
        out_path = argv[-1]
        before = read_bytes(out_path)
        second = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(read_bytes(out_path), before)                  # the file is untouched ...
        self.assertIn(b"already exists", second.stdout)
        doc = read_text(DOCS["references/how-to-export-clean.md"]) + read_text(DOCS["SKILL.md"])
        if second.returncode == 0:                                      # ... and (ffmpeg 7.1, 8.1.1, 9.0.1) the exit code does not say so
            self.assertIn("still exit 0", doc)
            self.assertIn("exit 0", read_text(DOCS["references/how-to-export-clean.md"]))


if __name__ == "__main__":
    unittest.main()
