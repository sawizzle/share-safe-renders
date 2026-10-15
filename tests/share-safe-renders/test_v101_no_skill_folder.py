# -*- coding: utf-8 -*-
"""Tests for package release 1.0.1: documentation and tests only. scan.py and make_demo.py are the files of 1.0, byte for byte.

The release adds references/no-skill-folder.md for an agent that received the skill as TEXT and has no skill folder.
  * ScriptPinTests      scan.py and make_demo.py hash to the values of the 1.0 release, so no behaviour can change here
  * DependencyTests     the file sets in the document's table are derived from the code: what each script imports, what it
                        opens, and whether it depends on its own path or name
  * MinimalSetTests     each documented set is copied ALONE into an empty folder (with spaces in its path) and run for real
                        on synthetic renders; the report is the report of the installed package; leaving a file out fails
  * SimulatorTests      get_skill_sim.py, the helper that makes a text file shaped like a "skill as text" answer
  * SnippetTests        the snippet is taken out of the document verbatim and run against simulated answers; every file must
                        come out byte for byte (plain fences inside markdown, a last block with no final newline, a CRLF file,
                        a whole answer saved with CRLF line ends); duplicate blocks, another skill's blocks and missing
                        names are refused loudly; broken copies of the snippet must fail
  * DocumentPinTests    the new text in SKILL.md, README.md and the reference says what the code does
Every check that can only pass has a negative control. Nothing here needs ffmpeg, Pillow, listing/ or dist/; the one
listing test skips with its reason when listing/ is not part of the checkout (the public repository).
Run:  python -I -B -m unittest discover -s tests/share-safe-renders
"""
import ast
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from _base import HERE, PKG, LISTING, B, read_text
import get_skill_sim

PACKAGE = Path(PKG)
SCRIPTS = PACKAGE / "scripts"
DOC = PACKAGE / "references" / "no-skill-folder.md"
SIM_SCRIPT = Path(HERE) / "get_skill_sim.py"
SKILL_NAME = "share-safe-renders"

# The two scripts of the live 1.0 zip. 1.0.1 changes documentation and tests only, so these must not move. (Each value is
# written in two halves: the hygiene tests refuse a 64-digit hex literal in any file.)
PINNED = {
    "scan.py": ("da4e39b29fb3894dd040bb5939ea5f03" + "ae72499041d6602e6768ebd941b6f2f2", 144720),
    "make_demo.py": ("350340f308429156ea21622ed3c48a48" + "d548653a32a3cc91a15eaf3cdf973726", 26418),
}

# The description line was trigger-tested for 1.0 and must not change in 1.0.1.
DESCRIPTION_LINE = ("description: Scans renders (PNG, JPEG, MP4/MOV, ComfyUI workflow JSON) for metadata that leaks API keys, "
                    "Discord/Slack webhooks, user names in paths, e-mails, LAN IPs and GPS. Use when asked if a render is safe to "
                    "share or post. Do not use for scrubbing files, judging picture content or scanning source code.")

# The new text describes our own route only: it names no marketplace or tool, and says nothing about what the text around
# such an answer tells an agent.
WRAPPER_CLAIMS = (r"get_skill", r"Agensi", r"marketplace", r"wrapper", r"\bpip(e|ed|es|ing)\b",
                  r"the (service|tool|answer|response) (says|tells|asks|warns)")

# What the pre-submit scan of the release tooling fails a package for: a recursive delete in any file of it.
RECURSIVE_DELETE = re.compile(r"rm\s+-rf|Remove-Item\b[^\n]*-Recurse|rmtree\(|del\s+/[sfq]")

LISTING_ABSENT = ("the listing source folder (listing/share-safe-renders) is not part of this checkout; the public repository "
                  "has only packages/ and tests/")


def read(path):
    return Path(path).read_bytes().decode("ascii")


def child_env(tmp=None):
    """The environment for every child process: no colour (Python 3.14 colours argparse help when FORCE_COLOR or
    PYTHON_COLORS is set), and, when `tmp` is given, that folder as the system temp folder (-I does not hide TMP, TEMP or
    TMPDIR, and tempfile.gettempdir() reads them)."""
    env = dict(os.environ)
    for name in ("FORCE_COLOR", "PYTHON_COLORS"):
        env.pop(name, None)
    env["NO_COLOR"] = "1"
    if tmp is not None:
        for name in ("TMPDIR", "TEMP", "TMP"):
            env[name] = str(tmp)
    return env


def wrapper_claims(text):
    return [pattern for pattern in WRAPPER_CLAIMS if re.search(pattern, text, re.I)]


def mask(text):
    """A report with its per-run keyed values masked: the hash prefix and the ~label of a hashed key change every run."""
    return re.sub(r"~[0-9a-f]{8}", "~H", re.sub(r"sha256=[0-9a-f]{8}", "sha256=X", text))


def masked_json(path):
    doc = json.loads(Path(path).read_bytes().decode("utf-8"))
    for finding in doc.get("findings", []):
        finding.pop("sha256_prefix", None)
    return mask(json.dumps(doc, sort_keys=True))


# --------------------------------------------------------------------------- the table in the document

TABLE_ROW = re.compile(r"^\| (?P<task>[^|\n]+) \| (?P<run>[^|\n]+) \| (?P<files>[^|\n]+) \| (?P<size>\d+) KB \|$", re.M)


def documented_sets(text=None):
    """[(task, scripts to run, files to write, size in KB)] from the table in section 1 of the document."""
    text = read(DOC) if text is None else text
    section = text.split("## 1. ")[1].split("\n## ")[0]
    rows = []
    for match in TABLE_ROW.finditer(section):
        rows.append((match.group("task").strip(), re.findall(r"`([\w]+\.py)`", match.group("run")),
                     re.findall(r"`([\w]+\.py)`", match.group("files")), int(match.group("size"))))
    return rows


def local_imports(source, modules):
    """The local modules a Python source imports, by a walk of its syntax tree (a lazy import inside a function too)."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found & modules


def import_graph():
    modules = {path.stem for path in SCRIPTS.glob("*.py")}
    return {path.stem: local_imports(read(path), modules) - {path.stem} for path in sorted(SCRIPTS.glob("*.py"))}


def closure(script, graph):
    needed, todo = set(), [script]
    while todo:
        name = todo.pop()
        if name not in needed:
            needed.add(name)
            todo.extend(graph[name])
    return needed


def set_problems(rows, graph):
    """Rows of the table whose file list is not exactly the closure of the scripts to run."""
    problems = []
    for task, run, files, _size in rows:
        needed = set()
        for script in run:
            needed |= closure(script.replace(".py", ""), graph)
        listed = {name.replace(".py", "") for name in files}
        if needed - listed:
            problems.append("%s: missing %s" % (task, sorted(needed - listed)))
        if listed - needed:
            problems.append("%s: not needed %s" % (task, sorted(listed - needed)))
    return problems


def names_used(source):
    """Every bare name and every attribute name in a source, by a walk of its syntax tree."""
    tree = ast.parse(source)
    return ({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)})


def string_constants(source):
    return {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


# --------------------------------------------------------------------------- helpers that run things

def materialise(files, without=None):
    """Copy ONLY the listed scripts into a new empty folder whose path holds spaces (layout scripts/<file>)."""
    folder = Path(tempfile.mkdtemp(prefix="ssr test set ")) / "skill folder"
    (folder / "scripts").mkdir(parents=True)
    for name in files:
        if name != without:
            shutil.copyfile(str(SCRIPTS / name), str(folder / "scripts" / name))
    return folder


def run_script(folder, script, *args, cwd, stdin_bytes=None):
    """The command of SKILL.md: python "<SKILL_DIR>/scripts/<script>" <args>, from another folder."""
    argv = [sys.executable, str(Path(folder) / "scripts" / script)] if stdin_bytes is None else [sys.executable, "-I", "-B", "-"]
    proc = subprocess.run(argv + [str(a) for a in args], capture_output=True, cwd=str(cwd), input=stdin_bytes, timeout=300,
                          env=child_env())
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def assert_next_line_names(case, out, scan_py, demo_folder):
    """make_demo.py's last line: the scan command with the scan.py it computed, when both paths are plain enough to print."""
    import make_demo
    lines = [line for line in out.splitlines() if line.startswith("Next: ")]
    case.assertEqual(len(lines), 1, out)
    if make_demo.pasteable(scan_py) and make_demo.pasteable(demo_folder):
        case.assertIn(scan_py, lines[0])
    else:                                           # a temp folder with a character that a shell reads: no command printed
        case.assertIn("no command line is printed", lines[0])


def listing_of(folder):
    return sorted(str(p.relative_to(folder)).replace(os.sep, "/") for p in Path(folder).rglob("*") if p.is_file())


def snippet_blocks(doc_text=None):
    doc_text = read(DOC) if doc_text is None else doc_text
    return re.findall(r"^```python\n(.*?)^```$", doc_text, re.S | re.M)


def run_snippet(snippet, response, folder, names, cwd=None, tmp=None):
    """What an agent does: the program on standard input, then the response file, `new` (or, to test the refusal, any other
    second argument) and the names as arguments. `tmp`, when given, is the child's system temp folder."""
    proc = subprocess.run([sys.executable, "-I", "-B", "-", str(response), str(folder)] + list(names),
                          input=snippet.encode("ascii"), capture_output=True, cwd=None if cwd is None else str(cwd), timeout=120,
                          env=child_env(tmp))
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def wrote_counts(out):
    """{file name: characters} from the snippet's 'wrote <path> <n> characters' lines."""
    return {m.group(1).rsplit("/", 1)[-1]: int(m.group(2)) for m in re.finditer(r"^wrote (.+) (\d+) characters\r?$", out, re.M)}


def documented_counts(doc_text=None):
    """The character counts section 2 tells the agent to compare with the wrote lines."""
    section = (read(DOC) if doc_text is None else doc_text).split("## 2. ")[1].split("\n## ")[0]
    m = re.search(r"`scan\.py` is ([\d,]+) characters and `make_demo\.py` ([\d,]+)\.", section)
    return {"scan.py": int(m.group(1).replace(",", "")), "make_demo.py": int(m.group(2).replace(",", ""))} if m else {}


def shell_wrappers(doc_text=None):
    """The two documented ways to feed the snippet: {'sh': text, 'powershell': text}."""
    section = (read(DOC) if doc_text is None else doc_text).split("## 2. ")[1].split("\n## ")[0]
    sh = re.search(r"In bash or sh:\n\n```text\n(.*?)```", section, re.S)
    ps = re.search(r"In Windows PowerShell:\n\n```text\n(.*?)```", section, re.S)
    return {"sh": sh.group(1) if sh else None, "powershell": ps.group(1) if ps else None}


class Scratch:
    """A scratch folder for one test class, removed afterwards."""
    def __init__(self, test_case_class, prefix):
        self.path = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
        test_case_class.addClassCleanup(shutil.rmtree, str(self.path), True)

    def __truediv__(self, name):
        return self.path / name


def make_fixture(folder):
    """A folder of renders the existing tests already use: a PNG with a fake key, a JPEG with GPS, a PNG with nothing.
    Returns the fake key, which must never appear in any output."""
    key = B.Fake().hf()
    folder = Path(folder)
    folder.mkdir(parents=True)
    (folder / "key.png").write_bytes(B.make_png(B.t_text("Comment", "token " + key)))
    (folder / "gps.jpg").write_bytes(B.make_jpeg(app1=[b"Exif\x00\x00" + B.exif_gps_tiff()]))
    (folder / "plain.png").write_bytes(B.make_png())
    return key


# --------------------------------------------------------------------------- the scripts are the 1.0 scripts

class ScriptPinTests(unittest.TestCase):
    def test_scan_py_and_make_demo_py_are_the_files_of_the_1_0_release(self):
        self.assertEqual(sorted(p.name for p in SCRIPTS.iterdir() if p.is_file()), sorted(PINNED))
        for name, (digest, size) in PINNED.items():
            with self.subTest(script=name):
                data = (SCRIPTS / name).read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest, "1.0.1 must not change a script")

    def test_the_pin_catches_a_one_byte_edit(self):
        # negative control: the smallest possible edit, one byte, gives another hash
        data = bytearray((SCRIPTS / "scan.py").read_bytes())
        data[len(data) // 2] ^= 1
        self.assertNotEqual(hashlib.sha256(bytes(data)).hexdigest(), PINNED["scan.py"][0])
        self.assertEqual(len(PINNED["scan.py"][0]), 64)


# --------------------------------------------------------------------------- what the sets are derived from

class DependencyTests(unittest.TestCase):
    def test_the_graph_walk_sees_imports_and_ignores_the_rest(self):
        modules = {"scan", "make_demo"}
        self.assertEqual(local_imports("import scan\nimport os\nfrom make_demo import x\n", modules), {"scan", "make_demo"})
        self.assertEqual(local_imports("def f():\n    import scan\n", modules), {"scan"}, "a lazy import counts")
        self.assertEqual(local_imports("import os, sys\nx = 'scan'\n", modules), set())

    def test_neither_script_imports_the_other_or_loads_code_in_a_way_the_walk_cannot_see(self):
        self.assertEqual(import_graph(), {"make_demo": set(), "scan": set()})
        loaders = {"__import__", "exec", "eval", "compile", "importlib", "runpy", "zipimport"}
        for path in sorted(SCRIPTS.glob("*.py")):
            with self.subTest(script=path.name):
                tree = ast.parse(read(path))
                bare = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}           # re.compile is an attribute, not this
                modules = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
                self.assertEqual(sorted((bare | modules) & loaders), [])
        # negative control: the walk sees a bare loader call and an import of a loader module
        tree = ast.parse("import importlib\nexec(x)\nre.compile(y)\n")
        self.assertEqual({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} & loaders, {"exec"})

    def test_every_documented_set_is_exactly_the_closure_of_its_scripts(self):
        rows = documented_sets()
        self.assertEqual(len(rows), 2)
        self.assertEqual(set_problems(rows, import_graph()), [])
        # negative control: the check fails when an import is added or a file is listed without need
        grown = dict(import_graph(), scan={"make_demo"})
        self.assertTrue([p for p in set_problems(rows, grown) if p.startswith("Check renders") and "make_demo" in p])
        padded = [(t, r, f + ["make_demo.py"] if t.startswith("Check renders") else f, s) for t, r, f, s in rows]
        self.assertTrue([p for p in set_problems(padded, import_graph()) if "not needed" in p])

    def test_no_script_opens_a_file_of_the_skill(self):
        # what a script could open by name: the folders and files of the package. Neither script holds one as a string.
        package_names = {"references", "examples", "SKILL.md", "README.md", "scripts"} | {p.name for p in PACKAGE.rglob("*")}
        package_names -= {"scan.py", "make_demo.py"}
        for path in sorted(SCRIPTS.glob("*.py")):
            with self.subTest(script=path.name):
                self.assertEqual(string_constants(read(path)) & package_names, set())
        # negative control: the walk finds such a name
        self.assertEqual(string_constants("p = os.path.join(d, 'references', 'x.md')") & package_names, {"references"})

    def test_scan_py_uses_neither_its_own_path_nor_its_own_name_and_make_demo_py_uses_its_path_once(self):
        self.assertNotIn("__file__", names_used(read(SCRIPTS / "scan.py")))
        self.assertIsNone(re.search(r"sys\.argv|__file__|__spec__|__loader__", read(SCRIPTS / "scan.py")))
        self.assertIn('prog="scan.py"', read(SCRIPTS / "scan.py"), "the usage line names scan.py whatever the file is called")
        demo = read(SCRIPTS / "make_demo.py")
        self.assertEqual(len(re.findall(r"__file__", demo)), 1)
        self.assertIn('os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")', demo)
        # negative control: the search finds both spellings
        self.assertTrue(re.search(r"sys\.argv|__file__", "x = sys.argv[0]"))
        self.assertIn("__file__", names_used("here = __file__"))

    def test_the_stated_sizes_and_line_count_are_the_real_ones(self):
        for task, run, files, size_kb in documented_sets():
            with self.subTest(task=task):
                for name in run + files:
                    self.assertTrue((SCRIPTS / name).is_file(), name)
                self.assertEqual(set(run), set(files))
                real = sum((SCRIPTS / name).stat().st_size for name in files)
                self.assertEqual(round(real / 1000.0), size_kb, "%s: %d bytes real, %d KB stated" % (task, real, size_kb))
        scan_bytes = (SCRIPTS / "scan.py").read_bytes()
        inline = read(DOC).split("## 5. ")[1]
        self.assertIn("about %d KB (%s lines)" % (round(len(scan_bytes) / 1000.0), format(scan_bytes.count(b"\n"), ",")), inline)
        # negative control: the same document with one size one KB off no longer matches the files
        off = read(DOC).replace("| `scan.py` | 145 KB |", "| `scan.py` | 146 KB |")
        self.assertNotEqual(off, read(DOC))
        row = [r for r in documented_sets(off) if r[1] == ["scan.py"]][0]
        self.assertNotEqual(round((SCRIPTS / "scan.py").stat().st_size / 1000.0), row[3])


# --------------------------------------------------------------------------- each set, alone, for real

class MinimalSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = Scratch(cls, "ssr_test_data_")
        cls.key = make_fixture(cls.data / "renders")
        proc = subprocess.run([sys.executable, str(SCRIPTS / "scan.py"), "renders", "--json", "installed.json"],
                              capture_output=True, cwd=str(cls.data.path), timeout=300, env=child_env())
        cls.installed = (proc.returncode, proc.stdout.decode("utf-8", "replace"), masked_json(cls.data / "installed.json"))
        if cls.installed[0] != 1:
            raise AssertionError("the installed scanner did not find the fixture's key: %r" % (proc.stderr,))

    def row(self, first_script):
        rows = [r for r in documented_sets() if r[1][0] == first_script]
        self.assertEqual(len(rows), 1, first_script)
        return rows[0]

    def isolated(self, files, without=None):
        folder = materialise(files, without)
        self.addCleanup(shutil.rmtree, str(folder.parent), True)
        return folder

    def report_name(self):
        return "report_%s.json" % uuid.uuid4().hex[:8]

    def test_each_documented_set_starts_alone_in_a_folder_with_spaces_in_its_path(self):
        for task, run, files, _size in documented_sets():
            folder = self.isolated(files)
            self.assertIn(" ", str(folder))
            self.assertEqual(listing_of(folder), sorted("scripts/" + name for name in files), "nothing but the documented files")
            for script in run:
                with self.subTest(task=task, script=script):
                    code, out, err = run_script(folder, script, "--help", cwd=self.data.path)
                    self.assertEqual(code, 0, err)
                    self.assertTrue(out.startswith("usage: %s" % script), out[:80])

    def test_the_scan_set_gives_the_report_of_the_installed_package_and_writes_nothing_beside_itself(self):
        _task, _run, files, _size = self.row("scan.py")
        self.assertEqual(files, ["scan.py"])
        folder = self.isolated(files)
        report = self.report_name()
        code, out, err = run_script(folder, "scan.py", "renders", "--json", report, cwd=self.data.path)
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(mask(out), mask(self.installed[1]), "the printed report is the installed package's report")
        self.assertEqual(masked_json(self.data / report), self.installed[2], "and so is the JSON report")
        self.assertTrue(out.rstrip().endswith("(exit 1)"))
        self.assertEqual(sorted(f["class"] for f in json.loads((self.data / report).read_text("utf-8"))["findings"]
                                if "companion_of" not in f), ["G1", "K1"])
        for text in (out, (self.data / report).read_text("utf-8")):
            self.assertNotIn(self.key, text, "the report never prints the leaked text")
            self.assertNotIn(self.key[3:20], text)
        self.assertEqual(listing_of(folder), ["scripts/scan.py"], "a run writes nothing into the temporary folder")

    def test_leaving_out_any_one_file_of_a_set_makes_the_task_fail(self):
        for task, run, files, _size in documented_sets():
            for left_out in files:
                with self.subTest(task=task, left_out=left_out):
                    folder = self.isolated(files, without=left_out)
                    failed = 0
                    for script in run:
                        demo = "demo_" + uuid.uuid4().hex[:8]
                        args = [demo, "--no-mp4"] if script == "make_demo.py" else ["renders"]
                        code, out, err = run_script(folder, script, *args, cwd=self.data.path)
                        if script == left_out:
                            self.assertNotEqual(code, 0)
                            self.assertIn("can't open file", err)
                            self.assertNotIn("RESULT:", out)
                            failed += 1
                        elif script == "make_demo.py":
                            # the demo is made, but the scan.py its last line names is not there
                            self.assertEqual(code, 0, err)
                            named = os.path.join(str(folder), "scripts", "scan.py")
                            assert_next_line_names(self, out, named, os.path.join(str(self.data.path), demo))
                            self.assertFalse(os.path.exists(named))
                    self.assertGreaterEqual(failed, 1, "the task still works without " + left_out)

    def test_the_demo_set_makes_the_demo_and_names_its_own_scan_py(self):
        _task, run, files, _size = self.row("make_demo.py")
        self.assertEqual(run, ["make_demo.py", "scan.py"])
        folder = self.isolated(files)
        code, out, err = run_script(folder, "make_demo.py", "demo_set", "--no-mp4", cwd=self.data.path)
        self.assertEqual((code, err), (0, ""))
        assert_next_line_names(self, out, os.path.join(str(folder), "scripts", "scan.py"), os.path.join(str(self.data.path), "demo_set"))
        code, out, err = run_script(folder, "scan.py", "demo_set", "--json", self.report_name(), cwd=self.data.path)
        self.assertEqual((code, err), (1, ""))
        self.assertIn("RESULT: FINDINGS", out.splitlines()[-1])
        self.assertEqual(listing_of(folder), ["scripts/make_demo.py", "scripts/scan.py"])
        # make_demo.py reads nothing of the skill: the installed package writes the same files, byte for byte
        code, _out, err = run_script(PACKAGE, "make_demo.py", "demo_installed", "--no-mp4", cwd=self.data.path)
        self.assertEqual((code, err), (0, ""))
        made, installed = self.data / "demo_set", self.data / "demo_installed"
        self.assertEqual(listing_of(made), listing_of(installed))
        self.assertIn("DEMO_EXPECTED.md", listing_of(made))
        self.assertEqual(len(listing_of(made)), 6, "five demo files without the MP4, and DEMO_EXPECTED.md")
        for name in listing_of(made):
            self.assertEqual((made / name).read_bytes(), (installed / name).read_bytes(), name)

    def test_scan_py_from_standard_input_gives_the_same_report_but_make_demo_py_does_not_name_its_scan_py(self):
        # "scan.py uses neither its own path nor its own name": the same report when the program is read from standard input
        report = self.report_name()
        code, out, err = run_script(None, None, "renders", "--json", report, cwd=self.data.path,
                                    stdin_bytes=(SCRIPTS / "scan.py").read_bytes())
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(mask(out), mask(self.installed[1]))
        self.assertEqual(masked_json(self.data / report), self.installed[2])
        # negative control, and the reason the document says to run make_demo.py from its file: read from standard input,
        # its last line names a scan.py in the working folder, which is not where the script is
        code, out, err = run_script(None, None, "demo_stdin", "--no-mp4", cwd=self.data.path,
                                    stdin_bytes=(SCRIPTS / "make_demo.py").read_bytes())
        self.assertEqual(code, 0, err)
        assert_next_line_names(self, out, os.path.join(str(self.data.path), "scan.py"), os.path.join(str(self.data.path), "demo_stdin"))
        self.assertFalse((self.data / "scan.py").exists())

    def test_the_mask_hides_only_the_per_run_values(self):
        # negative control for the comparisons above: two runs differ before masking, and a changed finding is not masked away
        a = run_script(PACKAGE, "scan.py", "renders", "--json", self.report_name(), cwd=self.data.path)[1]
        b = run_script(PACKAGE, "scan.py", "renders", "--json", self.report_name(), cwd=self.data.path)[1]
        self.assertNotEqual(a, b, "the keyed hash prefixes change every run")
        self.assertEqual(mask(a), mask(b))
        self.assertNotEqual(mask(a), mask(a.replace("[HIGH] K1", "[HIGH] K2")))


# --------------------------------------------------------------------------- the simulator

def make_package(folder, files, skill="---\nname: demo\ndescription: x\n---\n\n# Demo\n"):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_bytes(skill.encode("ascii"))
    for rel, data in files.items():
        path = folder / Path(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("ascii"))
    return folder


# Files that make a simulated answer hard on purpose: plain fences inside markdown, a markdown file that ends in a fence
# line, one with no final newline, an empty file, Windows line ends, and a LAST block with no final newline.
HARD_FILES = {
    "references/fenced.md": "# Notes\n\n```python\nx = 1\n```\n\nText between.\n\n```\nplain fence\n```\n\n### Not a file header\n",
    "references/ends_in_fence.md": "Last line is a fence:\n\n```\ncode\n```\n",
    "references/no_newline.md": "no final newline and a fence at the end\n```",
    "references/empty.md": "",
    "scripts/crlf.py": b"a = 1\r\nb = 2\r\n",
    "scripts/zlast.py": "print(1)",
}
HARD_NAMES = sorted(HARD_FILES)


class SimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Scratch(cls, "ssr_test_sim_")
        cls.hard = make_package(cls.scratch / "hard" / SKILL_NAME, HARD_FILES)

    def run_cli(self, *args):
        proc = subprocess.run([sys.executable, "-I", str(SIM_SCRIPT)] + [str(a) for a in args], capture_output=True, timeout=120,
                              env=child_env())
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def test_the_command_line_writes_the_response_for_any_package_folder(self):
        for package in (PACKAGE, self.hard):
            out = self.scratch / ("sim_%s.txt" % uuid.uuid4().hex[:8])
            code, stdout, err = self.run_cli(package, out)
            with self.subTest(package=str(package)):
                self.assertEqual((code, err), (0, ""))
                self.assertIn("%d file blocks" % len(get_skill_sim.package_files(package)), stdout)
                data = out.read_bytes()
                self.assertEqual(data, get_skill_sim.build(package).encode("utf-8"))
                text = data.decode("utf-8")
                headers = re.findall(r"^### File: (.*)$", text, re.M)
                self.assertEqual(headers, ["%s/%s" % (SKILL_NAME, rel) for rel in get_skill_sim.package_files(package)])
                self.assertEqual(headers, sorted(headers), "sorted by path")
                self.assertNotIn("### File: %s/SKILL.md" % SKILL_NAME, text)
                self.assertIn((package / "SKILL.md").read_bytes().decode("ascii").rstrip("\n"), text, "SKILL.md is inline")
                self.assertFalse(text.endswith("\n"), "the last block has no final newline")
                self.assertTrue(text.endswith("\n```"))
                self.assertNotIn("\r\n", text.replace("a = 1\r\nb = 2\r\n", ""), "LF line ends outside the CRLF fixture")

    def test_every_block_is_the_file_between_two_plain_fence_lines(self):
        text = get_skill_sim.build(PACKAGE)
        parts = re.split(r"(?m)^### File: ", text)[1:]
        self.assertEqual(len(parts), len(get_skill_sim.package_files(PACKAGE)))
        self.assertEqual(len(parts), 12, "README.md, 3 examples, 6 references and 2 scripts")
        for part in parts:
            head, _, body = part.partition("\n")
            rel = head.split("/", 1)[1]
            original = (PACKAGE / Path(*rel.split("/"))).read_bytes().decode("ascii")
            self.assertEqual(body.rstrip("\n"), "\n```\n" + original + "\n```", rel)

    def test_the_real_package_gives_the_snippet_a_hard_job_and_the_wording_is_neutral(self):
        # the markdown files of the package contain fences of their own, so a parser that trusts the first closing fence
        # cuts them short; and scan.py is the LAST block, with no newline after its closing fence
        text = get_skill_sim.build(PACKAGE)
        inner = [rel for rel in get_skill_sim.package_files(PACKAGE) if rel.endswith(".md")
                 and "\n```" in (PACKAGE / Path(*rel.split("/"))).read_bytes().decode("ascii")]
        self.assertGreaterEqual(len(inner), 4, inner)
        self.assertEqual(re.findall(r"(?m)^### File: (\S+)$", text)[-1], SKILL_NAME + "/scripts/scan.py")
        self.assertEqual(wrapper_claims(get_skill_sim.HEADER + get_skill_sim.MIDDLE), [])
        self.assertTrue(wrapper_claims("the answer tells you to call get_skill"), "negative control")

    def test_the_command_line_refuses_bad_arguments(self):
        out = self.scratch / "never_written.txt"
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual(self.run_cli(PACKAGE)[0], 2)
        self.assertEqual(self.run_cli(self.scratch.path, out)[0], 2, "a folder without SKILL.md")
        code, _stdout, err = self.run_cli(self.hard, self.hard / "inside.txt")
        self.assertEqual(code, 2)
        self.assertIn("must not be inside", err)
        self.assertFalse(out.exists())
        self.assertFalse((self.hard / "inside.txt").exists())


# --------------------------------------------------------------------------- the snippet in the document

# Breakages an agent could write (or a later edit could introduce). Each replaces one line of the snippet.
FENCE_LINE = 'block = re.fullmatch(r"\\s*(\\x60{3,})[^\\n]*\\n(.*)\\n\\1\\s*", body, re.S)'
SNIPPET_MUTATIONS = {
    "stop at the first closing fence": (FENCE_LINE, 'block = re.match(r"\\s*(\\x60{3,})[^\\n]*\\n(.*?)\\n\\1", body, re.S)'),
    "need a newline after the last fence": (FENCE_LINE, 'block = re.fullmatch(r"\\s*(\\x60{3,})[^\\n]*\\n(.*)\\n\\1\\n\\s*", body, re.S)'),
    "keep the newline in front of the closing fence": (FENCE_LINE, 'block = re.fullmatch(r"\\s*(\\x60{3,})[^\\n]*\\n(.*\\n)\\1\\s*", body, re.S)'),
    "read the response with universal newlines (a CRLF file changes)": (
        'text = open(response, encoding="utf-8", newline="").read()', 'text = open(response, encoding="utf-8").read()'),
    "drop the repair of an answer saved with CRLF line ends": ('    text = text.replace("\\r\\n", "\\n")', '    pass'),
}
# The refusals and the output guard. Each is tested on its own, because a snippet without it still extracts the files of a
# normal answer.
GUARDS = {
    "usage": ('if len(sys.argv) < 4 or sys.argv[2] != "new":\n'
              '    sys.exit("usage: python -I -B - RESPONSE new NAME...  (the second argument is always new)")\n'),
    "no blocks": 'if not parts:\n    sys.exit("no file blocks in this file: it is not a saved response with the skill as text")\n',
    "another skill": ('    if skill != "share-safe-renders":\n'
                      '        sys.exit("a block that is not from share-safe-renders: " + ascii(head[:80]))\n'),
    "duplicate": '    if name in files:\n        sys.exit("two blocks for: " + ascii(name))\n',
    "missing": 'if missing:\n    sys.exit("no complete block for: " + ", ".join(missing))\n',
    "output": 'sys.stdout.reconfigure(errors="backslashreplace")\n',
}
# 1.0.1 takes no folder: it always makes a fresh one. This pair of edits puts a folder argument back (the behaviour an audit
# found unsafe: an existing folder can be another user's, or hold links); the folder tests must catch it.
FOLDER_ARGUMENT = (('if len(sys.argv) < 4 or sys.argv[2] != "new":', 'if len(sys.argv) < 4:'),
                   ('folder = Path(tempfile.mkdtemp(prefix="ssr_")).resolve()',
                    'folder = Path(tempfile.mkdtemp(prefix="ssr_") if sys.argv[2] == "new" else sys.argv[2]).resolve()'))


def with_folder_argument(snippet):
    for old, new in FOLDER_ARGUMENT:
        assert snippet.count(old) == 1, old
        snippet = snippet.replace(old, new)
    return snippet


def folder_of(out):
    """The folder named by the snippet's last line, or None when it printed none."""
    m = re.search(r"^skill folder: (.+?)\r?$", out, re.M)
    return Path(m.group(1)) if m else None


class SnippetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Scratch(cls, "ssr_test_snippet_")
        cls.response = cls.scratch / "response.txt"
        cls.response.write_bytes(get_skill_sim.build(PACKAGE).encode("utf-8"))
        cls.crlf_response = cls.scratch / "response_crlf.txt"
        cls.crlf_response.write_bytes(get_skill_sim.build(PACKAGE).replace("\n", "\r\n").encode("utf-8"))
        cls.hard = make_package(cls.scratch / "hard" / SKILL_NAME, HARD_FILES)
        cls.hard_response = cls.scratch / "hard_response.txt"
        cls.hard_response.write_bytes(get_skill_sim.build(cls.hard).encode("utf-8"))
        cls.other = make_package(cls.scratch / "other" / "other-skill", {"scripts/scan.py": "print(1)\n"})
        cls.snippet = snippet_blocks()[0]

    def fresh_tmp(self, parent=None):
        """An empty folder that the child process sees as its system temp folder (so every folder the snippet makes stays
        inside the scratch folder, which is removed after the class)."""
        folder = (self.scratch.path if parent is None else Path(parent)) / ("tmp_" + uuid.uuid4().hex[:8])
        folder.mkdir(parents=True)
        return folder

    def snip(self, snippet, response, names, tmp=None, folder="new", cwd=None):
        """Run a snippet with `new` (or another second argument); returns (code, out, err, folder it printed, temp folder)."""
        tmp = self.fresh_tmp() if tmp is None else tmp
        code, out, err = run_snippet(snippet, response, folder, names, cwd=cwd, tmp=tmp)
        return code, out, err, folder_of(out), tmp

    def nest(self):
        return self.scratch / ("nest_" + self._testMethodName)

    def all_package_names(self):
        return [rel for rel in get_skill_sim.package_files(PACKAGE) if rel.startswith(("scripts/", "references/", "examples/"))]

    def extraction_problems(self, snippet):
        """Run a snippet against the simulated answers; what is wrong with the result, or [] when it is right."""
        problems = []
        wanted = [(self.response, PACKAGE, self.all_package_names()),
                  (self.crlf_response, PACKAGE, ["scripts/scan.py", "scripts/make_demo.py", "references/reading-the-report.md"]),
                  (self.hard_response, self.hard, HARD_NAMES)]
        for response, package, names in wanted:
            code, _out, err, folder, _tmp = self.snip(snippet, response, names)
            if code != 0 or folder is None:
                problems.append("%s: exit %d %s" % (response.name, code, err.strip().splitlines()[-1:]))
                continue
            for name in names:
                made, original = folder / Path(*name.split("/")), package / Path(*name.split("/"))
                if not made.is_file() or made.read_bytes() != original.read_bytes():
                    problems.append("%s: %s differs from the original" % (response.name, name))
        return problems

    def test_the_document_has_one_snippet_and_it_is_plain_stdlib_python(self):
        blocks = snippet_blocks()
        self.assertEqual(len(blocks), 1)
        snippet = blocks[0]
        snippet.encode("ascii")
        self.assertLessEqual(len(snippet.splitlines()), 45, "short enough to paste")
        for character, why in (("'", "an apostrophe ends a quoted here-document or here-string"),
                               ("$", "a dollar sign is expanded by sh and by a double-quoted PowerShell here-string"),
                               ("`", "a backtick is a command substitution in sh and an escape character in PowerShell"),
                               ("\t", "tabs are lost when pasting")):
            self.assertNotIn(character, snippet, why)
        tree = ast.parse(snippet, feature_version=(3, 9))     # the grammar of the oldest Python the skill supports
        for path in (SIM_SCRIPT, Path(__file__).resolve()):
            ast.parse(read(path), feature_version=(3, 9))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported, {"re", "sys", "tempfile", "pathlib"})
        self.assertEqual(len(snippet_blocks("```python\nx\n```\n\n```python\ny\n```\n")), 2, "negative control")

    def test_the_snippet_gives_every_file_back_byte_for_byte(self):
        # every file of scripts/, references/ and examples/ from the real package's simulated answer, three files from the
        # same answer saved with CRLF line ends, and the hard cases
        self.assertEqual(self.extraction_problems(self.snippet), [])

    def test_the_documented_sets_come_back_and_the_extracted_scanner_reports_like_the_package(self):
        data = self.scratch / "data_sets"
        key = make_fixture(data / "renders")
        installed = run_script(PACKAGE, "scan.py", "renders", cwd=data)
        for task, _run, files, _size in documented_sets():
            with self.subTest(task=task):
                code, out, err, folder, _tmp = self.snip(self.snippet, self.response, ["scripts/" + name for name in files])
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(listing_of(folder), sorted("scripts/" + name for name in files))
                for name in files:
                    self.assertEqual((folder / "scripts" / name).read_bytes(), (SCRIPTS / name).read_bytes())
                self.assertEqual(wrote_counts(out), {name: documented_counts()[name] for name in files},
                                 "the wrote lines carry the counts section 2 tells the agent to check")
                code, scan_out, err = run_script(folder, "scan.py", "renders", cwd=data)
                self.assertEqual((code, err), (1, ""))
                self.assertNotIn(key, scan_out)
                self.assertEqual(mask(scan_out), mask(installed[1]))

    def test_the_documented_shell_wrappers_feed_the_snippet(self):
        wrappers = shell_wrappers()
        self.assertTrue(wrappers["sh"].startswith('python -I -B - "<RESPONSE>" new scripts/scan.py <<' + "'EOF'\n<the snippet>\nEOF"))
        self.assertTrue(wrappers["powershell"].startswith("@'\n<the snippet>\n'@ | python -I -B - \"<RESPONSE>\" new scripts/scan.py"))
        body = self.snippet.rstrip("\n")
        exe = Path(sys.executable).as_posix()
        runs = {}
        if os.name == "nt" and shutil.which("powershell"):              # Windows PowerShell 5.1
            script = wrappers["powershell"].replace("<the snippet>", body).replace("<RESPONSE>", self.response.as_posix())
            script = script.replace("| python ", '| & "%s" ' % exe) + "\nexit $LASTEXITCODE"
            runs["powershell"] = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                  base64.b64encode(script.encode("utf-16-le")).decode("ascii")]
        if shutil.which("sh"):                                           # sh on POSIX, and Git Bash's sh on Windows
            script = wrappers["sh"].replace("<the snippet>", body).replace("<RESPONSE>", self.response.as_posix())
            runs["sh"] = ["sh", "-c", script.replace("python -I", '"%s" -I' % exe, 1)]
        if not runs:
            self.skipTest("neither sh nor Windows PowerShell is on this machine")
        for shell, argv in runs.items():
            with self.subTest(shell=shell):
                tmp = self.fresh_tmp()
                proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=300, env=child_env(tmp))
                out = proc.stdout.decode("utf-8", "replace")
                self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
                folder = folder_of(out)
                self.assertEqual(folder.parent, tmp.resolve())
                self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), (SCRIPTS / "scan.py").read_bytes())
                self.assertEqual(listing_of(folder), ["scripts/scan.py"])

    def test_the_snippet_prints_what_it_wrote_and_names_the_folder(self):
        names = ["scripts/make_demo.py", "scripts/scan.py"]
        code, out, err, folder, tmp = self.snip(self.snippet, self.response, names)
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(len(lines), 3)
        for line, name in zip(lines, names):
            self.assertEqual(line, "wrote %s %d characters" % ((folder / Path(*name.split("/"))).as_posix(),
                                                              (PACKAGE / Path(*name.split("/"))).stat().st_size))
        self.assertEqual(lines[-1], "skill folder: " + folder.as_posix())
        self.assertTrue(folder.is_absolute())
        self.assertEqual(listing_of(folder), sorted(names), "nothing but what was asked for")
        self.assertEqual(wrote_counts(out), documented_counts())
        self.assertEqual(documented_counts(), {name: (SCRIPTS / name).stat().st_size for name in ("scan.py", "make_demo.py")})

    def test_a_response_with_a_fenced_footer_after_the_last_block_fails_the_documented_count_check(self):
        footer = self.scratch / "footer.txt"
        footer.write_bytes(self.response.read_bytes() + b"\n\nA footer with code:\n```\nx\n```\n")
        code, out, err, folder, _tmp = self.snip(self.snippet, footer, ["scripts/scan.py"])
        self.assertEqual((code, err), (0, ""), "the snippet cannot tell a footer from the file")
        self.assertNotEqual(wrote_counts(out)["scan.py"], documented_counts()["scan.py"], "the count check catches it")
        self.assertNotEqual((folder / "scripts" / "scan.py").read_bytes(), (SCRIPTS / "scan.py").read_bytes())

    def test_every_run_makes_a_fresh_private_folder_in_the_temp_folder(self):
        tmp = self.fresh_tmp()
        code, out, err, first, _tmp = self.snip(self.snippet, self.response, ["scripts/scan.py"], tmp=tmp)
        self.assertEqual((code, err), (0, ""))
        code, out, err, second, _tmp = self.snip(self.snippet, self.response, ["scripts/make_demo.py"], tmp=tmp)
        self.assertEqual((code, err), (0, ""))
        self.assertNotEqual(first, second, "a second run with new gives a different fresh folder")
        for folder in (first, second):
            self.assertTrue(folder.name.startswith("ssr_"))
            self.assertEqual(folder.parent, tmp.resolve(), "directly in the temp folder")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700, "only the user can open it")
        self.assertEqual(sorted(p.name for p in tmp.iterdir()), sorted([first.name, second.name]))
        self.assertEqual(listing_of(first), ["scripts/scan.py"], "the second run leaves the first folder alone")
        self.assertEqual(listing_of(second), ["scripts/make_demo.py"])
        # and without a test temp folder it is the real system temp folder
        code, out, err = run_snippet(self.snippet, self.response, "new", ["scripts/scan.py"])
        self.assertEqual((code, err), (0, ""))
        real = folder_of(out)
        self.addCleanup(shutil.rmtree, str(real), True)
        self.assertEqual(real.parent, Path(tempfile.gettempdir()).resolve())

    def test_any_second_argument_other_than_new_is_refused_and_nothing_is_written(self):
        tmp = self.fresh_tmp()
        project = self.scratch / "project"                       # the user's project, with a file named like a skill file
        (project / "scripts").mkdir(parents=True)
        (project / "scripts" / "scan.py").write_bytes(b"# the user's own file\n")
        earlier = tmp / "ssr_earlier"                            # a folder named like the snippet's own, in the temp folder
        (earlier / "scripts").mkdir(parents=True)
        (earlier / "scripts" / "scan.py").write_bytes(b"older copy\n")
        for second in (str(project), str(earlier), ".", "NEW", "new/", "-", str(tmp / "ssr_missing"), str(tmp)):
            code, out, err, folder, _tmp = self.snip(self.snippet, self.response, ["scripts/scan.py"], tmp=tmp, folder=second,
                                                     cwd=project)
            with self.subTest(second=second):
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("usage: python -I -B - RESPONSE new NAME...  (the second argument is always new)", err)
        self.assertEqual((project / "scripts" / "scan.py").read_bytes(), b"# the user's own file\n")
        self.assertEqual(listing_of(project), ["scripts/scan.py"])
        self.assertEqual(listing_of(tmp), ["ssr_earlier/scripts/scan.py"], "no folder made, nothing written")
        self.assertEqual((earlier / "scripts" / "scan.py").read_bytes(), b"older copy\n")
        # negative control: a snippet that takes a folder argument again writes into the user's project and over the older copy
        broken = with_folder_argument(self.snippet)
        for target in (project, earlier):
            code, _out, err, _folder, _tmp = self.snip(broken, self.response, ["scripts/scan.py"], tmp=tmp, folder=str(target))
            self.assertEqual((code, err), (0, ""))
            self.assertEqual((target / "scripts" / "scan.py").read_bytes(), (SCRIPTS / "scan.py").read_bytes())

    def test_a_path_the_console_cannot_print_does_not_stop_the_snippet_half_way(self):
        # stdout that cannot encode a character of the folder path (as a Windows console code page cannot): every file is
        # written first, and the lines are printed with the character escaped instead of a crash
        ascii_stdout = "import io, sys\nsys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=\"ascii\")\n"
        names = ["scripts/scan.py", "scripts/make_demo.py"]
        tmp = self.fresh_tmp(self.scratch / ("pa" + chr(0x141) + "h"))
        code, out, err, _folder, _tmp = self.snip(ascii_stdout + self.snippet, self.response, names, tmp=tmp)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("\\u0141", out.splitlines()[-1], "the character is escaped, not a crash")
        made = [p for p in tmp.iterdir()]
        self.assertEqual(len(made), 1)
        self.assertEqual(listing_of(made[0]), sorted(names))
        # negative control: without the guard the first print fails, after the files are written
        tmp = self.fresh_tmp(self.scratch / ("pa" + chr(0x141) + "h"))
        code, out, err, _folder, _tmp = self.snip(ascii_stdout + self.snippet.replace(GUARDS["output"], ""), self.response, names, tmp=tmp)
        self.assertNotEqual(code, 0)
        self.assertIn("UnicodeEncodeError", err)
        made = [p for p in tmp.iterdir()]
        self.assertEqual(len(made), 1)
        self.assertEqual(listing_of(made[0]), sorted(names), "all files are written before anything is printed")

    def test_the_last_block_has_no_final_newline_and_is_still_read(self):
        text = self.response.read_bytes()
        self.assertFalse(text.endswith(b"\n"))
        self.assertEqual(re.findall(rb"(?m)^### File: (\S+)$", text)[-1], (SKILL_NAME + "/scripts/scan.py").encode())
        code, _out, err, folder, _tmp = self.snip(self.snippet, self.response, ["scripts/scan.py"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), (SCRIPTS / "scan.py").read_bytes())
        # negative control: a pattern that needs a newline after the closing fence misses exactly this block
        old, new = SNIPPET_MUTATIONS["need a newline after the last fence"]
        broken = self.snippet.replace(old, new)
        self.assertNotEqual(broken, self.snippet)
        code, _out, err, _folder, _tmp = self.snip(broken, self.response, ["scripts/scan.py"])
        self.assertNotEqual(code, 0)
        self.assertIn("no complete block for: scripts/scan.py", err)

    def test_markdown_files_with_plain_fences_come_out_whole(self):
        for rel in ("references/how-to-export-clean.md", "references/no-skill-folder.md", "README.md"):
            self.assertIn("\n```\n", read(PACKAGE / Path(*rel.split("/"))), rel + " has a plain fence of its own")
        for rel in ("references/fenced.md", "references/ends_in_fence.md", "references/no_newline.md", "references/empty.md"):
            code, _out, err, folder, _tmp = self.snip(self.snippet, self.hard_response, [rel])
            with self.subTest(file=rel):
                self.assertEqual((code, err), (0, ""))
                self.assertEqual((folder / Path(*rel.split("/"))).read_bytes(), (self.hard / Path(*rel.split("/"))).read_bytes())
        # negative control: a pattern that stops at the first closing fence cuts a file short
        old, new = SNIPPET_MUTATIONS["stop at the first closing fence"]
        _code, _out, _err, folder, _tmp = self.snip(self.snippet.replace(old, new), self.hard_response, ["references/fenced.md"])
        self.assertNotEqual((folder / "references" / "fenced.md").read_bytes(), (self.hard / "references" / "fenced.md").read_bytes())

    def test_a_crlf_file_survives_and_an_answer_saved_with_crlf_line_ends_is_read_back(self):
        code, _out, err, folder, _tmp = self.snip(self.snippet, self.hard_response, ["scripts/crlf.py"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual((folder / "scripts" / "crlf.py").read_bytes(), b"a = 1\r\nb = 2\r\n")
        # the whole answer saved with CRLF line ends: the files come back with the plain line ends of the package
        self.assertIn(b"\r\n### File: ", self.crlf_response.read_bytes())
        for rel in self.all_package_names():
            self.assertNotIn(b"\r", (PACKAGE / Path(*rel.split("/"))).read_bytes(), rel + ": the package uses plain line ends")
        code, _out, err, folder, _tmp = self.snip(self.snippet, self.crlf_response, ["scripts/scan.py"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), (SCRIPTS / "scan.py").read_bytes())
        # negative control: without the repair the scanner comes out with CR characters in it
        old, new = SNIPPET_MUTATIONS["drop the repair of an answer saved with CRLF line ends"]
        broken = self.snippet.replace(old, new)
        self.assertNotEqual(broken, self.snippet)
        _code, _out, _err, folder, _tmp = self.snip(broken, self.crlf_response, ["scripts/scan.py"])
        self.assertIn(b"\r", (folder / "scripts" / "scan.py").read_bytes())

    def test_a_missing_name_writes_nothing_and_fails_loudly(self):
        code, out, err, folder, tmp = self.snip(self.snippet, self.response, ["scripts/scan.py", "scripts/not_in_the_skill.py"])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("no complete block for: scripts/not_in_the_skill.py", err)
        self.assertEqual(list(tmp.iterdir()), [], "no folder is made, so no half-written set")
        # negative control: with the check taken away a folder IS made and the first name written before the failure
        broken = self.snippet.replace(GUARDS["missing"], "")
        self.assertNotEqual(broken, self.snippet)
        code, _out, _err, _folder, tmp = self.snip(broken, self.response, ["scripts/scan.py", "scripts/not_in_the_skill.py"])
        self.assertNotEqual(code, 0)
        made = list(tmp.iterdir())
        self.assertEqual(len(made), 1)
        self.assertTrue((made[0] / "scripts" / "scan.py").exists())

    def test_a_file_with_no_blocks_and_a_short_command_line_are_refused_with_a_clear_reason(self):
        escaped = self.scratch / "escaped.txt"                 # an answer saved as one JSON string: no line starts a block
        escaped.write_bytes(json.dumps({"text": self.response.read_bytes().decode("utf-8")}).encode("ascii"))
        code, out, err, _folder, tmp = self.snip(self.snippet, escaped, ["scripts/scan.py"])
        self.assertNotEqual(code, 0)
        self.assertIn("no file blocks in this file", err)
        self.assertEqual(list(tmp.iterdir()), [])
        for args in ([], [str(self.response)], [str(self.response), "new"]):
            proc = subprocess.run([sys.executable, "-I", "-B", "-"] + args, input=self.snippet.encode("ascii"),
                                  capture_output=True, timeout=120, env=child_env(tmp))
            with self.subTest(args=len(args)):
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(b"usage: python -I -B - RESPONSE new NAME...", proc.stderr)
                self.assertNotIn(b"Traceback", proc.stderr)
        self.assertEqual(list(tmp.iterdir()), [])
        # a missing or unreadable response file: a Python error message, not a stated reason, and nothing written
        utf16 = self.scratch / "utf16.txt"
        utf16.write_bytes(self.response.read_bytes().decode("utf-8").encode("utf-16"))
        for label, response in (("missing", self.scratch / "no_such_response.txt"), ("a folder", self.scratch / "hard"),
                                ("not UTF-8", utf16)):
            code, out, err, _folder, tmp = self.snip(self.snippet, response, ["scripts/scan.py"])
            with self.subTest(response=label):
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("Traceback", err)
                self.assertRegex(err, r"(FileNotFoundError|IsADirectoryError|PermissionError|UnicodeDecodeError)")
                self.assertEqual(list(tmp.iterdir()), [], "nothing written")
        # negative control: without the check the answer is reported as cut off, which sends the agent the wrong way
        _code, _out, err, _folder, _tmp = self.snip(self.snippet.replace(GUARDS["no blocks"], ""), escaped, ["scripts/scan.py"])
        self.assertIn("no complete block for", err)

    def test_two_blocks_with_the_same_name_are_refused(self):
        text = self.response.read_bytes().decode("utf-8")
        twice = self.scratch / "twice.txt"
        extra = "\n\n### File: %s/scripts/scan.py\n\n```\nprint(1)\n```" % SKILL_NAME
        twice.write_bytes((text + extra).encode("utf-8"))
        code, out, err, _folder, tmp = self.snip(self.snippet, twice, ["scripts/scan.py"])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("two blocks for: ", err)
        self.assertIn("scripts/scan.py", err)
        self.assertEqual(list(tmp.iterdir()), [])
        # negative control: without the check the LAST block wins, and that is a one-line stand-in, not the scanner
        broken = self.snippet.replace(GUARDS["duplicate"], "")
        self.assertNotEqual(broken, self.snippet)
        code, _out, _err, folder, _tmp = self.snip(broken, twice, ["scripts/scan.py"])
        self.assertEqual(code, 0)
        self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), b"print(1)")

    def test_blocks_of_another_skill_are_refused(self):
        other_response = self.scratch / "other_response.txt"
        other_response.write_bytes(get_skill_sim.build(self.other).encode("utf-8"))
        mixed = self.scratch / "mixed_response.txt"
        mixed.write_bytes(self.response.read_bytes() + b"\n\n" + other_response.read_bytes())
        for response in (other_response, mixed):
            code, out, err, _folder, tmp = self.snip(self.snippet, response, ["scripts/scan.py"])
            with self.subTest(response=response.name):
                self.assertNotEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("a block that is not from share-safe-renders: ", err)
                self.assertIn("other-skill/scripts/scan.py", err)
                self.assertEqual(list(tmp.iterdir()), [])
        # negative control: without the check the other skill's file is written in place of the scanner
        broken = self.snippet.replace(GUARDS["another skill"], "")
        self.assertNotEqual(broken, self.snippet)
        code, _out, _err, folder, _tmp = self.snip(broken, other_response, ["scripts/scan.py"])
        self.assertEqual(code, 0)
        self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), b"print(1)\n")

    def test_a_cut_off_response_is_refused_for_the_cut_block_only(self):
        text = self.response.read_bytes()
        cut = self.scratch / "cut_response.txt"
        cut.write_bytes(text[:text.rindex(b"\n```")])      # the closing fence of the last block (scan.py) is gone
        code, _out, err, _folder, tmp = self.snip(self.snippet, cut, ["scripts/scan.py"])
        self.assertNotEqual(code, 0)
        self.assertIn("no complete block for: scripts/scan.py", err)
        self.assertEqual(list(tmp.iterdir()), [])
        code, _out, err, _folder, _tmp = self.snip(self.snippet, cut, ["scripts/make_demo.py"])
        self.assertEqual((code, err), (0, ""), "the blocks before the cut are complete")

    def test_names_that_are_not_files_of_the_skill_are_refused(self):
        bad_names = ("../outside.py", "scripts/../../outside.py", "scripts/a/../x.py", "scripts/a/x.py", "/absolute.py",
                     "/scripts/scan.py", "C:/scripts/scan.py", "scripts\\scan.py", "scripts/scan.py/", "scripts//scan.py",
                     "scripts/", "scripts", "scripts/..", "README.md", "SKILL.md", "tests/test_x.py", "scripts/.hidden",
                     "scripts/a b.py", "scripts/x.py;rm")
        for bad in bad_names:
            code, _out, err, _folder, tmp = self.snip(self.snippet, self.response, ["scripts/scan.py", bad],
                                                      tmp=self.fresh_tmp(self.nest() / "level"))
            with self.subTest(name=bad):
                self.assertNotEqual(code, 0)
                self.assertIn("not a file name of the skill", err)
                self.assertEqual(list(tmp.iterdir()), [])
        self.assertEqual(listing_of(self.nest()), [], "nothing was written, not even one or two levels up")
        # negative control: a name pattern that allows a slash in the file part lets a parent step through
        loose = self.snippet.replace("[A-Za-z0-9_][A-Za-z0-9_.-]*", "[A-Za-z0-9_][A-Za-z0-9_./-]*")
        self.assertNotEqual(loose, self.snippet)
        code, _out, err, _folder, _tmp = self.snip(loose, self.response, ["scripts/a/../x.py"])
        self.assertNotIn("not a file name of the skill", err)

    def test_the_header_path_in_the_response_cannot_choose_where_a_file_goes(self):
        hostile = self.scratch / "hostile.txt"
        hostile.write_bytes(("### File: %s/../../escaped.py\n\n```\nprint(1)\n```\n\n### File: %s/scripts/ok.py\n\n```\nprint(2)\n```"
                             % (SKILL_NAME, SKILL_NAME)).encode("ascii"))
        tmp = self.fresh_tmp(self.nest() / "level")
        code, _out, err, folder, _tmp = self.snip(self.snippet, hostile, ["scripts/ok.py"], tmp=tmp)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(listing_of(folder), ["scripts/ok.py"])
        self.assertEqual(listing_of(self.nest()), ["level/%s/%s/scripts/ok.py" % (tmp.name, folder.name)], "nothing one or two levels up")

    def test_broken_snippets_fail_the_extraction_check(self):
        # negative control for extraction_problems itself: every mutation must be reported as a problem
        self.assertEqual(self.extraction_problems(self.snippet), [])
        for label, (old, new) in SNIPPET_MUTATIONS.items():
            with self.subTest(mutation=label):
                self.assertEqual(self.snippet.count(old), 1, "the mutation targets a line that is in the snippet")
                self.assertTrue(self.extraction_problems(self.snippet.replace(old, new)), label)
        for label, guard in GUARDS.items():
            self.assertEqual(self.snippet.count(guard), 1, label)
        with_folder_argument(self.snippet)                      # its two targets are in the snippet, once each


# --------------------------------------------------------------------------- the words in the package

def package_texts():
    return {str(p.relative_to(PACKAGE)).replace(os.sep, "/"): read(p) for p in sorted(PACKAGE.rglob("*")) if p.is_file()}


def skill_section():
    return read(PACKAGE / "SKILL.md").split("## If there is no skill folder\n")[1].split("\n## ")[0]


def readme_install():
    return read(PACKAGE / "README.md").split("## Install")[1].split("## Requirements")[0]


def run_table(tests_readme):
    """The rows [machine, ffmpeg, python, pillow, pyyaml, skipped] of "Where the suite has been run" in the tests README."""
    part = tests_readme.split("| Machine |", 1)[1]
    rows = []
    for line in part.splitlines()[2:]:
        if not line.startswith("|"):
            break
        rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows


def stated_skips(tests_readme):
    """(Windows 3.14.6 skips, Linux minimum, Linux maximum) from the run table: the figures the READMEs and the listing quote."""
    rows = run_table(tests_readme)
    windows = {int(r[5]) for r in rows if r[0] == "Windows 11" and r[2] == "3.14.6"}
    linux = [int(r[5]) for r in rows if r[0].startswith(("Ubuntu", "Debian")) and r[3] != "none"]
    assert len(windows) == 1 and linux, (windows, linux)
    return windows.pop(), min(linux), max(linux)


PUBLIC_SENTENCE = re.compile(r"runs skip (\d+) more tests: (\d+) listing tests \((\d+) in `test_listing\.py`, (\d+) in `test_audit_docs\.py`, "
                             r"(\d+) in `test_v101_no_skill_folder\.py`\) and (\d+) precheck tests .*? and (\d+) private-term tests")
PUBLIC_MEASURED = re.compile(r"skipped (\d+) \((\d+) \+ (\d+)\), Ubuntu 22\.04 as root (\d+) \((\d+) \+ (\d+)\) and Ubuntu 26\.04 as root "
                             r"(\d+) \((\d+) \+ (\d+)\)")


def public_figures(tests_readme):
    """What the tests README says a public checkout skips more, by kind: {'total', 'listing', 'listing_test_listing', ...}."""
    flat = " ".join(tests_readme.split())
    m = PUBLIC_SENTENCE.search(flat)
    if not m:
        return None
    keys = ("total", "listing", "listing_test_listing", "listing_test_audit_docs", "listing_test_v101", "precheck", "private")
    return dict(zip(keys, (int(x) for x in m.groups())))


class DocumentPinTests(unittest.TestCase):
    def test_the_frontmatter_is_unchanged(self):
        lines = read(PACKAGE / "SKILL.md").split("\n")
        self.assertEqual(lines[:4], ["---", "name: share-safe-renders", DESCRIPTION_LINE, "---"],
                         "the description was trigger-tested and must not change")

    def test_skill_md_has_a_short_section_before_the_first_command(self):
        skill = read(PACKAGE / "SKILL.md")
        section = skill_section()
        lines = [line for line in section.strip("\n").split("\n") if line.strip()]
        self.assertGreaterEqual(len(lines), 4)
        self.assertLessEqual(len(lines), 8, "6 to 10 lines with the heading and the blank lines")
        flat = " ".join(section.split())
        for needle in ("references/no-skill-folder.md", "fresh temporary folder in the system temp folder", "`scripts/scan.py` alone",
                       "Write only the files it lists", "treat the temporary folder as `<SKILL_DIR>`", "delete the temporary folder",
                       "do not cut a script out of the text any other way or retype it"):
            self.assertIn(needle, flat)
        self.assertNotIn("outside the user's project", flat)
        start = skill.index("## If there is no skill folder")
        first_command = min(skill.index("`python --version`"), skill.index("```sh"))
        self.assertLess(start, first_command)
        self.assertLess(start, skill.index("## When to use"))
        self.assertGreater(start, skill.index("its report never prints the leaked text"))
        self.assertIn("- `<SKILL_DIR>` is the folder that contains this SKILL.md (with no skill folder: the temporary folder, see above);",
                      skill)
        files = skill.split("## Files in this skill")[1]
        self.assertIn("`no-skill-folder.md` for an agent that has the skill only as text", files)

    def test_the_reference_is_short_and_states_what_the_snippet_does(self):
        text = read(DOC)
        flat = " ".join(text.split())
        self.assertLessEqual(len(text.splitlines()), 110)
        self.assertLessEqual(len(text), 10000)
        self.assertEqual(re.findall(r"^## (.*)$", text, re.M), ["1. The files each task needs", "2. Write the files", "3. Run",
                                                                "4. Delete", "5. The response came back inline"])
        self.assertTrue(text.startswith("# No skill folder"))
        for needle in ("If the folder exists, ignore this file", "into a fresh folder in the system temp folder",
                       "Each set below was run alone in an otherwise empty folder",
                       "Run `make_demo.py` from its file, not from standard input",
                       "follows \"Names in commands\" in `SKILL.md`", "pass every name the task needs in one run",
                       "If a `### File: ` line of the response comes right after a Windows line end (CR LF), every CR LF in the "
                       "response is turned into a plain line end first",
                       "when the second argument is not `new`, when a name you asked for is not a file name of the skill, when the "
                       "file holds no blocks, when a name you asked for has no complete block, when two blocks have the same name, "
                       "or when a block belongs to another skill",
                       "A missing or unreadable response file gives a Python error message instead of a stated reason, and nothing "
                       "is written",
                       "a new folder that `tempfile.mkdtemp` makes in the system temp folder",
                       "on Linux and other POSIX systems only your user can open it", "and into no other folder",
                       "If the system has no usable temp folder, Python can fall back to the current folder: check that the printed "
                       "path is not inside the user's project, and if it is, delete that folder and stop",
                       "Any other count means a block was not cut where it should be: delete the folder (section 4), tell the user, and stop"):
            self.assertIn(needle, flat)
        for gone in ("outside the user's project", "it writes nowhere else", "a folder it printed before", "a folder this snippet made"):
            self.assertNotIn(gone, flat, "the folder argument is gone, and so is every sentence about it")
        # the CR LF repair condition in the snippet is the one the sentence states
        self.assertIn('if "\\r\\n### File: " in text:', snippet_blocks()[0])

    def test_every_size_in_the_reference_is_the_real_size(self):
        scan_kb = round((SCRIPTS / "scan.py").stat().st_size / 1000.0)
        both_kb = round(((SCRIPTS / "scan.py").stat().st_size + (SCRIPTS / "make_demo.py").stat().st_size) / 1000.0)
        sizes = [int(n) for n in re.findall(r"(\d+) KB", read(DOC))]
        self.assertEqual(sorted(sizes), sorted([scan_kb, both_kb, scan_kb]), "the table's two rows and section 5")
        self.assertEqual(read(DOC).count("%d KB" % scan_kb), 2)
        # negative control: either mention one KB off is caught
        for i in range(2):
            parts = read(DOC).split("%d KB" % scan_kb)
            off = ("%d KB" % scan_kb).join(parts[:i + 1]) + ("%d KB" % (scan_kb + 1)) + ("%d KB" % scan_kb).join(parts[i + 1:])
            self.assertNotEqual(sorted(int(n) for n in re.findall(r"(\d+) KB", off)), sorted([scan_kb, both_kb, scan_kb]))

    def test_the_run_section_says_the_report_is_unchanged(self):
        run = " ".join(read(DOC).split("## 3. Run")[1].split("\n## ")[0].split())
        for needle in ("The report is the same as from an installed folder", "`scan.py` uses neither its own path nor its own name",
                       "it never prints the leaked text, only the class, the place, the length and a keyed hash",
                       "Do not put `<REPORT>`", "prints `usage: scan.py` when the file is complete"):
            self.assertIn(needle, run)
        commands = re.findall(r"^```sh\n(.*?)```", read(DOC), re.S | re.M)
        self.assertEqual(commands, ['python "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"\n'])
        self.assertIn(commands[0].strip(), read(PACKAGE / "SKILL.md"), "the same command as step 2 of SKILL.md")
        self.assertIn('python -I -B - "<RESPONSE>" new scripts/scan.py', read(DOC))
        self.assertIn("that folder is `<SKILL_DIR>` for the rest of the task", read(DOC))

    def test_the_delete_step_matches_the_prefix_the_snippet_uses_and_names_no_command(self):
        delete = " ".join(read(DOC).split("## 4. Delete")[1].split("\n## ")[0].split())
        for needle in ("starts with `ssr_`", "with the path in double quotes", "delete nothing else",
                       "compare the path with the `skill folder:` line", "the re-scan of the copies in step 5 included",
                       "run the snippet again with `new` and the names that step needs: it makes another folder",
                       "you delete every folder it printed at the end"):
            self.assertIn(needle, delete)
        self.assertIn('tempfile.mkdtemp(prefix="ssr_")', snippet_blocks()[0])
        for name, content in package_texts().items():
            with self.subTest(file=name):
                self.assertEqual(RECURSIVE_DELETE.findall(content), [])
        for sample in ("rm -rf /tmp/x", "Remove-Item -Path x -Recurse -Force", "shutil.rmtree(folder)", "del /s /q x"):
            self.assertTrue(RECURSIVE_DELETE.findall(sample), sample)
        self.assertEqual(RECURSIVE_DELETE.findall("delete the folder with your shell's own command"), [])

    def test_the_known_issue_gives_a_way_to_find_the_folder_that_works_and_asks_for_a_check_that_it_is_gone(self):
        delete = read(DOC).split("## 4. Delete")[1].split("\n## ")[0]
        issue = " ".join([p for p in delete.split("\n\n") if p.startswith("Known issue:")][0].split())
        for needle in ("Known issue: on Windows, a user name with accented letters can make the printed path unreadable to an agent "
                       "that reads the output as UTF-8", "The scan commands then exit 2 and nothing wrong runs, but the folder stays behind",
                       "or ask the user to delete that `ssr_` folder in their system temp folder",
                       "After any delete, check that the folder is really gone: a delete command can exit 0 on a path it could not "
                       "read, so a zero exit code proves nothing"):
            self.assertIn(needle, issue)
        commands = re.findall(r"`(python -I -c [^`]+)`", issue)
        self.assertEqual(commands, ['python -I -c "import tempfile; print(ascii(tempfile.gettempdir()))"'])
        self.assertNotIn("print(tempfile.gettempdir())", issue, "the plain print shows the same unreadable path, or fails")
        # what the command prints for a temp folder with accented letters is plain ASCII that gives the real path back, even on a
        # console that can encode nothing else; the plain print it replaced fails there
        tmp = Path(tempfile.mkdtemp(prefix="ssr_test_issue_")).resolve() / ("Jos" + chr(0xE9) + " " + chr(0x141) + "ukasz")
        self.addCleanup(shutil.rmtree, str(tmp.parent), True)
        tmp.mkdir()
        ascii_stdout = "import io, sys; sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=\"ascii\"); "
        code = commands[0].split('-c "', 1)[1].rstrip('"')
        for program, works in ((code, True), (code.replace("print(ascii(tempfile.gettempdir()))", "print(tempfile.gettempdir())"), False)):
            proc = subprocess.run([sys.executable, "-I", "-c", ascii_stdout + program], capture_output=True, timeout=60, env=child_env(tmp))
            with self.subTest(program=program):
                if works:
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    printed = proc.stdout.decode("ascii").strip()
                    self.assertIn("\\xe9", printed)
                    self.assertEqual(Path(ast.literal_eval(printed)).resolve(), tmp)
                else:
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn(b"UnicodeEncodeError", proc.stderr)

    def test_the_inline_case_tells_the_user_instead_of_copying_by_hand(self):
        inline = " ".join(read(DOC).split("## 5. The response came back inline")[1].split())
        for needle in ("nothing was saved to a file", "cannot sensibly be copied by hand", "do not try", "Tell the user",
                       "nothing has been scanned", "ask them to install it", "to have the response saved to a file",
                       "Do not fall back to reading the files yourself"):
            self.assertIn(needle, inline)

    def test_readme_gives_the_folder_less_route(self):
        readme = read(PACKAGE / "README.md")
        install = readme_install()
        flat = " ".join(install.split())
        for needle in ("references/no-skill-folder.md", "nothing was installed", "a fresh folder in the system temp folder",
                       "the one file a scan needs (`scripts/scan.py`)", "deletes that folder afterwards"):
            self.assertIn(needle, flat)
        self.assertNotIn("outside your project", flat)
        added = [line for line in install.split("\n") if "no-skill-folder" in line or "fresh folder in the system temp folder" in line]
        self.assertEqual(len(added), 2, "the note is two lines")
        table = readme.split("## What is in the folder")[1].split("## Permissions")[0]
        self.assertIn("| `references/no-skill-folder.md` |", table)
        permissions = " ".join(readme.split("## Permissions")[1].split("## Source and tests")[0].split())
        self.assertIn("the agent itself (not the scripts) reads the saved response file, writes the scripts a task needs", permissions)

    def test_no_package_line_starts_like_a_block_separator(self):
        separator = re.compile(r"^### File: ", re.M)
        for name, text in package_texts().items():
            with self.subTest(file=name):
                self.assertIsNone(separator.search(text))
        self.assertIsNotNone(separator.search("text\n### File: share-safe-renders/x.py\n"))
        self.assertIsNone(separator.search("the line `### File: x` is quoted in the middle of a line"))

    def test_the_new_text_makes_no_claim_about_a_marketplace_answer(self):
        for label, text in (("reference", read(DOC)), ("SKILL.md section", skill_section()), ("README install", readme_install())):
            with self.subTest(text=label):
                self.assertEqual(wrapper_claims(text), [])
        self.assertTrue(wrapper_claims("the marketplace tells you to pipe it"), "negative control")
        self.assertEqual(wrapper_claims("write the files into a temporary folder and delete it afterwards"), [])

    def test_the_tests_readme_documents_the_new_module_and_the_simulator(self):
        text = " ".join(read(Path(HERE) / "README.md").split())
        self.assertIn("`test_v101_no_skill_folder.py`", text)
        self.assertIn("python -I tests/share-safe-renders/get_skill_sim.py packages/share-safe-renders out.txt", text)
        self.assertIn("scan.py and make_demo.py are the files of 1.0, byte for byte", text)

    def test_the_public_checkout_skip_figures_are_the_measured_ones(self):
        # The READMEs say how many more tests skip in a checkout of the public repository (no listing/, no tools/, no private
        # deny-list file). Measure it: copy packages/ and tests/ into an empty folder and run the four modules that read those
        # files there. The run inside the copy reaches this test again; the environment variable stops it from recursing.
        if os.environ.get("SSR_NESTED_PUBLIC_RUN") == "1":
            return
        tests_readme = read(Path(HERE) / "README.md")
        stated = public_figures(tests_readme)
        self.assertIsNotNone(stated, "the tests README no longer states the public-checkout figures in the form this test reads")
        work = Path(tempfile.mkdtemp(prefix="ssr_test_public_"))
        self.addCleanup(shutil.rmtree, str(work), True)
        shutil.copytree(str(PACKAGE), str(work / "packages" / SKILL_NAME), ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(HERE, str(work / "tests" / SKILL_NAME),
                        ignore=shutil.ignore_patterns("__pycache__", "_private_denylist.json"))
        modules = ("test_listing", "test_audit_docs", "test_package_hygiene", "test_v101_no_skill_folder")
        env = dict(child_env(), SSR_NESTED_PUBLIC_RUN="1")
        log = ""
        for module in modules:
            proc = subprocess.run([sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", "tests/" + SKILL_NAME, "-p",
                                   module + ".py", "-v"], cwd=str(work), capture_output=True, timeout=600, env=env)
            log += proc.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace")[-2000:])
        measured = {}
        for m in re.finditer(r"^\w+ \((\w+)\.[\w.]+\)(?:\n.*?)? \.\.\. skipped '(.*)'$", log, re.M):
            module, reason = m.group(1), m.group(2)
            kind = ("listing" if "listing" in reason else "precheck" if "agensi_precheck" in reason else
                    "private" if "deny-list" in reason else "other")
            measured[(module, kind)] = measured.get((module, kind), 0) + 1
        got = {"listing_test_listing": measured.get(("test_listing", "listing"), 0),
               "listing_test_audit_docs": measured.get(("test_audit_docs", "listing"), 0),
               "listing_test_v101": measured.get(("test_v101_no_skill_folder", "listing"), 0),
               "precheck": sum(n for (_m, k), n in measured.items() if k == "precheck"),
               "private": sum(n for (_m, k), n in measured.items() if k == "private")}
        got["listing"] = got["listing_test_listing"] + got["listing_test_audit_docs"] + got["listing_test_v101"]
        got["total"] = got["listing"] + got["precheck"] + got["private"]
        self.assertEqual(stated, got, "the tests README's public-checkout figures are not the measured ones")
        flat = " ".join(tests_readme.split())
        self.assertIn("(%d tests skip without those two," % (got["listing"] + got["precheck"]), flat)
        self.assertIn("the maintainer-only private deny-list file (%d tests;" % got["private"], flat)
        self.assertIn("a checkout of it skips %d more tests" % got["total"], " ".join(read(PACKAGE / "README.md").split()))
        # the measured runs quoted in the tests README add the same number to the run table's own figures
        windows, _lo, _hi = stated_skips(tests_readme)
        rows = {(r[0], r[1]): int(r[5]) for r in run_table(tests_readme) if r[5].isdigit()}
        m = PUBLIC_MEASURED.search(flat)
        self.assertTrue(m)
        figures = [int(x) for x in m.groups()]
        for (whole, base, extra), row_base in zip((figures[0:3], figures[3:6], figures[6:9]),
                                                  (windows, rows[("Ubuntu 22.04, root", "4.4.2")], rows[("Ubuntu 26.04, root", "8.0.1")])):
            self.assertEqual((base, extra, whole), (row_base, got["total"], row_base + got["total"]))
        # negative control: the parser reads a different figure when the sentence changes
        self.assertNotEqual(public_figures(tests_readme.replace("runs skip %d more" % got["total"], "runs skip %d more" % (got["total"] - 1))),
                            got)

    def test_the_listing_source_and_the_proposal_carry_the_new_text(self):
        # last statement of the test: a skip ends the test under failfast
        if not os.path.isdir(LISTING):
            self.skipTest(LISTING_ABSENT)
        proposal = read_text(os.path.join(LISTING, "update_v1.0.1_PROPOSAL.md"))
        fields = read_text(os.path.join(LISTING, "listing_fields.md"))
        n = unittest.TestLoader().discover(HERE).countTestCases()
        new_text = "\n".join(re.findall(r"^New:\n((?:>.*\n?)+)", proposal, re.M))
        self.assertIn("%d automated tests" % n, new_text)
        self.assertIn("The suite has %d tests." % n, new_text)
        self.assertNotIn("[[", new_text, "a placeholder never sits inside a New block that is pasted into the listing")
        # the fresh-buyer re-test is done: its result stands in its own section and the placeholder is gone
        self.assertNotIn("[[RETEST RESULT", proposal)
        retest = proposal.split("## Fresh-buyer re-test")[1].split("\n## ")[0]
        for word in ("Claude Sonnet", "Claude Haiku", "simulated answer", "failed commands"):
            self.assertIn(word, retest)
        scan_kb = round((SCRIPTS / "scan.py").stat().st_size / 1000.0)
        for label, text in (("New blocks", new_text), ("listing_fields.md", fields)):
            with self.subTest(text=label):
                flat = " ".join(text.replace("\n> ", " ").split())
                self.assertIn("references/no-skill-folder.md", flat)
                self.assertEqual([int(x) for x in re.findall(r"scan\.py, about (\d+) KB", flat)], [scan_kb, scan_kb])
                self.assertIn("its report is the same: it never prints the leaked text", flat)
                self.assertNotIn("outside your project", flat)
                self.assertIn("fresh folder in the system temp folder", flat)
                windows, lo, hi = stated_skips(read(Path(HERE) / "README.md"))
                self.assertEqual(re.findall(r"\((\d+) of the (\d+) on Windows with Python 3\.14\.6, (\d+) to (\d+) on Linux\)", flat),
                                 [(str(windows), str(n), str(lo), str(hi))])
        stated = public_figures(read(Path(HERE) / "README.md"))
        self.assertIn("a public checkout skips %d more tests" % stated["total"], " ".join(fields.split()))
        changelog = proposal.split("## 7. Changelog for the Update dialog")[1]
        self.assertIn("1.0.1", changelog.split("\n```\n")[1].split("\n")[0])
        self.assertIn("v1.1", changelog.split("\n```\n")[1].split("\n")[0])
        self.assertIn("scan.py and make_demo.py are unchanged", changelog)
        # the new sentences describe our own route only (the listing names Agensi elsewhere, in its licence sentence)
        new_sentences = [s for s in re.split(r"(?<=\.) ", new_text) if "as text" in s or "no-skill-folder" in s]
        self.assertGreaterEqual(len(new_sentences), 4)
        self.assertEqual(wrapper_claims(" ".join(new_sentences)), [])


if __name__ == "__main__":
    unittest.main()
