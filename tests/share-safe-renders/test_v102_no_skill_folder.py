# -*- coding: utf-8 -*-
"""Tests for package release 1.0.2: documentation and tests only. scan.py and make_demo.py are the files of 1.0, byte for byte.

Release 1.0.1 added references/no-skill-folder.md for an agent that has the skill only as TEXT (no skill folder). Its snippet
cut the scripts out of one answer that held every file as '### File:' blocks. Since 2026-10-15 such an answer gives SKILL.md
and an index of the files, and each file is loaded on its own (a header line, a blank line, the exact file); a long result is
saved by the agent's host as plain text (P1) or as JSON (P2), a short one comes back in the conversation. 1.0.2 rewrites the
note for that shape around a self-verifying program (an extractor with three modes, new, put and check, that writes and accepts
only files with the published length and SHA-256), and makes the documented scan command `python -I -B ...`.
  * ScriptPinTests      scan.py and make_demo.py hash to the values of the 1.0 release, so no behaviour can change here
  * DependencyTests     the file sets in the note's table are derived from the code (imports, files opened, own path or name)
  * ProgramPinTests     the program in the note is the program generated from the package scripts (gen_table.py and
                        extract_core.py, kept here), so its table pins the real files; the readable hash table, the size, the
                        paste rules and the message texts the note quotes are pinned too
  * SimulatorTests      get_skill_sim.py: the first answer, the file answers, P1, P2, the old shape and the stand-in tool
  * RouteTests          each documented set written through the new route (put from P1 and P2 saved files, an inline result
                        through a scratch file, a hand-written file then check) into a fresh folder of an empty temp folder,
                        and run from there; the report is the installed package's; leaving out a file, a wrong byte, a planted
                        file and a foreign layout are refused
  * ExtractorTests      the program, verbatim from the note, against wrong and hostile input (core tests specialised)
  * PosixGuardTests     on POSIX: hard links, modes open to other users, a temp folder (or a folder above it, two levels up
                        too) that others can write or that another user owns, sticky or not (the owner cases as root), and the
                        modes of what the program makes with umask 0; the audits of 1.0.2 found these pinned only by the size pin
  * PlantedModuleTests  every `python ... -c` command of the package, run from a working folder holding planted modules
                        (the audit of 1.0.2 found the report-folder helper and the Pillow commands importing from there)
  * WorkingFolderTests  where the commands run: cmd starts a python.bat, py.bat, ffmpeg.bat or ffprobe.bat planted in the
                        working folder (the second audit of 1.0.2, B3); every documented form is run through cmd from such a
                        folder (the control), after the documented set command, from a trusted folder, and through PowerShell
                        and bash; and the docs say so
  * ShellTests          the note's bash heredoc and PowerShell here-string forms, run as written
  * RealAnswerTests     real saved answers, when the caller names them (SSR_REAL_P1, SSR_REAL_OLD_SHAPE); skipped otherwise
  * DocumentPinTests    the new text in SKILL.md, README.md and the note says what the code does
  * SuiteHygieneTests   no test here makes a temp folder whose name starts like the route's folders (ssr_)
Every check that can only pass has a negative control. Nothing here needs ffmpeg, Pillow, listing/ or dist/; the one listing
test skips with its reason when listing/ is not part of the checkout (the public repository).
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
import time
import unicodedata
import unittest
import uuid
import warnings
from pathlib import Path

from _base import HERE, PKG, LISTING, B, read_text
import gen_table
import get_skill_sim

PACKAGE = Path(PKG)
SCRIPTS = PACKAGE / "scripts"
DOC = PACKAGE / "references" / "no-skill-folder.md"
SIM_SCRIPT = Path(HERE) / "get_skill_sim.py"
TEMPLATE = Path(HERE) / "extract_core.py"
SKILL_NAME = "share-safe-renders"
DISPLAY = "Share-Safe Renders"
PREFIX = "ssr_"
POSIX = os.name != "nt"

# The two scripts of the live 1.0 zip. 1.0.1 and 1.0.2 change documentation and tests only, so these must not move. (Each value
# is written in two halves: the hygiene tests refuse a 64-digit hex literal in any file.)
PINNED = {
    "scan.py": ("da4e39b29fb3894dd040bb5939ea5f03" + "ae72499041d6602e6768ebd941b6f2f2", 144720),
    "make_demo.py": ("350340f308429156ea21622ed3c48a48" + "d548653a32a3cc91a15eaf3cdf973726", 26418),
}
NAMES = ["scripts/make_demo.py", "scripts/scan.py"]

# The description line was trigger-tested for 1.0 and must not change.
DESCRIPTION_LINE = ("description: Scans renders (PNG, JPEG, MP4/MOV, ComfyUI workflow JSON) for metadata that leaks API keys, "
                    "Discord/Slack webhooks, user names in paths, e-mails, LAN IPs and GPS. Use when asked if a render is safe to "
                    "share or post. Do not use for scrubbing files, judging picture content or scanning source code.")

# The new text describes our own route only: it names no marketplace or tool, and says nothing about what the text around
# such an answer tells an agent.
WRAPPER_CLAIMS = (r"get_skill", r"Agensi", r"marketplace", r"wrapper", r"\bpip(e|ed|es|ing)\b", r"in-session",
                  r"the (service|tool|answer|response) (says|tells|asks|warns)")

# What the pre-submit scan of the release tooling fails a package for: a recursive delete in any file of it.
RECURSIVE_DELETE = re.compile(r"rm\s+-rf|Remove-Item\b[^\n]*-Recurse|rmtree\(|del\s+/[sfq]")

LISTING_ABSENT = ("the listing source folder (listing/share-safe-renders) is not part of this checkout; the public repository "
                  "has only packages/ and tests/")
REAL_ABSENT = ("%s is not set: the real saved answers are not part of any checkout (the maintainer names their paths when "
               "running the suite)")


def read(path):
    return Path(path).read_bytes().decode("ascii")


def child_env(tmp=None):
    """The environment for every child process: no colour, and, when `tmp` is given, that folder as the system temp folder
    (-I does not hide TMP, TEMP or TMPDIR, and tempfile.gettempdir() reads them)."""
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


def listing_of(folder):
    """Every entry under a folder (links not followed), as relative names with forward slashes."""
    out = []
    for dirpath, dirnames, files in os.walk(str(folder)):
        for n in dirnames + files:
            out.append(os.path.relpath(os.path.join(dirpath, n), str(folder)).replace(os.sep, "/"))
    return sorted(out)


def remove_tree(path):
    """Remove a scratch tree: junctions and links are removed as links, never followed; private modes are opened first."""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass
    if os.name == "nt" and os.path.isdir(str(path)):
        for dirpath, dirnames, _files in os.walk(str(path)):
            for d in list(dirnames):
                full = os.path.join(dirpath, d)
                if getattr(os.lstat(full), "st_file_attributes", 0) & 1024:
                    os.rmdir(full)
                    dirnames.remove(d)
    shutil.rmtree(str(path), onerror=onerror)


class Scratch:
    """A scratch folder for one test class, removed afterwards."""
    def __init__(self, test_case_class, prefix):
        self.path = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
        test_case_class.addClassCleanup(remove_tree, str(self.path))

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


# --------------------------------------------------------------------------- the note, read as an agent reads it

TABLE_ROW = re.compile(r"^\| (?P<task>[^|\n]+) \| (?P<run>[^|\n]+) \| (?P<files>[^|\n]+) \| (?P<size>\d+) KB \|$", re.M)


def section(number, text=None):
    text = read(DOC) if text is None else text
    return text.split("\n## %d. " % number)[1].split("\n## ")[0]


def note_header_example():
    """The header line that step 2 of section 3 shows as the start of a file request's result."""
    m = re.search(r"The result is a header line \(`(## File: [^`]+)`\), a blank line, and then the file\.", " ".join(section(3).split()))
    assert m, "step 2 no longer shows the header line in the form this helper reads"
    return m.group(1)


def documented_sets(text=None):
    """[(task, scripts to run, files to write without scripts/, size in KB)] from the table in section 1 of the note."""
    rows = []
    for match in TABLE_ROW.finditer(section(1, text)):
        rows.append((match.group("task").strip(), re.findall(r"`([\w]+\.py)`", match.group("run")),
                     re.findall(r"`scripts/([\w]+\.py)`", match.group("files")), int(match.group("size"))))
    return rows


def doc_program(text=None):
    blocks = re.findall(r"^```python\n(.*?)^```$", read(DOC) if text is None else text, re.S | re.M)
    assert len(blocks) == 1, len(blocks)
    return blocks[0]


def text_fences(text=None):
    return re.findall(r"^```text\n(.*?)^```$", read(DOC) if text is None else text, re.S | re.M)


def package_table():
    return gen_table.table_entries(PACKAGE, NAMES)


def generated_program(table=None):
    """The program the note must hold: the template kept here, specialised for this skill from the package scripts."""
    return gen_table.specialise(TEMPLATE.read_bytes().decode("ascii"), SKILL_NAME, PREFIX, table or package_table())


def readable_hash_table(table):
    rows = ["| File | Bytes | SHA-256 |", "| --- | --- | --- |"]
    for name in sorted(table):
        digest, size = table[name]
        rows.append("| `%s` | %s | `%s` `%s` |" % (name, format(size, ","), digest[:32], digest[32:]))
    return "\n".join(rows)


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
    tree = ast.parse(source)
    return ({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)})


def string_constants(source):
    return {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


# --------------------------------------------------------------------------- running the program as an agent does

class Result:
    def __init__(self, code, out, err):
        self.code, self.out, self.err = code, out, err

    def folder(self):
        m = re.search(r"^OK folder: (.+)$", self.out, re.M)
        return Path(m.group(1)) if m else None

    def __repr__(self):
        return "Result(code=%r, out=%r, err=%r)" % (self.code, self.out[-500:], self.err[-500:])


def run_program(args, tmp, cwd, program=None, prefix=""):
    """The program on standard input, the mode and its arguments on the command line, `tmp` as the system temp folder."""
    proc = subprocess.run([sys.executable, "-I", "-B", "-"] + [str(a) for a in args],
                          input=(prefix + (doc_program() if program is None else program)).encode("ascii"),
                          capture_output=True, cwd=str(cwd), timeout=300, env=child_env(tmp))
    norm = lambda b: b.decode("utf-8", "replace").replace("\r\n", "\n")
    return Result(proc.returncode, norm(proc.stdout), norm(proc.stderr))


def run_script(folder, script, *args, cwd, flags=("-I", "-B"), stdin_bytes=None):
    """The command of SKILL.md: python -I -B "<SKILL_DIR>/scripts/<script>" <args>, from another folder."""
    if stdin_bytes is None:
        argv = [sys.executable] + list(flags) + [str(Path(folder) / "scripts" / script)]
    else:
        argv = [sys.executable, "-I", "-B", "-"]
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
    else:
        case.assertIn("no command line is printed", lines[0])


class Agent(unittest.TestCase):
    """A test case with a scratch root, a neutral working folder and a fresh child temp folder per test."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = Scratch(cls, "ssrtest_route_")
        cls.work = cls.scratch / "work"
        cls.work.mkdir()

    def setUp(self):
        self.tmp = self.new_tmp()

    def new_tmp(self, parent=None, name=None):
        tmp = Path(parent or self.scratch.path) / (name or ("tmp_" + uuid.uuid4().hex[:8]))
        tmp.mkdir(parents=True)
        if POSIX:              # the folders made here are private like a real temp folder (a user's umask may be 002), and so
            folder = tmp       # are the ones made between the scratch root and it: the program checks every folder above
            while folder != self.scratch.path and self.scratch.path in folder.parents:
                os.chmod(str(folder), 0o700)
                folder = folder.parent
        return tmp

    def x(self, *args, tmp=None, cwd=None, program=None, prefix=""):
        return run_program(args, tmp or self.tmp, cwd or self.work, program=program, prefix=prefix)

    def new(self, tmp=None):
        r = self.x("new", tmp=tmp)
        self.assertEqual(r.code, 0, r)
        folder = r.folder()
        self.assertIsNotNone(folder, r)
        return folder

    def saved(self, data, suffix=".txt"):
        """A saved result in the agent's own area (not the temp folder)."""
        path = self.scratch / ("saved_" + uuid.uuid4().hex[:8]) / ("result" + suffix)
        path.parent.mkdir()
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def assertRefused(self, r, *needles):
        self.assertEqual(r.code, 1, r)
        self.assertEqual(r.out, "", r)
        self.assertTrue(r.err.startswith("REFUSED: "), r)
        self.assertNotIn("Traceback", r.err)
        for needle in needles:
            self.assertIn(needle, r.err)

    def assertExact(self, folder, names):
        self.assertEqual(listing_of(folder), sorted({"scripts"} | set(names)))
        for name in names:
            self.assertEqual((Path(folder) / name).read_bytes(), (PACKAGE / name).read_bytes(), name)

    def put_all(self, folder, names, how):
        """Write `names` into `folder` through the new route. how: 'p1', 'p2', 'scratch' (an inline result written as shown,
        header kept, then put) or 'hand' (an inline result written straight into the folder, header removed)."""
        for name in names:
            answer = get_skill_sim.file_answer(PACKAGE, name)
            if how == "hand":
                (Path(folder) / name).write_bytes(answer.split("\n\n", 1)[1].encode("utf-8"))
                continue
            data = get_skill_sim.saved_p2(answer) if how == "p2" else get_skill_sim.saved_p1(answer)
            r = self.x("put", folder, self.saved(data, ".json" if how == "p2" else ".txt"), SKILL_NAME + "/" + name,
                       tmp=Path(folder).parent)
            self.assertEqual((r.code, r.err), (0, ""), r)
            self.assertEqual(r.out, "OK %s verified (%d bytes)\n" % (name, (PACKAGE / name).stat().st_size))


# --------------------------------------------------------------------------- the scripts are the 1.0 scripts

class ScriptPinTests(unittest.TestCase):
    def test_scan_py_and_make_demo_py_are_the_files_of_the_1_0_release(self):
        self.assertEqual(sorted(p.name for p in SCRIPTS.iterdir() if p.is_file()), sorted(PINNED))
        for name, (digest, size) in PINNED.items():
            with self.subTest(script=name):
                data = (SCRIPTS / name).read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest, "1.0.2 must not change a script")

    def test_the_pin_catches_a_one_byte_edit(self):
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
                bare = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
                modules = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
                self.assertEqual(sorted((bare | modules) & loaders), [])
        tree = ast.parse("import importlib\nexec(x)\nre.compile(y)\n")
        self.assertEqual({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} & loaders, {"exec"})

    def test_every_documented_set_is_exactly_the_closure_of_its_scripts(self):
        rows = documented_sets()
        self.assertEqual(len(rows), 2)
        self.assertEqual(set_problems(rows, import_graph()), [])
        grown = dict(import_graph(), scan={"make_demo"})
        self.assertTrue([p for p in set_problems(rows, grown) if p.startswith("Check renders") and "make_demo" in p])
        padded = [(t, r, f + ["make_demo.py"] if t.startswith("Check renders") else f, s) for t, r, f, s in rows]
        self.assertTrue([p for p in set_problems(padded, import_graph()) if "not needed" in p])

    def test_every_script_of_a_set_is_in_the_programs_table_and_nothing_else_is(self):
        table = set(package_table())
        for _task, _run, files, _size in documented_sets():
            self.assertTrue({"scripts/" + f for f in files} <= table)
        self.assertEqual(table, set(NAMES), "the table holds the two scripts and nothing else")

    def test_no_script_opens_a_file_of_the_skill(self):
        package_names = {"references", "examples", "SKILL.md", "README.md", "scripts"} | {p.name for p in PACKAGE.rglob("*")}
        package_names -= {"scan.py", "make_demo.py"}
        for path in sorted(SCRIPTS.glob("*.py")):
            with self.subTest(script=path.name):
                self.assertEqual(string_constants(read(path)) & package_names, set())
        self.assertEqual(string_constants("p = os.path.join(d, 'references', 'x.md')") & package_names, {"references"})

    def test_scan_py_uses_neither_its_own_path_nor_its_own_name_and_make_demo_py_uses_its_path_once(self):
        self.assertNotIn("__file__", names_used(read(SCRIPTS / "scan.py")))
        self.assertIsNone(re.search(r"sys\.argv|__file__|__spec__|__loader__", read(SCRIPTS / "scan.py")))
        self.assertIn('prog="scan.py"', read(SCRIPTS / "scan.py"))
        demo = read(SCRIPTS / "make_demo.py")
        self.assertEqual(len(re.findall(r"__file__", demo)), 1)
        self.assertIn('os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")', demo)
        self.assertTrue(re.search(r"sys\.argv|__file__", "x = sys.argv[0]"))
        self.assertIn("__file__", names_used("here = __file__"))

    def test_the_stated_sizes_are_the_real_ones(self):
        for task, run, files, size_kb in documented_sets():
            with self.subTest(task=task):
                self.assertEqual(set(run), set(files))
                real = sum((SCRIPTS / name).stat().st_size for name in files)
                self.assertEqual(round(real / 1000.0), size_kb, "%s: %d bytes real, %d KB stated" % (task, real, size_kb))
        off = read(DOC).replace("| `scripts/scan.py` | 145 KB |", "| `scripts/scan.py` | 146 KB |")
        self.assertNotEqual(off, read(DOC))
        row = [r for r in documented_sets(off) if r[1] == ["scan.py"]][0]
        self.assertNotEqual(round((SCRIPTS / "scan.py").stat().st_size / 1000.0), row[3])

    def test_the_note_says_its_kb_are_decimal_and_gives_the_kib_figure_the_file_index_shows(self):
        # the audit of 1.0.2: the note's sizes are KB of 1,000 bytes, the file index an agent sees prints KiB with one decimal
        flat = " ".join(section(1).split())
        m = re.search(r"Size is what you load and write, in KB of 1,000 bytes \(the file index counts 1,024 bytes to a KB, so it "
                      r"shows `scripts/scan.py` as (\d+\.\d) KB\)\.", flat)
        self.assertTrue(m, "the sentence about the two kinds of KB is missing")
        self.assertEqual(m.group(1), "%.1f" % ((SCRIPTS / "scan.py").stat().st_size / 1024.0))
        self.assertIn("- `share-safe-renders/scripts/scan.py` (%s KB)" % m.group(1), get_skill_sim.first_answer(PACKAGE),
                      "the simulated index, whose KiB figure matches the measured index (141.3 KB for scan.py)")
        self.assertNotEqual("%.1f" % ((SCRIPTS / "scan.py").stat().st_size / 1000.0), m.group(1), "negative control: KB and KiB differ")


# --------------------------------------------------------------------------- the program in the note

class ProgramPinTests(unittest.TestCase):
    def test_the_program_in_the_note_is_the_one_generated_from_the_package_scripts(self):
        self.assertEqual(doc_program(), generated_program(), "regenerate the program with gen_table.py after any script edit")
        # negative control: a script edited by one byte gives another program
        table = package_table()
        data = bytearray((SCRIPTS / "scan.py").read_bytes())
        data[100] ^= 1
        edited = dict(table, **{"scripts/scan.py": (hashlib.sha256(bytes(data)).hexdigest(), len(data))})
        self.assertNotEqual(generated_program(edited), doc_program())

    def test_the_table_in_the_program_is_the_real_files_and_the_readable_table_says_the_same(self):
        table = package_table()
        self.assertEqual(sorted(table), NAMES)
        for name, (digest, size) in table.items():
            self.assertEqual((digest, size), PINNED[name.split("/")[1]])
            self.assertIn('"%s": ("%s" "%s", %d),' % (name, digest[:32], digest[32:], size), doc_program())
        self.assertEqual(section(2).count(readable_hash_table(table)), 1)
        self.assertNotIn(readable_hash_table(dict(table, **{"scripts/scan.py": ("0" * 64, 144720)})), read(DOC))

    def test_the_program_fits_the_paste_rules_and_the_budget(self):
        program = doc_program()
        self.assertEqual(gen_table.snippet_problems(program), [])
        self.assertLessEqual(len(program), gen_table.MAX_CHARS)
        self.assertEqual((program.count("\n"), len(program)), (92, 6175), "the figures quoted in the tests README")
        self.assertTrue(program.startswith("try:  # Skill file extractor."))
        # the first-line comment (the last read of 1.0.2: "is a SyntaxError, never a silent run" was not exact, a few cuts inside
        # the last line still compile): every prefix of the program is compiled, and almost none compiles
        self.assertIn("One try block: a copy cut short almost always ends in a SyntaxError or IndentationError; only the OK lines "
                      "mean success.", program.split("\n", 1)[0])
        kinds = {}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for n in range(len(program)):
                try:
                    compile(program[:n], "<cut>", "exec")
                    kinds["compiles"] = kinds.get("compiles", 0) + 1
                except SyntaxError as e:                      # IndentationError is a SyntaxError
                    kinds[type(e).__name__] = kinds.get(type(e).__name__, 0) + 1
        self.assertLessEqual(kinds.get("compiles", 0), len(program) // 100, kinds)
        self.assertLessEqual(set(kinds) - {"compiles"}, {"SyntaxError", "IndentationError"}, kinds)
        self.assertGreater(kinds.get("compiles", 0), 1, "a few cuts compile (an empty copy, cuts inside the last line): not 'never'")
        self.assertTrue(program.rstrip("\n").splitlines()[-2].startswith("except (OSError, MemoryError)"))
        self.assertTrue(gen_table.snippet_problems(program.replace("ssr_", "ssr'_", 1)), "negative control")
        ast.parse(program, feature_version=(3, 9))

    def test_the_program_reads_no_environment_variable_and_deletes_nothing(self):
        tree = ast.parse(doc_program())
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertEqual(attrs & {"environ", "getenv", "remove", "unlink", "rmdir", "rmtree", "system", "popen", "chmod"}, set())
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertEqual(imported, {"hashlib", "itertools", "json", "os", "re", "stat", "sys", "tempfile"})
        self.assertNotIn("subprocess", doc_program())

    def test_every_message_the_note_quotes_is_a_message_of_the_program(self):
        program = doc_program()
        stop = section(6)
        quoted = {
            "is not the published file (": "is not the published file (%d bytes, published %d)",
            "holds no exact copy of": "holds no exact copy of %s; file headers in it: %s. Nothing was written.",
            "the working folder is the temp folder, or no temp folder is usable:":
                "the working folder is the temp folder, or no temp folder is usable: change to another folder",
            "is not a folder that new makes": '" is not a folder that new makes"',
            "is not directly in the temp folder": '" is not directly in the temp folder"',
            "other users can replace folders in <PATH>, the temp folder or a folder above it":
                '"other users can replace folders in " + show(p) + ", the temp folder or a folder above it"',
            " holds ": '" holds " + ascii(n) + " - run scripts with -B"',
            "must hold only scripts": '" must hold only "',
            "the system refused:": "REFUSED: the system refused: %s %s",
        }
        for in_note, in_program in quoted.items():
            with self.subTest(message=in_note):
                self.assertIn(in_note, stop)
                self.assertIn(in_program, program)
        for line in ("OK folder:", "OK %s verified (%d bytes)%s", "OK %d verified files and nothing else in %s", "REFUSED: "):
            self.assertIn(line, program)
        self.assertIn("`OK <NAME> verified (<n> bytes)`", section(2))
        self.assertIn("`OK <N> verified files and nothing else in <FOLDER>`", section(2))
        self.assertIn("`OK folder: <FOLDER>`", section(2))
        self.assertNotIn("is not the published file (%d bytes, published %d)", program.replace("published %d)", "x"), "negative control")


# --------------------------------------------------------------------------- the simulator

def make_package(folder, files, skill="---\nname: demo\ndescription: a demo skill\n---\n\n# Demo Skill\n"):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "SKILL.md").write_bytes(skill.encode("ascii"))
    for rel, data in files.items():
        path = folder / Path(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("ascii"))
    return folder


# Files that make a simulated answer hard on purpose: plain fences inside markdown, a markdown file that ends in a fence line,
# one with no final newline, an empty file, Windows line ends, a file of about 40,000 characters (saved as plain text by the
# stand-in) and one of about 60,000 (saved as JSON).
HARD_FILES = {
    "references/fenced.md": "# Notes\n\n```python\nx = 1\n```\n\nText between.\n\n```\nplain fence\n```\n\n### Not a file header\n",
    "references/ends_in_fence.md": "Last line is a fence:\n\n```\ncode\n```\n",
    "references/no_newline.md": "no final newline and a fence at the end\n```",
    "references/empty.md": "",
    "scripts/crlf.py": b"a = 1\r\nb = 2\r\n",
    "scripts/mid.py": "".join("# line %05d %s\n" % (i, "m" * 20) for i in range(1300)),
    "scripts/zlast.py": "".join("# line %05d %s\n" % (i, "z" * 40) for i in range(1200)),
}


class SimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Scratch(cls, "ssrtest_sim_")
        cls.hard = make_package(cls.scratch / "hard" / "demo-skill", HARD_FILES)

    def run_cli(self, *args):
        proc = subprocess.run([sys.executable, "-I", str(SIM_SCRIPT)] + [str(a) for a in args], capture_output=True, timeout=120,
                              env=child_env())
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def fake(self, tool, *args):
        proc = subprocess.run([sys.executable, "-I", str(tool)] + list(args), capture_output=True, timeout=120, env=child_env())
        return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8")

    def test_the_first_answer_has_the_listing_skill_md_and_the_file_index(self):
        first = get_skill_sim.first_answer(PACKAGE)
        self.assertTrue(first.startswith("# %s\n" % DISPLAY))
        self.assertIn(DESCRIPTION_LINE[len("description: "):], first)
        for heading in ("## Description", "## Compatibility", "## Known Limitations", "## Permissions", "**Tags:**", "## Creator",
                        "## SKILL.md", "## Files in this skill"):
            self.assertIn(heading, first)
        self.assertIn((PACKAGE / "SKILL.md").read_bytes().decode("ascii").rstrip("\n"), first, "SKILL.md is inline")
        index = re.findall(r"^- `([^`]+)` \((\d+\.\d) KB\)$", first, re.M)
        files = get_skill_sim.package_files(PACKAGE)
        self.assertEqual(len(files), 12, "README.md, 3 examples, 6 references and 2 scripts")
        self.assertEqual(index, [("%s/%s" % (SKILL_NAME, rel), "%.1f" % ((PACKAGE / rel).stat().st_size / 1024.0)) for rel in files])
        self.assertIn(("share-safe-renders/scripts/scan.py", "141.3"), index, "the size the measured index showed for scan.py")
        self.assertTrue(first.endswith("Load a file with fake_get_skill.py --file <path> when SKILL.md tells you to."))
        self.assertIsNone(re.search(r"^#{2,3} File: ", first, re.M), "no file blocks any more")
        self.assertLess(len(first), get_skill_sim.INLINE_LIMIT, "the first answer comes back inline")

    def test_a_file_answer_is_the_header_a_blank_line_and_the_exact_file(self):
        for package in (PACKAGE, self.hard):
            for rel in get_skill_sim.package_files(package):
                answer = get_skill_sim.file_answer(package, rel)
                head, rest = answer.split("\n\n", 1)
                with self.subTest(file=rel):
                    self.assertEqual(head, "## File: %s/%s (from %s)" % (get_skill_sim.skill_name(package), rel,
                                                                         get_skill_sim.display_name(package)))
                    self.assertEqual(rest.encode("utf-8"), (package / rel).read_bytes())
                    self.assertEqual(json.loads(get_skill_sim.saved_p2(answer).decode("utf-8")), [{"type": "text", "text": answer}])
                    self.assertEqual(get_skill_sim.saved_p1(answer), answer.encode("utf-8"))
        self.assertEqual(get_skill_sim.display_name(self.hard), "Demo Skill")

    def test_the_old_shape_has_every_file_between_two_plain_fence_lines(self):
        text = get_skill_sim.old_shape(PACKAGE)
        parts = re.split(r"(?m)^### File: ", text)[1:]
        self.assertEqual(len(parts), 12)
        for part in parts:
            head, _, body = part.partition("\n")
            rel = head.split("/", 1)[1]
            self.assertEqual(body.rstrip("\n"), "\n```\n" + read(PACKAGE / rel) + "\n```", rel)
        self.assertFalse(text.endswith("\n"))
        self.assertEqual(re.findall(r"(?m)^### File: (\S+)$", text)[-1], SKILL_NAME + "/scripts/scan.py")

    def test_the_command_line_writes_the_stand_in_tool_and_the_old_shape(self):
        out = self.scratch / ("sim_" + uuid.uuid4().hex[:8])
        code, _stdout, err = self.run_cli(PACKAGE, out)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["fake_get_skill.py", "old_shape_answer.txt"])
        self.assertEqual((out / "old_shape_answer.txt").read_bytes(), get_skill_sim.old_shape(PACKAGE).encode("utf-8"))
        tool = out / "fake_get_skill.py"
        ast.parse(read(tool), feature_version=(3, 9))
        self.assertNotIn(b"def scan_file", tool.read_bytes(), "the package text is stored compressed, not readable in the tool")
        code, first, err = self.fake(tool)
        self.assertEqual((code, err, first), (0, "", get_skill_sim.first_answer(PACKAGE)))
        for arg in ("share-safe-renders/scripts/make_demo.py", "scripts/make_demo.py"):
            code, answer, err = self.fake(tool, "--file", arg)
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(answer, get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py"), "a short file comes back inline")
        code, message, err = self.fake(tool, "--file", "share-safe-renders/scripts/scan.py")
        self.assertEqual((code, err), (0, ""))
        m = re.fullmatch(r"Output too large \(\d+\.\dKB\)\. Full output saved to: (.+\.json)\n", message)
        self.assertTrue(m, message)
        saved = Path(m.group(1))
        self.assertEqual(saved.parent, out / "saved")
        self.assertEqual(json.loads(saved.read_bytes().decode("utf-8")),
                         [{"type": "text", "text": get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")}])
        code, message, err = self.fake(tool, "--file", "share-safe-renders/scripts/nope.py")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("No file share-safe-renders/scripts/nope.py in this skill", message)
        self.assertEqual(self.fake(tool, "--bad")[0], 2)

    def test_the_stand_in_saves_plain_text_between_30000_and_50000_characters(self):
        out = self.scratch / ("hard_" + uuid.uuid4().hex[:8])
        self.assertEqual(self.run_cli(self.hard, out)[0], 0)
        lengths = {rel: len(get_skill_sim.file_answer(self.hard, rel)) for rel in ("scripts/mid.py", "scripts/zlast.py")}
        self.assertTrue(30000 < lengths["scripts/mid.py"] <= 50000 < lengths["scripts/zlast.py"], lengths)
        _code, message, _ = self.fake(out / "fake_get_skill.py", "--file", "demo-skill/scripts/mid.py")
        m = re.fullmatch(r"Result \(([\d,]+) characters across ([\d,]+) lines\) is too long to show; output saved to: (.+\.txt) "
                         r"\(plain text\)\n", message)
        self.assertTrue(m, message)
        self.assertEqual(int(m.group(1).replace(",", "")), lengths["scripts/mid.py"])
        self.assertEqual(Path(m.group(3)).read_bytes(), get_skill_sim.file_answer(self.hard, "scripts/mid.py").encode("utf-8"))
        _code, message, _ = self.fake(out / "fake_get_skill.py", "--file", "demo-skill/scripts/zlast.py")
        self.assertTrue(message.startswith("Output too large ("), message)
        proc = subprocess.run([sys.executable, "-I", str(out / "fake_get_skill.py"), "--file", "demo-skill/scripts/crlf.py"],
                              capture_output=True, timeout=120, env=child_env())
        self.assertEqual(proc.stdout, b"## File: demo-skill/scripts/crlf.py (from Demo Skill)\n\na = 1\r\nb = 2\r\n")

    def test_the_command_line_refuses_bad_arguments(self):
        out = self.scratch / "never_written"
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual(self.run_cli(PACKAGE)[0], 2)
        self.assertEqual(self.run_cli(self.scratch.path, out)[0], 2, "a folder without SKILL.md")
        code, _stdout, err = self.run_cli(self.hard, self.hard / "inside")
        self.assertEqual(code, 2)
        self.assertIn("must not be inside", err)
        exists = self.scratch / "exists"
        exists.mkdir()
        code, _stdout, err = self.run_cli(self.hard, exists)
        self.assertEqual(code, 2)
        self.assertIn("must not exist yet", err)
        self.assertFalse(out.exists())
        self.assertFalse((self.hard / "inside").exists())
        self.assertEqual(list(exists.iterdir()), [])

    def test_the_simulator_copies_no_text_of_a_real_service(self):
        for text in (get_skill_sim.FIRST_TEMPLATE, get_skill_sim.FAKE_TOOL, get_skill_sim.OLD_HEADER, get_skill_sim.OLD_MIDDLE):
            self.assertEqual(wrapper_claims(text.replace("fake_get_skill.py", "").replace("get_skill_sim.py", "")), [])
        self.assertTrue(wrapper_claims("run it in-session, the answer says"), "negative control")


# --------------------------------------------------------------------------- each set, through the new route, for real

class RouteTests(Agent):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = make_fixture(cls.work / "renders")
        code, out, err = run_script(PACKAGE, "scan.py", "renders", "--json", "installed.json", cwd=cls.work)
        if code != 1:
            raise AssertionError("the installed scanner did not find the fixture's key: %r" % (err,))
        cls.installed = (code, out, masked_json(cls.work / "installed.json"))

    def row(self, first_script):
        rows = [r for r in documented_sets() if r[1][0] == first_script]
        self.assertEqual(len(rows), 1, first_script)
        return rows[0]

    def report_name(self):
        return "report_%s.json" % uuid.uuid4().hex[:8]

    def test_the_scan_set_through_every_route_gives_the_installed_report(self):
        _task, run, files, _size = self.row("scan.py")
        self.assertEqual((run, files), (["scan.py"], ["scan.py"]))
        for how in ("p1", "p2", "scratch", "hand"):
            with self.subTest(route=how):
                folder = self.new(tmp=self.new_tmp())
                self.put_all(folder, ["scripts/scan.py"], how)
                r = self.x("check", folder, "scripts/scan.py", tmp=folder.parent)
                self.assertEqual(r.out, "OK scripts/scan.py verified (144720 bytes)\nOK 1 verified files and nothing else in %s\n" % folder, r)
                self.assertExact(folder, ["scripts/scan.py"])
                report = self.report_name()
                code, out, err = run_script(folder, "scan.py", "renders", "--json", report, cwd=self.work)
                self.assertEqual((code, err), (1, ""))
                self.assertEqual(mask(out), mask(self.installed[1]), "the printed report is the installed package's report")
                self.assertEqual(masked_json(self.work / report), self.installed[2], "and so is the JSON report")
                for text in (out, (self.work / report).read_text("utf-8")):
                    self.assertNotIn(self.key, text, "the report never prints the leaked text")
                self.assertEqual(self.x("check", folder, "scripts/scan.py", tmp=folder.parent).code, 0, "a run leaves nothing behind")

    def test_the_demo_set_makes_the_demo_and_names_its_own_scan_py(self):
        _task, run, files, _size = self.row("make_demo.py")
        self.assertEqual(run, ["make_demo.py", "scan.py"])
        folder = self.new()
        self.put_all(folder, ["scripts/scan.py"], "p2")
        self.put_all(folder, ["scripts/make_demo.py"], "scratch")
        r = self.x("check", folder, *("scripts/" + f for f in files))
        self.assertTrue(r.out.endswith("OK 2 verified files and nothing else in %s\n" % folder), r)
        demo = "demo_" + uuid.uuid4().hex[:8]
        code, out, err = run_script(folder, "make_demo.py", demo, "--no-mp4", cwd=self.work)
        self.assertEqual((code, err), (0, ""))
        assert_next_line_names(self, out, os.path.join(str(folder), "scripts", "scan.py"), os.path.join(str(self.work), demo))
        code, out, err = run_script(folder, "scan.py", demo, "--json", self.report_name(), cwd=self.work)
        self.assertEqual((code, err), (1, ""))
        self.assertIn("RESULT: FINDINGS", out.splitlines()[-1])
        self.assertEqual(self.x("check", folder, "scripts/scan.py", "scripts/make_demo.py").code, 0)
        installed = "demo_installed_" + uuid.uuid4().hex[:8]
        self.assertEqual(run_script(PACKAGE, "make_demo.py", installed, "--no-mp4", cwd=self.work)[0], 0)
        self.assertEqual(listing_of(self.work / demo), listing_of(self.work / installed))
        for name in listing_of(self.work / demo):
            self.assertEqual((self.work / demo / name).read_bytes(), (self.work / installed / name).read_bytes(), name)

    def test_leaving_out_a_file_of_a_set_is_refused_by_check_and_the_task_fails(self):
        for task, _run, files, _size in documented_sets():
            for left_out in files:
                with self.subTest(task=task, left_out=left_out):
                    folder = self.new(tmp=self.new_tmp())
                    self.put_all(folder, ["scripts/" + f for f in files if f != left_out], "p1")
                    r = self.x("check", folder, *("scripts/" + f for f in files), tmp=folder.parent)
                    self.assertRefused(r, "missing: scripts/" + left_out)
                    code, _out, err = run_script(folder, left_out, "--help", cwd=self.work)
                    self.assertNotEqual(code, 0)
                    self.assertIn("can't open file", err)

    def test_a_copy_with_one_wrong_byte_is_refused_by_put_and_by_check(self):
        folder = self.new()
        answer = get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")
        wrong = answer.replace("import argparse", "import argparsf", 1)
        self.assertNotEqual(wrong, answer)
        r = self.x("put", folder, self.saved(get_skill_sim.saved_p1(wrong)), "scripts/scan.py")
        self.assertRefused(r, "holds no exact copy of scripts/scan.py", "Nothing was written")
        self.assertEqual(listing_of(folder), ["scripts"])
        (folder / "scripts" / "scan.py").write_bytes(wrong.split("\n\n", 1)[1].encode("utf-8"))
        r = self.x("check", folder, "scripts/scan.py")
        self.assertRefused(r, "scripts/scan.py is not the published file (144720 bytes, published 144720)")

    def test_a_hand_copy_with_the_usual_slips_is_refused_by_check_and_repaired_by_put(self):
        # the slips a file tool or a hand copy makes to the WHOLE file it writes (the note's step 4, and the sizes M13 prints)
        body = read(SCRIPTS / "make_demo.py")
        slips = {"windows line ends": (lambda t: t.replace("\n", "\r\n"), 26418 + body.count("\n")),
                 "no final newline": (lambda t: t[:-1], 26417),
                 "one newline too many": (lambda t: t + "\n", 26419),
                 "a byte order mark": (lambda t: "\ufeff" + t, 26421),
                 "windows line ends and no final newline": (lambda t: t.replace("\n", "\r\n")[:-2], 26416 + body.count("\n"))}
        header = "## File: share-safe-renders/scripts/make_demo.py (from Share-Safe Renders)\n\n"
        # step 4 of the note: "the header line, and the blank line after it, may each stay or go" (the audit of 1.0.2 found the
        # copy with the header line removed and the blank line kept refused)
        shown_forms = {"header line and blank line kept": header + body, "both removed": body,
                       "header line removed, blank line kept": header[-1:] + body, "header line kept, blank line removed": header[:-1] + body}
        self.assertIn("(the header line, and the blank line after it, may each stay or go)", " ".join(read(DOC).split()))
        for label, (slip, size_on_disk) in slips.items():
            with self.subTest(slip=label):
                folder = self.new(tmp=self.new_tmp())
                (folder / "scripts" / "make_demo.py").write_bytes(slip(body).encode("utf-8"))
                r = self.x("check", folder, "scripts/make_demo.py", tmp=folder.parent)
                self.assertRefused(r, "scripts/make_demo.py is not the published file (%d bytes, published 26418)" % size_on_disk)
                (folder / "scripts" / "make_demo.py").unlink()
                for form, shown in shown_forms.items():
                    r = self.x("put", folder, self.saved(slip(shown).encode("utf-8")), "scripts/make_demo.py", tmp=folder.parent)
                    self.assertEqual(r.code, 0, (form, r))
                    self.assertExact(folder, ["scripts/make_demo.py"])
                    (folder / "scripts" / "make_demo.py").unlink()
        # negative control: a copy with a changed byte is not "repaired"
        folder = self.new()
        r = self.x("put", folder, self.saved((header + body.replace("import", "imp0rt", 1)).encode("utf-8")), "scripts/make_demo.py")
        self.assertRefused(r, "holds no exact copy of scripts/make_demo.py")

    def test_the_stop_table_arithmetic_is_what_check_prints(self):
        # the row of section 6 that explains "(N bytes, published M)": every difference it names, measured with check
        row = [line for line in section(6).splitlines() if line.startswith("| `<NAME> is not the published file")]
        self.assertEqual(len(row), 1)
        row = row[0]
        self.assertIn("N minus M equal to the number of lines of the file means Windows line ends", row)
        self.assertIn("the same length means other bytes", row)
        bom = int(re.search(r"; (-?\d+) means a byte order mark", row).group(1))
        more, less = map(int, re.search(r"; (-?\d+) or (-?\d+) means one final newline too many or missing", row).groups())
        body = read(SCRIPTS / "make_demo.py")
        copies = {"crlf": body.replace("\n", "\r\n"), "bom": "﻿" + body, "more": body + "\n", "less": body[:-1],
                  "other": body.replace("import", "imp0rt", 1)}
        measured = {}
        for label, text in copies.items():
            folder = self.new(tmp=self.new_tmp())
            (folder / "scripts" / "make_demo.py").write_bytes(text.encode("utf-8"))
            r = self.x("check", folder, "scripts/make_demo.py", tmp=folder.parent)
            self.assertRefused(r, "scripts/make_demo.py is not the published file (")
            n, m = map(int, re.search(r"\((\d+) bytes, published (\d+)\)", r.err).groups())
            measured[label] = n - m
        self.assertEqual(measured["crlf"], body.count("\n"), "Windows line ends: N - M is the number of lines")
        self.assertEqual((measured["bom"], measured["more"], measured["less"], measured["other"]), (bom, more, less, 0))

    def test_a_saved_json_string_and_a_later_copy_of_the_same_file_are_read(self):
        # a JSON file that holds the result as one string, and a saved text whose first block for the file is not the file:
        # the program reads the string, and tries up to 4 headers for a name (the audit of 1.0.2 found neither tested)
        answer = get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py")
        decoy = "## File: share-safe-renders/scripts/make_demo.py (from Share-Safe Renders)\n\nprint(1)\n\n"
        cases = {"a JSON file that holds one string": json.dumps(answer).encode("ascii"),
                 "a cut copy first, the file after it": (decoy + answer).encode("utf-8"),
                 "three cut copies first": (decoy * 3 + answer).encode("utf-8")}
        for label, data in cases.items():
            with self.subTest(case=label):
                folder = self.new(tmp=self.new_tmp())
                r = self.x("put", folder, self.saved(data), "scripts/make_demo.py", tmp=folder.parent)
                self.assertEqual(r.out, "OK scripts/make_demo.py verified (26418 bytes)\n", r)
                self.assertExact(folder, ["scripts/make_demo.py"])
        folder = self.new()
        r = self.x("put", folder, self.saved((decoy * 4 + answer).encode("utf-8")), "scripts/make_demo.py")
        self.assertRefused(r, "holds no exact copy of scripts/make_demo.py")
        self.assertEqual(listing_of(folder), ["scripts"], "the limit: a fifth header for the same name is not looked at")

    def test_a_planted_file_and_a_foreign_layout_are_refused_and_nothing_is_written(self):
        # The root entries come in pairs: one that sorts before `scripts` and one that sorts after it (the third audit's A10:
        # a check that refused only a listing that sorts before ["scripts"] passed every root case that was here).
        cases = {"planted json.py": ("scripts/json.py", "holds 'scripts/json.py'"),
                 "a __pycache__": ("scripts/__pycache__/scan.cpython-314.pyc", "holds 'scripts/__pycache__' - run scripts with -B"),
                 "a references folder": ("references/reading-the-report.md", "must hold only scripts"),
                 "a file at the top": ("SKILL.md", "must hold only scripts"),
                 "a file at the top that sorts after scripts": ("x.txt", "must hold only scripts"),
                 "an empty folder at the top that sorts after scripts": ("zz/", "must hold only scripts"),
                 "a report in the folder": ("scripts/report.json", "holds 'scripts/report.json'")}
        self.assertEqual(sorted([e.split("/")[0] for e, _n in cases.values() if not e.startswith("scripts/")] + ["scripts"]),
                         ["SKILL.md", "references", "scripts", "x.txt", "zz"], "root entries on both sides of scripts")
        for label, (extra, needle) in cases.items():
            with self.subTest(case=label):
                folder = self.new(tmp=self.new_tmp())
                self.put_all(folder, ["scripts/scan.py"], "p1")
                target = folder / extra
                if extra.endswith("/"):
                    target.mkdir(0o700)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"open('CANARY', 'w')\n")
                self.assertRefused(self.x("check", folder, "scripts/scan.py", tmp=folder.parent), needle)
                saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py")))
                self.assertRefused(self.x("put", folder, saved, "scripts/make_demo.py", tmp=folder.parent), needle)
                self.assertFalse((folder / "scripts" / "make_demo.py").exists())

    def test_a_planted_module_next_to_scan_py_runs_without_minus_i_and_not_with_it(self):
        # why the documented command is `python -I -B`: without -I, Python puts the script's folder first on its search path
        folder = self.new()
        self.put_all(folder, ["scripts/scan.py"], "p1")
        marker = self.scratch / ("canary_" + uuid.uuid4().hex[:8])
        (folder / "scripts" / "json.py").write_text("open(%r, 'w').write('ran')\n" % str(marker))
        code, out, _err = run_script(folder, "scan.py", "renders", "--json", self.report_name(), cwd=self.work)
        self.assertEqual(code, 1)
        self.assertFalse(marker.exists(), "-I keeps the planted module out")
        self.assertEqual(mask(out), mask(self.installed[1]))
        run_script(folder, "scan.py", "renders", cwd=self.work, flags=())
        self.assertTrue(marker.exists(), "negative control: without -I the planted module runs")

    def test_scan_py_from_standard_input_gives_the_same_report_but_make_demo_py_does_not_name_its_scan_py(self):
        report = self.report_name()
        code, out, err = run_script(None, None, "renders", "--json", report, cwd=self.work, stdin_bytes=(SCRIPTS / "scan.py").read_bytes())
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(mask(out), mask(self.installed[1]))
        demo = "demo_stdin_" + uuid.uuid4().hex[:8]
        code, out, err = run_script(None, None, demo, "--no-mp4", cwd=self.work, stdin_bytes=(SCRIPTS / "make_demo.py").read_bytes())
        self.assertEqual(code, 0, err)
        assert_next_line_names(self, out, os.path.join(str(self.work), "scan.py"), os.path.join(str(self.work), demo))
        self.assertFalse((self.work / "scan.py").exists())

    def test_the_mask_hides_only_the_per_run_values(self):
        a = run_script(PACKAGE, "scan.py", "renders", "--json", self.report_name(), cwd=self.work)[1]
        b = run_script(PACKAGE, "scan.py", "renders", "--json", self.report_name(), cwd=self.work)[1]
        self.assertNotEqual(a, b)
        self.assertEqual(mask(a), mask(b))
        self.assertNotEqual(mask(a), mask(a.replace("[HIGH] K1", "[HIGH] K2")))


# --------------------------------------------------------------------------- the program against wrong and hostile input

class ExtractorTests(Agent):
    def test_new_makes_a_fresh_private_folder_every_time_and_takes_no_folder(self):
        made = [self.new() for _ in range(12)]
        self.assertEqual(len(set(made)), 12)
        for folder in made:
            self.assertRegex(folder.name, r"\Assr_[a-z0-9_]{8}\Z")
            self.assertEqual(folder.parent.resolve(), self.tmp.resolve())
            self.assertEqual(listing_of(folder), ["scripts"])
            if POSIX:
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((folder / "scripts").stat().st_mode), 0o700)
        before = listing_of(self.tmp)
        project = self.scratch / ("project_" + uuid.uuid4().hex[:6])
        (project / "scripts").mkdir(parents=True)
        for extra in ([str(project)], [str(made[0])], ["."], [str(self.tmp)], ["new"]):
            r = self.x("new", *extra)
            with self.subTest(extra=extra):
                self.assertEqual((r.code, r.out), (2, ""), r)
                self.assertIn("usage: python -I -B - new | put FOLDER SAVED NAME... | check FOLDER [NAME...]", r.err)
        for mode in ("NEW", "new/", " new", "--help", ""):
            self.assertEqual(self.x(mode).code, 2, mode)
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        for args in (["put", made[0], saved], ["put", made[0]], ["put"], ["check"]):
            r = self.x(*args)
            with self.subTest(args=[args[0], len(args)]):
                self.assertEqual((r.code, r.out), (2, ""), r)
                self.assertIn("usage: python -I -B - new | put FOLDER SAVED NAME...", r.err)
        self.assertEqual(listing_of(self.tmp), before, "no folder made, nothing written")
        self.assertEqual(listing_of(project), ["scripts"])

    def test_a_folder_that_new_did_not_make_is_refused(self):
        project = self.scratch / ("project_" + uuid.uuid4().hex[:6])
        (project / "scripts").mkdir(parents=True)
        earlier = self.tmp / "ssr_earlier"                          # the 1.0.1 snippet's kind of name: not 8 characters
        (earlier / "scripts").mkdir(parents=True)
        nested = self.tmp / "sub" / "ssr_abcdefgh"
        (nested / "scripts").mkdir(parents=True)
        if POSIX:                                                   # private like new's, so the parent test is what refuses it
            os.chmod(str(nested), 0o700)
            os.chmod(str(nested / "scripts"), 0o700)
        upper = self.tmp / "ssr_ABCDEFGH"
        (upper / "scripts").mkdir(parents=True)
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        for folder, needle in ((project, "is not a folder that new makes"), (earlier, "is not a folder that new makes"),
                               (nested, "is not directly in the temp folder"), (upper, "is not a folder that new makes"),
                               (self.tmp, "is not a folder that new makes")):
            with self.subTest(folder=folder.name):
                self.assertRefused(self.x("put", folder, saved, "scripts/scan.py"), needle)
                self.assertRefused(self.x("check", folder), needle)
        for folder in (project, earlier, nested, upper):
            self.assertEqual(listing_of(folder), ["scripts"], "nothing written into a folder new did not make")

    def test_an_attackers_folder_with_a_planted_module_is_refused(self):
        # the 1.0.1 audit: a folder in the shared temp folder, named like ours, holding the published files AND a json.py
        folder = self.tmp / "ssr_plant3d0"
        (folder / "scripts").mkdir(parents=True)
        for name in NAMES:
            shutil.copyfile(str(PACKAGE / name), str(folder / name))
        (folder / "scripts" / "json.py").write_bytes(b"raise SystemExit('planted')\n")
        if POSIX:                                                   # private like new's, so the layout test is what refuses it
            os.chmod(str(folder), 0o700)
            os.chmod(str(folder / "scripts"), 0o700)
        self.assertRefused(self.x("check", folder, "scripts/scan.py"), "holds 'scripts/json.py'")
        if POSIX:
            os.chmod(str(folder), 0o777)
            (folder / "scripts" / "json.py").unlink()
            self.assertRefused(self.x("check", folder, "scripts/scan.py"), "is open to other users or has a hard link")

    def test_a_linked_scripts_folder_is_refused(self):
        folder = self.new()
        elsewhere = self.scratch / ("elsewhere_" + uuid.uuid4().hex[:6])
        elsewhere.mkdir()
        (folder / "scripts").rmdir()
        if os.name == "nt":
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(folder / "scripts"), str(elsewhere)],
                                  capture_output=True).returncode == 0
        else:
            os.symlink(str(elsewhere), str(folder / "scripts"))
            made = True
        if not made:
            self.skipTest("no junction could be made here")
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        self.assertRefused(self.x("put", folder, saved, "scripts/scan.py"), "is a link or junction")
        self.assertRefused(self.x("check", folder), "is a link or junction")
        self.assertEqual(list(elsewhere.iterdir()), [], "nothing written through the link")

    def test_names_that_are_not_files_of_the_table_are_refused_before_anything_is_read(self):
        folder = self.new()
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        for bad in ("../outside.py", "scripts/../scan.py", "scripts/a/x.py", "/scripts/scan.py", "C:/scripts/scan.py",
                    "scripts\\scan.py", "scripts/scan.py/", "scripts//scan.py", "scripts", "SKILL.md", "README.md",
                    "references/no-skill-folder.md", "scripts/SCAN.py", "scripts/scan.py ", "scripts/scan.py.",
                    "share-safe-renders/share-safe-renders/scripts/scan.py", "share-safe-renders", "video-export-qa/scripts/scan.py",
                    "scripts/json.py", "scripts/scan.py\r", "\x1b[31mscripts/scan.py"):
            with self.subTest(name=bad):
                r = self.x("put", folder, saved, bad)
                self.assertRefused(r, "not a file of share-safe-renders: ", "its files: scripts/make_demo.py, scripts/scan.py")
                self.assertTrue(all(32 <= ord(c) < 127 for c in r.err.strip()), "printed through ascii()")
        self.assertEqual(listing_of(folder), ["scripts"])

    def test_wrong_saved_results_are_refused_and_nothing_is_written(self):
        folder = self.new()
        answer = get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")
        cases = {
            "another file's result": get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py"),
            "another skill's header": answer.replace("share-safe-renders/scripts", "other-skill/scripts", 1),
            "cut short": answer[:len(answer) // 2],
            "one character changed": answer[:-30] + "X" + answer[-29:],
            "empty": "",
            "header only": answer.split("\n\n", 1)[0] + "\n\n",
            "content doubled": answer + answer.split("\n\n", 1)[1],
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                r = self.x("put", folder, self.saved(text.encode("utf-8")), "scripts/scan.py")
                self.assertRefused(r, "holds no exact copy of scripts/scan.py; file headers in it: ", "Nothing was written.")
        r = self.x("put", folder, self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py"))),
                   "scripts/make_demo.py", "scripts/scan.py")
        self.assertRefused(r, "holds no exact copy of scripts/scan.py")
        self.assertEqual(listing_of(folder), ["scripts"], "all or nothing: make_demo.py was found but nothing was written")
        self.assertRefused(self.x("put", folder, self.scratch / "no_such_saved_file.txt", "scripts/scan.py"),
                           "the system refused: FileNotFoundError ")
        self.assertRefused(self.x("put", folder, self.scratch.path, "scripts/scan.py"), "is not a file of at most 16 MB")
        self.assertRefused(self.x("put", folder, self.saved(b" " * 16000001), "scripts/scan.py"), "is not a file of at most 16 MB")
        self.assertEqual(listing_of(folder), ["scripts"])

    def test_an_existing_file_is_never_replaced(self):
        folder = self.new()
        self.put_all(folder, ["scripts/scan.py"], "p1")
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        r = self.x("put", folder, saved, "scripts/scan.py")
        self.assertEqual(r.out, "OK scripts/scan.py verified (144720 bytes) - was already there\n", r)
        (folder / "scripts" / "scan.py").write_bytes(b"print('replaced')\n")
        self.assertRefused(self.x("put", folder, saved, "scripts/scan.py"),
                           "scripts/scan.py is not the published file (18 bytes, published 144720)")
        self.assertEqual((folder / "scripts" / "scan.py").read_bytes(), b"print('replaced')\n", "refused, not overwritten")

    def test_a_file_that_appears_during_put_is_never_overwritten(self):
        # a file created in the folder after put checked it and before it writes (here: while the saved result is parsed)
        folder = self.new()
        target = folder / "scripts" / "scan.py"
        race = ("import json as _json\n_loads = _json.loads\n"
                "def _racing(*a, **k):\n    open(%r, \"wb\").write(b\"planted by another process\\n\")\n    return _loads(*a, **k)\n"
                "_json.loads = _racing\n" % str(target))
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        r = self.x("put", folder, saved, "scripts/scan.py", prefix=race)
        self.assertRefused(r, "the system refused: FileExistsError")
        self.assertEqual(target.read_bytes(), b"planted by another process\n", "exclusive create: the planted file is not replaced")
        self.assertRefused(self.x("check", folder, "scripts/scan.py"), "scripts/scan.py is not the published file")

    def test_a_write_that_loses_a_byte_is_caught_by_the_check_after_writing(self):
        folder = self.new()
        lossy = ("import builtins as _b\n_real_open = _b.open\n"
                 "class _Lossy:\n    def __init__(self, h): self.h = h\n    def __enter__(self): return self\n"
                 "    def __exit__(self, *a): return self.h.__exit__(*a)\n    def write(self, data): return self.h.write(data[:-1])\n"
                 "def _lossy_open(f, mode=\"r\", *a, **k):\n    h = _real_open(f, mode, *a, **k)\n"
                 "    return _Lossy(h) if mode == \"xb\" else h\n"
                 "_b.open = _lossy_open\n")
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        r = self.x("put", folder, saved, "scripts/scan.py", prefix=lossy)
        self.assertRefused(r, "scripts/scan.py is not the published file (144719 bytes, published 144720)")
        self.assertNotIn("OK ", r.out)

    def test_the_old_shape_is_still_understood(self):
        folder = self.new()
        old = get_skill_sim.old_shape(PACKAGE)
        r = self.x("put", folder, self.saved(old.encode("utf-8")), "scripts/scan.py", "scripts/make_demo.py")
        self.assertEqual(r.code, 0, r)
        self.assertExact(folder, NAMES)
        for label, data in (("crlf", old.replace("\n", "\r\n").encode("utf-8")), ("json", json.dumps({"text": old}).encode("ascii")),
                            ("p2", get_skill_sim.saved_p2(old))):
            with self.subTest(form=label):
                other = self.new(tmp=self.new_tmp())
                r = self.x("put", other, self.saved(data), "scripts/scan.py", "scripts/make_demo.py", tmp=other.parent)
                self.assertEqual(r.code, 0, r)
                self.assertExact(other, NAMES)

    def test_hostile_saved_files_are_refused_quickly_and_without_a_traceback(self):
        folder = self.new()
        head = "## File: share-safe-renders/scripts/scan.py (from X)\n\n"
        cases = {"200,000 header lines": (head * 200000).encode("utf-8"),
                 "a fence bomb": (head + "\x60" * 300000 + "\n").encode("utf-8") * 4,
                 "200,000 nested lists": b"[" * 200000 + b"]" * 200000,
                 "50,000 nested objects": b'{"a":' * 50000 + b"1" + b"}" * 50000,
                 "bytes that are not UTF-8": b"\xff\xfe\x80" * 100000 + head.encode("utf-8"),
                 "a NUL flood": b"\x00" * 1000000}
        for label, data in cases.items():
            with self.subTest(case=label):
                start = time.time()
                r = self.x("put", folder, self.saved(data), "scripts/scan.py")
                self.assertRefused(r, "holds no exact copy of scripts/scan.py")
                self.assertLess(time.time() - start, 60)
        self.assertEqual(listing_of(folder), ["scripts"])

    def test_hostile_text_in_a_saved_file_is_printed_escaped(self):
        folder = self.new()
        hostile = "## File: share-safe-renders/scripts/scan.py\x1b[2J\x07 (from \u00e9vil)\n\nprint(1)\n"
        r = self.x("put", folder, self.saved(hostile.encode("utf-8")), "scripts/scan.py")
        self.assertRefused(r, "file headers in it: [")
        self.assertNotIn("\x1b", r.err)
        self.assertNotIn("\x07", r.err)
        self.assertIn("\\x1b", r.err)
        self.assertTrue(all(32 <= ord(c) < 127 for c in r.err.strip()))

    def test_the_working_folder_may_not_be_the_temp_folder_and_planted_modules_there_never_run(self):
        r = self.x("new", cwd=self.tmp)
        self.assertRefused(r, "the working folder is the temp folder, or no temp folder is usable")
        self.assertEqual(listing_of(self.tmp), [])
        marker = self.scratch / ("cwd_canary_" + uuid.uuid4().hex[:8])
        planted = self.scratch / ("planted_" + uuid.uuid4().hex[:8])
        planted.mkdir()
        for module in ("json", "re", "tempfile", "hashlib", "os", "stat", "itertools"):
            (planted / (module + ".py")).write_text("open(%r, 'a').write(%r)\n" % (str(marker), module))
        folder = self.new()
        r = self.x("check", folder, cwd=planted)
        self.assertEqual(r.code, 0, r)
        self.assertFalse(marker.exists(), "-I keeps the working folder off the search path")

    def test_an_accented_temp_folder_is_printed_so_that_it_can_be_recovered(self):
        tmp = self.new_tmp(parent=self.scratch / ("Caf\u00e9 \u0141" + uuid.uuid4().hex[:4]))
        r = self.x("new", tmp=tmp)
        self.assertEqual(r.code, 0, r)
        line = r.out.strip()
        self.assertTrue(line.startswith("OK folder: '"), line)
        self.assertTrue(all(32 <= ord(c) < 127 for c in line))
        self.assertIn("\\xe9", line)
        folder = Path(ast.literal_eval(line[len("OK folder: "):]))
        self.assertEqual(folder.parent.resolve(), tmp.resolve())
        self.assertEqual(self.x("check", folder, tmp=tmp).code, 0, "the recovered path works")
        example = re.search(r"for example `('D:[^`]+')`", section(5)).group(1)
        self.assertEqual(ast.literal_eval(example), "D:\\Caf\u00e9 Temp\\ssr_ab12cd34", "the note's example reads back the same way")

    def test_a_plain_temp_folder_is_printed_as_it_is(self):
        folder = self.new()
        self.assertTrue(re.fullmatch(r"[\w .:/\\~+-]+", str(folder), re.A), "this scratch path is plain")

    def test_a_path_with_any_other_character_is_printed_quoted_and_reads_back(self):
        # the known issue of section 5 names an apostrophe, &, parentheses and $ too (the audit of 1.0.2: not only accents)
        for name in ("O'Brien", "R&D", "renders (old)", "cost$", "Café"):
            with self.subTest(name=ascii(name)):
                tmp = self.new_tmp(parent=self.scratch / ("%s %s" % (name, uuid.uuid4().hex[:4])))
                r = self.x("new", tmp=tmp)
                self.assertEqual(r.code, 0, r)
                shown = r.out.strip()[len("OK folder: "):]
                self.assertTrue(all(32 <= ord(c) < 127 for c in shown))
                self.assertEqual(shown[0], '"' if "'" in name else "'", "between double quotes when the path holds an apostrophe")
                folder = Path(ast.literal_eval(shown))
                self.assertEqual(folder.parent.resolve(), tmp.resolve())
                r = self.x("check", folder, tmp=tmp)
                self.assertEqual(r.code, 0, r)
                self.assertTrue(r.out.strip().endswith(" in " + shown), "check prints it the same way")

    def test_a_temp_folder_reached_through_a_link_is_used_by_its_real_path(self):
        # the printed folder has no link in it, and a path to it through the link is refused: so the folder a script later runs
        # from is the one whose parents the program checked
        real = self.new_tmp()
        link = self.scratch / ("tmplink_" + uuid.uuid4().hex[:8])
        if os.name == "nt":
            if subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], capture_output=True).returncode != 0:
                self.skipTest("no junction could be made here")
        else:
            os.symlink(str(real), str(link))
        r = self.x("new", tmp=link)
        self.assertEqual(r.code, 0, r)
        folder = r.folder()
        self.assertEqual(os.path.normcase(str(folder.parent)), os.path.normcase(str(real)), "printed by its real path")
        self.assertEqual(self.x("check", folder, tmp=link).code, 0)
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        for args in (("check", link / folder.name), ("put", link / folder.name, saved, "scripts/scan.py")):
            with self.subTest(mode=args[0]):
                self.assertRefused(self.x(*args, tmp=link), "is not directly in the temp folder")
        self.assertEqual(listing_of(folder), ["scripts"])

    def test_a_wrong_command_line_prints_the_usage_line_and_exits_as_the_note_says(self):
        # the second audit of 1.0.2 (E03): the exit code the note gives for a wrong command line was not pinned
        m = re.search(r"a wrong command line prints the usage line \(exit (\d)\)", " ".join(read(DOC).split()))
        self.assertTrue(m)
        usage = re.search(r'print\("(usage: [^"]+)"', doc_program()).group(1)
        folder = self.new()
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        for args in ((), ("bogus",), ("new", "extra"), ("put", folder, saved), ("check",)):
            with self.subTest(args=[str(a)[-20:] for a in args]):
                r = self.x(*args)
                self.assertEqual((r.code, r.out, r.err.strip()), (int(m.group(1)), "", usage), r)
        self.assertEqual(sorted(os.listdir(str(self.tmp))), [folder.name], "nothing made")
        self.assertEqual(listing_of(folder), ["scripts"], "nothing written")

    def test_the_folder_may_be_written_in_another_case_only_where_names_ignore_case(self):
        # the second audit of 1.0.2 (R10): the case-blind comparison of the folder's place with the temp folder was pinned only by
        # the size pin. On Windows the same folder spelt in another case is accepted; on POSIX that is another path, refused.
        folder = self.new()
        other = Path(str(folder.parent).swapcase()) / folder.name
        self.assertNotEqual(str(other), str(folder))
        r = self.x("check", other)
        if os.name == "nt":
            self.assertEqual((r.code, r.err), (0, ""), r)
            self.assertIn("OK 0 verified files and nothing else in ", r.out)
        else:
            self.assertRefused(r)
        self.assertRefused(self.x("check", Path(str(folder).upper())), "is not a folder that new makes")


# --------------------------------------------------------------------------- POSIX owners, modes and links

IS_ROOT = POSIX and hasattr(os, "geteuid") and os.geteuid() == 0
OTHER_UID = 4242                    # no account needs to exist for it: chown takes a number


@unittest.skipUnless(POSIX, "POSIX owners, modes and hard links: the program checks them only on Linux and other POSIX systems")
class PosixGuardTests(Agent):
    """The audit of 1.0.2 found these checks covered only by the program's size pin: a length-preserving edit of any of them
    passed the suite. Each case is run, and each refusal has its control (the same folder accepted once it is put back)."""

    def check_ok(self, folder, tmp=None):
        r = self.x("check", folder, "scripts/scan.py", tmp=tmp or folder.parent)
        self.assertEqual((r.code, r.err), (0, ""), r)

    def test_a_hard_link_or_a_file_or_folder_open_to_other_users_is_refused(self):
        folder = self.new()
        self.put_all(folder, ["scripts/scan.py"], "p1")
        target = folder / "scripts" / "scan.py"
        self.check_ok(folder)
        link = self.scratch / ("hardlink_" + uuid.uuid4().hex[:8])
        os.link(str(target), str(link))
        try:
            self.assertRefused(self.x("check", folder, "scripts/scan.py"), "%s is open to other users or has a hard link" % target)
            saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/make_demo.py")))
            self.assertRefused(self.x("put", folder, saved, "scripts/make_demo.py"), "has a hard link")
            self.assertFalse((folder / "scripts" / "make_demo.py").exists())
        finally:
            link.unlink()
        self.check_ok(folder)
        for path, modes in ((target, (0o666, 0o602)), (folder, (0o750, 0o705, 0o701)), (folder / "scripts", (0o710, 0o770, 0o707))):
            for mode in modes:
                with self.subTest(path=path.name, mode=oct(mode)):
                    os.chmod(str(path), mode)
                    try:
                        self.assertRefused(self.x("check", folder, "scripts/scan.py"), "%s is open to other users" % path)
                    finally:
                        os.chmod(str(path), 0o600 if path == target else 0o700)
                    self.check_ok(folder)

    def test_a_temp_folder_or_a_folder_above_it_that_others_can_write_is_refused(self):
        above = self.new_tmp()
        tmp = self.new_tmp(parent=above)
        folder = self.new(tmp=tmp)                                  # made while every folder is private
        self.put_all(folder, ["scripts/scan.py"], "p1")
        cases = ((tmp, 0o775, False), (tmp, 0o757, False), (tmp, 0o1777, True), (tmp, 0o755, True),
                 (above, 0o777, False), (above, 0o775, False), (above, 0o1777, True), (above, 0o755, True))
        for where, mode, accepted in cases:
            with self.subTest(folder="temp" if where == tmp else "above", mode=oct(mode)):
                os.chmod(str(where), mode)
                try:
                    before = sorted(os.listdir(str(tmp)))
                    made, checked = self.x("new", tmp=tmp), self.x("check", folder, "scripts/scan.py", tmp=tmp)
                    if accepted:
                        self.assertEqual((made.code, checked.code), (0, 0), (made, checked))
                        os.rmdir(str(made.folder() / "scripts"))
                        os.rmdir(str(made.folder()))
                    else:
                        for r in (made, checked):
                            self.assertRefused(r, "other users can replace folders in %s, the temp folder or a folder above it" % where)
                    self.assertEqual(sorted(os.listdir(str(tmp))), before, "nothing made")
                finally:
                    os.chmod(str(where), 0o700)
        self.check_ok(folder, tmp=tmp)
        # a folder of the path that is not a real folder (a link whose mode is 0755, as on macOS) is refused too: simulated by
        # a stand-in for os.lstat, because Linux gives every link the mode 0777, which the mode rule refuses anyway
        fake = ("import os as _o, stat as _s, sys as _y\n_lstat = _o.lstat\n"
                "def _fake(p, *a, **k):\n    st = _lstat(p, *a, **k)\n"
                "    if p == %r and _y._getframe(1).f_code.co_name == \"tempdir\":\n"
                "        return _o.stat_result((_s.S_IFLNK | 0o755,) + tuple(st)[1:])\n"
                "    return st\n"
                "_o.lstat = _fake\n" % str(above))
        self.assertRefused(self.x("check", folder, "scripts/scan.py", tmp=tmp, prefix=fake), "other users can replace folders in %s" % above)
        self.check_ok(folder, tmp=tmp)

    def test_a_folder_two_levels_above_the_temp_folder_that_others_can_write_is_refused(self):
        # the second audit of 1.0.2 (R02b): a walk that stopped at the temp folder's parent passed every test
        top = self.new_tmp()
        tmp = self.new_tmp(parent=self.new_tmp(parent=top))
        folder = self.new(tmp=tmp)
        self.put_all(folder, ["scripts/scan.py"], "p1")
        for mode, accepted in ((0o777, False), (0o757, False), (0o770, False), (0o1777, True), (0o755, True)):
            with self.subTest(mode=oct(mode)):
                os.chmod(str(top), mode)
                try:
                    before = sorted(os.listdir(str(tmp)))
                    made, checked = self.x("new", tmp=tmp), self.x("check", folder, "scripts/scan.py", tmp=tmp)
                    if accepted:
                        self.assertEqual((made.code, checked.code), (0, 0), (made, checked))
                        os.rmdir(str(made.folder() / "scripts"))
                        os.rmdir(str(made.folder()))
                    else:
                        for r in (made, checked):
                            self.assertRefused(r, "other users can replace folders in %s, the temp folder or a folder above it" % top)
                    self.assertEqual(sorted(os.listdir(str(tmp))), before, "nothing made")
                finally:
                    os.chmod(str(top), 0o700)
        self.check_ok(folder, tmp=tmp)

    def test_the_files_and_folders_it_makes_are_private_whatever_the_umask(self):
        # the second audit of 1.0.2 (R06): a written file that others can read (0644) passed every test, because check refuses
        # only a file that others can write. With umask 0 the modes are the ones the program asks for.
        umask0 = "import os as _os\n_os.umask(0)\n"
        r = self.x("new", prefix=umask0)
        self.assertEqual(r.code, 0, r)
        folder = r.folder()
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        r = self.x("put", folder, saved, "scripts/scan.py", prefix=umask0)
        self.assertEqual((r.code, r.err), (0, ""), r)
        modes = {name: oct(stat.S_IMODE(os.lstat(str(folder / name)).st_mode)) for name in (".", "scripts", "scripts/scan.py")}
        self.assertEqual(modes, {".": "0o700", "scripts": "0o700", "scripts/scan.py": "0o600"})
        probe = self.scratch / ("umask_probe_" + uuid.uuid4().hex[:8])
        subprocess.run([sys.executable, "-I", "-c", "import os, sys; os.umask(0); os.close(os.open(sys.argv[1], os.O_CREAT | os.O_WRONLY, 0o644))",
                        str(probe)], check=True, timeout=60)
        self.assertEqual(oct(stat.S_IMODE(os.lstat(str(probe)).st_mode)), "0o644", "negative control: with umask 0 a file gets the mode it asks for")

    @unittest.skipUnless(IS_ROOT, "changing the owner of a file or folder needs root")
    def test_files_folders_and_temp_folders_of_another_user_are_refused(self):
        folder = self.new()
        self.put_all(folder, ["scripts/scan.py"], "p1")
        for path in (folder, folder / "scripts", folder / "scripts" / "scan.py"):
            with self.subTest(owned_by_another_user=path.name):
                os.chown(str(path), OTHER_UID, -1)
                try:
                    self.assertRefused(self.x("check", folder, "scripts/scan.py"), "%s belongs to another user" % path)
                finally:
                    os.chown(str(path), 0, -1)
                self.check_ok(folder)
        for where in (self.tmp, self.tmp.parent):
            with self.subTest(owned_by_another_user="temp" if where == self.tmp else "above"):
                os.chown(str(where), OTHER_UID, -1)
                try:
                    before = sorted(os.listdir(str(self.tmp)))
                    for r in (self.x("new"), self.x("check", folder, "scripts/scan.py")):
                        self.assertRefused(r, "other users can replace folders in %s, the temp folder or a folder above it" % where)
                    self.assertEqual(sorted(os.listdir(str(self.tmp))), before)
                finally:
                    os.chown(str(where), 0, -1)
                self.check_ok(folder)
        # a sticky folder that others may write is accepted only when it is root's or yours (as /tmp is root's): one of another
        # user is refused although it is sticky (the second audit of 1.0.2, R03b: that case had no test)
        for where in (self.tmp, self.tmp.parent):
            with self.subTest(sticky_folder_of_another_user="temp" if where == self.tmp else "above"):
                os.chown(str(where), OTHER_UID, -1)
                os.chmod(str(where), 0o1777)
                try:
                    before = sorted(os.listdir(str(self.tmp)))
                    for r in (self.x("new"), self.x("check", folder, "scripts/scan.py")):
                        self.assertRefused(r, "other users can replace folders in %s, the temp folder or a folder above it" % where)
                    self.assertEqual(sorted(os.listdir(str(self.tmp))), before)
                finally:
                    os.chmod(str(where), 0o700)
                    os.chown(str(where), 0, -1)
                self.check_ok(folder)


# --------------------------------------------------------------------------- python -c commands and the working folder

PYTHON_C = re.compile(r'(?m)(?:^|`)((?:python3?|py -3)(?: -(?!c )[A-Za-z]+)* -c "[^"\n]*"[^`\n]*)')
SEARCH_PATH_LINE = "sys.path = [p for p in sys.path if p]; "


def documented_python_c_commands():
    """[(file, command)] for every `python ... -c "<code>" ...` command written in the package's Markdown files."""
    return [(name, cmd.strip()) for name, text in package_texts().items() if name.endswith(".md") for cmd in PYTHON_C.findall(text)]


def imported_modules(command):
    code = command.split(' -c "', 1)[1].split('"', 1)[0]
    found = set()
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


class PlantedModuleTests(Agent):
    """A command such as `python -c "import tempfile; ..."` imports from the working folder first, and the working folder may be
    the folder the user asked to scan. The audit of 1.0.2 ran a planted tempfile.py through the report-folder helper of SKILL.md
    and a planted PIL package through the Pillow commands of how-to-export-clean.md. Every such command must keep the working
    folder off the search path."""

    def plant(self):
        work = self.scratch / ("planted_cwd_" + uuid.uuid4().hex[:8])
        markers = self.scratch / ("markers_" + uuid.uuid4().hex[:8])
        (work / "PIL").mkdir(parents=True)
        markers.mkdir()
        for module in ("tempfile", "os", "sys", "json", "re", "io", "struct", "zlib", "PIL/__init__"):
            path = work / (module + ".py")
            path.write_text("open(%r, 'w').write('ran')\nraise ImportError('planted')\n" % str(markers / module.replace("/", "_")))
        return work, markers

    def run_command(self, command, work, out_dir):
        src = out_dir / "in.png"                       # an RGB picture made by Pillow itself when there is one (both commands read it)
        if pillow_found():
            subprocess.run([sys.executable, "-c", "import sys; from PIL import Image; Image.new('RGB', (4, 4), (200, 10, 10)).save(sys.argv[1])",
                            str(src)], check=True, capture_output=True, cwd=str(out_dir), timeout=120)
        else:
            src.write_bytes(B.make_png())
        line = command
        for ext in ("png", "jpg"):
            line = line.replace("<IN.%s>" % ext, str(src)).replace("<OUT.%s>" % ext, str(out_dir / ("out." + ext)))
        self.assertNotIn("<", line.split(' -c "', 1)[1].split('"', 1)[1], "every placeholder filled")
        argv = shlex_split(line)
        self.assertIn(argv[0], ("python", "python3", "py"))
        argv = [sys.executable] + argv[(2 if argv[0] == "py" else 1):]
        return subprocess.run(argv, capture_output=True, cwd=str(work), timeout=120, env=child_env(self.tmp))

    def test_no_python_c_command_of_the_package_imports_from_the_working_folder(self):
        commands = documented_python_c_commands()
        # what the docs say about the two guards (the -I hiding a user-site Pillow is measured on the author's Windows machine)
        howto = " ".join(read(PACKAGE / "references" / "how-to-export-clean.md").split())
        self.assertIn("The first statement takes the working folder off Python's search path before Pillow is imported, so a folder named "
                      "`PIL` or a file named like a part of Python in the working folder (the renders folder, for example) is not run; "
                      "Python's `-I` option would do that too, but it also hides a Pillow that was installed for your user only.", howto)
        self.assertIn("`-I` keeps a `tempfile.py` in the working folder from running", " ".join(read(PACKAGE / "SKILL.md").split()))
        self.assertEqual(sorted({name for name, _ in commands}), ["SKILL.md", "references/how-to-export-clean.md",
                                                                 "references/no-skill-folder.md"])
        self.assertEqual(len(commands), 4, commands)
        for name, command in commands:
            with self.subTest(file=name, command=command[:60]):
                self.assertTrue(" -I -c " in command or SEARCH_PATH_LINE in command, "isolated, or the working folder taken off the path")
                if SEARCH_PATH_LINE in command:
                    self.assertTrue(command.split(' -c "', 1)[1].startswith("import sys; " + SEARCH_PATH_LINE), "before any other import")
                work, markers = self.plant()
                out_dir = self.scratch / ("out_" + uuid.uuid4().hex[:8])
                out_dir.mkdir()
                p = self.run_command(command, work, out_dir)
                self.assertEqual(sorted(os.listdir(str(markers))), [], "a planted module ran: %r" % p.stderr[-300:])
                if "PIL" not in imported_modules(command):
                    self.assertEqual(p.returncode, 0, p.stderr)
                elif pillow_found():
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertTrue(any(f.startswith("out.") for f in os.listdir(str(out_dir))), "the copy was written")

    def test_without_the_guard_the_planted_module_runs(self):
        # negative controls: the two commands the audit reproduced, in their 1.0.2 form
        commands = documented_python_c_commands()
        helper = [c for _n, c in commands if "tempfile.mkdtemp()" in c]
        pillow = [c for _n, c in commands if "PIL" in c]
        self.assertEqual((len(helper), len(pillow)), (1, 2), commands)
        for command, guard, module in ((helper[0], " -I", "tempfile"), (pillow[0], SEARCH_PATH_LINE, "PIL___init__")):
            with self.subTest(module=module):
                unguarded = command.replace(guard, "", 1)
                self.assertNotEqual(unguarded, command)
                work, markers = self.plant()
                out_dir = self.scratch / ("out_" + uuid.uuid4().hex[:8])
                out_dir.mkdir()
                self.run_command(unguarded, work, out_dir)
                self.assertIn(module, os.listdir(str(markers)), "without the guard the planted module runs")


# --------------------------------------------------------------------------- where the commands run

CMD_GUARD = "set NoDefaultCurrentDirectoryInExePath=1"
CMD_GUARD_ONE_LINE = CMD_GUARD + "& <command>"          # for a tool that starts a new cmd for every command (third audit)
PLANTED_PROGRAMS = ("python", "python3", "py", "ffmpeg", "ffprobe")

# The whole "Where to run them" paragraph of SKILL.md, sentence by sentence: an added sentence that contradicts it (the third
# audit's D13 added "In PowerShell the scanned folder is a fine working folder.") is caught as well as a changed one.
WHERE_TO_RUN = (
    "**Where to run them.** Run every command of this skill, `python --version` included, from a folder you trust, such as the "
    "user's home folder (start the command with `cd ~;` in bash or PowerShell, and give every path in full), never from inside the "
    "folder you scan or any other folder of files you received.",
    "On Windows use PowerShell or bash, not cmd: cmd starts a program of that name from the working folder (a planted "
    "`python.bat`, `py.bat`, `ffmpeg.bat` or `ffprobe.bat`) before the real one on PATH, and `-I` cannot stop that, because Python "
    "never starts (measured on Windows 11 with `python --version`, the scan command, the ffmpeg export commands, the ffprobe checks "
    "and the Pillow command; Windows PowerShell 5.1 and Git Bash started the real programs).",
    "If you have to use cmd, first run `%s` in the same cmd session: cmd then no longer looks in the working folder." % CMD_GUARD,
    "If each command you run starts a new cmd, put the set command in front of it on the same line, and nothing before it (in cmd, "
    "`cd ~;` takes the rest of the line up to the next `&` as a folder name, so a set command after it never runs): `%s`." % CMD_GUARD_ONE_LINE)

# The how-to page's rule for the same thing, the whole bullet.
HOWTO_WHERE_TO_RUN = (
    "- Run every command on this page from a folder you trust, such as your home folder, with every path in full, and never from "
    "inside the folder of the files you export or any other folder of files you received: on Windows, cmd starts an `ffmpeg.bat`, "
    "`ffprobe.bat` or `python.bat` from the working folder in place of the real program (\"Where to run them\" in `SKILL.md`). Use "
    "PowerShell or bash; in cmd, first run `%s` in the same session, or, if each command starts a new cmd, in front of it on the "
    "same line, with nothing before it (not `cd ~;`): `%s`." % (CMD_GUARD, CMD_GUARD_ONE_LINE))


def where_to_run_paragraph(skill_text):
    """The paragraph of SKILL.md that starts with **Where to run them.**, up to the blank line after it."""
    m = re.search(r"^\*\*Where to run them\.\*\* .*?(?=\n\n)", skill_text, re.S | re.M)
    return m.group(0) if m else None


def without_cmd_guard(env):
    """`env` without NoDefaultCurrentDirectoryInExePath, as on a Windows machine by default. A copy of os.environ has upper-case
    keys on Windows, so a pop of the mixed-case name removes nothing; the host this suite was built on sets the variable for its
    own shells, and the second audit of 1.0.2 missed the attack on its first try for that reason."""
    env = dict(env)
    for key in [k for k in env if k.upper() == CMD_GUARD.split(" ")[1].split("=")[0].upper()]:
        del env[key]
    return env


def documented_forms():
    """[(file, form)]: every command form of the package that a shell starts by a bare program name python, python3, py, ffmpeg
    or ffprobe, as written (the version checks, the two scan forms, the export commands, the ffprobe checks, the Pillow lines)."""
    skill, howto = read(PACKAGE / "SKILL.md"), read(PACKAGE / "references" / "how-to-export-clean.md")
    forms = [("SKILL.md", s) for s in dict.fromkeys(re.findall(r"`((?:python3?|py -3) --version)`", skill))]
    forms += [("SKILL.md", s) for s in re.findall(r'`(py -3 -I -B "<SKILL_DIR>\\scripts\\scan\.py"[^`]*)`', skill)]
    forms += [("SKILL.md", s) for s in dict.fromkeys(re.findall(r'^(python -I -B "<SKILL_DIR>/scripts/scan\.py"[^\n]*)$', skill, re.M))]
    forms += [("SKILL.md", s) for s in re.findall(r"^(ffmpeg -loglevel error -n -i [^\n]*)$", skill, re.M)]
    forms += [("references/how-to-export-clean.md", s) for s in re.findall(r"^(ffprobe -v error [^\n]*)$", howto, re.M)]
    forms += [("references/how-to-export-clean.md", s) for s in re.findall(r'^(python -c "import sys; [^\n]*)$', howto, re.M)]
    return forms


class WorkingFolderTests(Agent):
    """The second audit of 1.0.2 (B3, there since 1.0): on Windows, cmd starts a program named python, py, ffmpeg or ffprobe from
    the WORKING FOLDER before the one on PATH when NoDefaultCurrentDirectoryInExePath is not set (the Windows default), so a
    received renders folder holding a python.bat runs it in place of Python, and `-I` cannot help. SKILL.md now says where to run
    every command ("Where to run them"): from a folder you trust, PowerShell or bash rather than cmd, and in cmd the set command
    first."""

    def guard_texts(self):
        """(set command, its one-line form, cd) as SKILL.md gives them; the one-line form is what the cmd rows below run."""
        flat = " ".join(read(PACKAGE / "SKILL.md").split())
        guard = re.findall(r"first run `(set [^`]+)` in the same cmd session", flat)
        one_line = re.findall(r"put the set command in front of it on the same line, and nothing before it \([^)]*\): `(set [^`]+)`", flat)
        cd = re.findall(r"start the command with `(cd ~;)` in bash or PowerShell", flat)
        self.assertEqual((guard, one_line, cd), ([CMD_GUARD], [CMD_GUARD_ONE_LINE], ["cd ~;"]),
                         "SKILL.md gives the set command for cmd, its one-line form, and the cd for bash and PowerShell")
        how_to = re.findall(r"if each command starts a new cmd, in front of it on the same line, with nothing before it \(not `cd ~;`\): `(set [^`]+)`",
                            " ".join(read(PACKAGE / "references" / "how-to-export-clean.md").split()))
        self.assertEqual(how_to, one_line, "the how-to page gives the same one-line form")
        self.assertEqual(one_line[0].count("<command>"), 1)
        return guard[0], one_line[0], cd[0]

    @unittest.skipUnless(os.name == "nt", "cmd's lookup of the working folder is Windows behaviour")
    def test_cmd_runs_a_program_planted_in_the_working_folder_unless_the_documented_guards_are_used(self):
        guard, one_line, cd = self.guard_texts()
        forms = documented_forms()
        self.assertEqual(len(forms), 12, forms)
        skill_dir = self.scratch / ("skill_" + uuid.uuid4().hex[:6]) / SKILL_NAME
        shutil.copytree(str(PACKAGE), str(skill_dir), ignore=shutil.ignore_patterns("__pycache__"))
        demo, planted, markers, out = (self.scratch / (n + uuid.uuid4().hex[:6]) for n in ("renders_", "received_", "markers_", "out_"))
        subprocess.run([sys.executable, "-I", "-B", str(skill_dir / "scripts" / "make_demo.py"), str(demo)], check=True,
                       capture_output=True, timeout=300)
        for folder in (planted, markers, out):
            folder.mkdir()
        for name in PLANTED_PROGRAMS:          # a received folder with programs planted in it: each writes its marker
            (planted / (name + ".bat")).write_bytes(('@echo off\r\necho ran> "%s"\r\necho PLANTED %s\r\n' % (markers / name, name)).encode("ascii"))
        env = without_cmd_guard(child_env())
        env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")      # `python` is this interpreter
        self.assertFalse(any(k.upper() == "NODEFAULTCURRENTDIRECTORYINEXEPATH" for k in env))
        bash = git_bash()
        counter = iter(range(1, 10000))

        def fill(form):
            """The form with its placeholders filled, and the new files it must write (an export or a Pillow copy)."""
            n = next(counter)
            line = form.replace("<SKILL_DIR>", str(skill_dir)).replace("<PATH>", str(demo)).replace("<REPORT>", str(out / ("r%d.json" % n)))
            made = []
            for ext, name in (("png", "01_png_api_key_and_username.png"), ("jpg", "06_jpeg_exif_gps.jpg"), ("mp4", "05_mp4_prompt_tag_and_free_box.mp4")):
                if "<OUT.%s>" % ext in line:
                    made.append(out / ("c%d.%s" % (n, ext)))
                line = line.replace("<IN.%s>" % ext, str(demo / name)).replace("<OUT.%s>" % ext, str(out / ("c%d.%s" % (n, ext))))
            self.assertNotIn("<", line)
            return line, made

        def run(shell, cwd, line):
            stdin, data = subprocess.DEVNULL, None
            if shell == "cmd":
                argv = 'cmd /d /c "' + line + '"'       # a new cmd for this one line (as a tool that starts one per command)
            elif shell.startswith("cmd session"):        # one cmd that reads the set command, then the command, as typed
                argv, stdin = ["cmd", "/d", "/q"], None
                first = guard + "\r\n" if shell == "cmd session" else ""
                data = (first + line + "\r\nexit %errorlevel%\r\n").encode("ascii")
            elif shell == "powershell":
                argv = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                        base64.b64encode((line + "; exit $LASTEXITCODE").encode("utf-16-le")).decode("ascii")]
            else:
                argv = [bash, "-c", line]
            p = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, stdin=stdin, input=data, timeout=300)
            return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")

        # each row: (label, shell, working folder, the line as the docs write it, with <command> for the command)
        rows = [("cmd from the received folder (the control)", "cmd", planted, "<command>"),
                ("cmd from the received folder, the set command on the same line", "cmd", planted, one_line),
                # the third audit's reviewer: cmd has no `cd ~`; it takes the rest up to the & as a folder name, so the set never runs
                ("cmd from the received folder, cd ~; before the set command (the control)", "cmd", planted, cd + " " + one_line),
                ("cmd from the received folder, typed in a session without the set command (the control)", "cmd session, no set",
                 planted, "<command>"),
                ("cmd from the received folder, the set command first in the same session", "cmd session", planted, "<command>"),
                ("cmd from a trusted folder", "cmd", self.work, "<command>"),
                ("PowerShell from the received folder", "powershell", planted, "<command>"),
                ("PowerShell from the received folder, cd ~ first", "powershell", planted, cd + " <command>"),
                ("bash from the received folder", "bash", planted, "<command>"),
                ("bash from the received folder, cd ~ first", "bash", planted, cd + " <command>")]
        for where, form in forms:
            program = form.split(" ")[0]
            real = shutil.which(program, path=env["PATH"])
            for label, shell, cwd, template in rows:
                if shell == "bash" and bash is None:
                    continue
                with self.subTest(form=form[:50], run=label):
                    for marker in markers.iterdir():
                        marker.unlink()
                    command, made = fill(form)
                    line = template.replace("<command>", command)
                    if shell.startswith("cmd session") and not line.isascii():
                        continue                         # typed into cmd's input: kept to ASCII paths here
                    code, printed = run(shell, cwd, line)
                    ran = sorted(m.name for m in markers.iterdir())
                    if label.endswith("(the control)"):
                        self.assertEqual(ran, [program], "cmd started the planted %s.bat from the working folder: %r" % (program, printed[-200:]))
                        continue
                    self.assertEqual(ran, [], "a planted program ran: %r" % printed[-300:])
                    if real is None or program == "python" and "PIL" in form and not pillow_found():
                        continue
                    # the real program ran and did its work (an exit code 0 alone would also come from a line that ran nothing)
                    if form.endswith("--version"):
                        # a cmd that reads its input prints its banner and prompt before the output
                        self.assertRegex(printed, r"\APython 3\." if shell != "cmd session" else r"(?m)>Python 3\.", printed[-300:])
                    elif "scan.py" in form:
                        self.assertEqual(code, 1, printed[-300:])
                        self.assertIn("RESULT: FINDINGS", printed)
                    else:
                        self.assertEqual(code, 0, printed[-300:])
                        if made:
                            self.assertTrue(all(p.is_file() and p.stat().st_size > 0 for p in made), "no copy written: %r" % printed[-300:])
                        else:
                            self.assertEqual(program, "ffprobe", form)
                            self.assertRegex(printed, r"(?m)codec_type=video|(^|>)\d+\s*$", printed[-300:])

    def test_the_docs_say_where_to_run_every_command_and_that_the_report_stays(self):
        self.guard_texts()
        skill_text = read(PACKAGE / "SKILL.md")
        skill = " ".join(skill_text.split())
        howto_text = read(PACKAGE / "references" / "how-to-export-clean.md")
        howto = " ".join(howto_text.split())
        note = " ".join(read(DOC).split())
        # the whole paragraph, so that a sentence added to it is caught too (the third audit's D13), and nothing between it and
        # the next heading (a paragraph added after it passed the first form of this pin); the whole how-to bullet, and the next
        # line is the next bullet (an indented line added under it passed the first form)
        self.assertEqual(where_to_run_paragraph(skill_text), " ".join(WHERE_TO_RUN))
        self.assertEqual(skill_text.count("**Where to run them.**"), 1)
        self.assertIn("\n\n" + " ".join(WHERE_TO_RUN) + "\n\n## Workflow\n", skill_text)
        howto_lines = howto_text.split("\n")
        found = [i for i, line in enumerate(howto_lines) if "cmd starts an" in line]
        self.assertEqual([howto_lines[i] for i in found], [HOWTO_WHERE_TO_RUN])
        self.assertTrue(howto_lines[found[0] + 1].startswith("- "), "the bullet ends where the next bullet starts")
        sentence = " In PowerShell the scanned folder is a fine working folder."
        for changed in (skill_text.replace(WHERE_TO_RUN[-1], WHERE_TO_RUN[-1] + sentence),
                        skill_text.replace(WHERE_TO_RUN[-1], WHERE_TO_RUN[-1] + " Or run them from the scanned folder."),
                        skill_text.replace(WHERE_TO_RUN[-1] + "\n\n", WHERE_TO_RUN[-1] + "\n\n" + sentence.strip() + "\n\n")):
            self.assertNotEqual(changed, skill_text)
            self.assertFalse(where_to_run_paragraph(changed) == " ".join(WHERE_TO_RUN)
                             and "\n\n" + " ".join(WHERE_TO_RUN) + "\n\n## Workflow\n" in changed, "negative control")
        for needle in WHERE_TO_RUN + ('Then, from a folder you trust ("Where to run them" above):',
                                      'Run them from a folder you trust, not from the folder of the originals ("Where to run them").',
                                      'Windows (PowerShell; cmd only as "Where to run them" says): `py -3 -I -B',
                                      "The report stays when you are done (with no skill folder too: only the folder that "
                                      "`references/no-skill-folder.md` makes is deleted), so tell the user where it is."):
            self.assertIn(needle, skill)
        self.assertLess(skill.index("**Where to run them.**"), skill.index("## Workflow"), "inside Names in commands, before the first command")
        self.assertIn("Run every command on this page from a folder you trust, such as your home folder, with every path in full, and never "
                      "from inside the folder of the files you export or any other folder of files you received: on Windows, cmd starts an "
                      "`ffmpeg.bat`, `ffprobe.bat` or `python.bat` from the working folder in place of the real program", howto)
        self.assertIn("Use PowerShell or bash; in cmd, first run `%s` in the same session, or, if each command starts a new cmd, in front of "
                      "it on the same line, with nothing before it (not `cd ~;`): `%s`." % (CMD_GUARD, CMD_GUARD_ONE_LINE), howto)
        self.assertIn('Run `new` once, from a folder you trust, such as your home folder ("Where to run them" in `SKILL.md`), not from the '
                      "system temp folder itself.", note)
        # make_demo.py's last line prints the scan command without -I -B and quotes a path only when it is not plain (the last
        # read of 1.0.2: copied as printed, a path with a space breaks it), so the note tells the agent to add both
        self.assertIn("its last line names the `scan.py` next to it, without `-I -B` and with plain paths unquoted: add `-I -B` and "
                      "double quotes around both paths, as in `SKILL.md`.", note)
        self.assertIn('print("Next: python %s %s" % (quote(scan_py), quote(out)))', read(SCRIPTS / "make_demo.py"))
        self.assertIn("return p if _PLAIN.fullmatch(p) else '\"%s\"' % p", read(SCRIPTS / "make_demo.py"))
        # no text of the package lets a command run from any folder, or offers cmd without the set command
        stale = re.compile(r"from any folder|PowerShell or cmd\)|in the working folder when that is the scanned folder")
        for name, text in package_texts().items():
            if name.endswith(".md"):
                with self.subTest(file=name):
                    self.assertEqual(stale.findall(" ".join(text.split())), [])
        for old in ("Then, from any folder:", "Windows (PowerShell or cmd): `py -3", "Run `new` once, from any folder except the system temp folder itself.",
                    "and not in the working folder when that is the scanned folder."):
            self.assertTrue(stale.search(old), "negative control: %s" % old)
        guards = {name: re.findall(r"`(set [^`]*)`", text) for name, text in package_texts().items() if name.endswith(".md")}
        self.assertEqual({name: found for name, found in guards.items() if found},
                         {"README.md": [CMD_GUARD], "SKILL.md": [CMD_GUARD, CMD_GUARD_ONE_LINE],
                          "references/how-to-export-clean.md": [CMD_GUARD, CMD_GUARD_ONE_LINE]},
                         "one spelling of the set command, and of its one-line form, everywhere they are given")
        # the last read of 1.0.2: README named PowerShell only, SKILL.md and the how-to page PowerShell or bash
        self.assertIn("Run the commands in PowerShell or bash, or in cmd only after `%s`: cmd starts a `python.bat` or `ffmpeg.bat` that "
                      "sits in the working folder before the real program" % CMD_GUARD, " ".join(read(PACKAGE / "README.md").split()))
        self.assertIn("On Windows use PowerShell or bash, not cmd", " ".join(skill.split()))


def shlex_split(line):
    import shlex
    if os.name == "nt":
        return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in shlex.split(line, posix=False)]
    return shlex.split(line)


_PILLOW = []


def pillow_found():
    """Whether a child Python without -I finds Pillow (it often sits in a user site that -I hides)."""
    if not _PILLOW:
        _PILLOW.append(subprocess.run([sys.executable, "-c", "import PIL"], capture_output=True, timeout=120).returncode == 0)
    return _PILLOW[0]


# --------------------------------------------------------------------------- the documented shell forms

def git_bash():
    """The bash an agent's Bash tool uses: Git Bash on Windows (not the WSL launcher), bash or sh elsewhere."""
    if os.name == "nt":
        candidate = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Git", "usr", "bin", "bash.exe")
        return candidate if os.path.exists(candidate) else None
    return shutil.which("bash") or shutil.which("sh")


class ShellTests(Agent):
    def forms(self):
        fences = text_fences()
        self.assertEqual(fences, ["python -I -B - new <<'EOF'\n<the program>\nEOF\n",
                                  "@'\n<the program>\n'@ | python -I -B - new\n",
                                  "python -I -B - put \"<FOLDER>\" \"<SAVED>\" scripts/scan.py <<'EOF'\n<the program>\nEOF\n",
                                  "@'\n<the program>\n'@ | python -I -B - check \"<FOLDER>\" scripts/scan.py\n"])
        return fences

    def bash(self, script, tmp):
        exe = git_bash()
        if exe is None:
            self.skipTest("no Git Bash, bash or sh on this machine")
        script = script.replace("python -I -B -", '"%s" -I -B -' % Path(sys.executable).as_posix(), 1)
        proc = subprocess.run([exe, "-c", script], capture_output=True, stdin=subprocess.DEVNULL, timeout=300, env=child_env(tmp),
                              cwd=str(self.work))
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def powershell(self, script, tmp):
        if not (os.name == "nt" and shutil.which("powershell")):
            self.skipTest("Windows PowerShell 5.1 is a Windows program")
        script = script.replace("| python ", '| & "%s" ' % Path(sys.executable).as_posix()) + "\nexit $LASTEXITCODE"
        proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                               base64.b64encode(script.encode("utf-16-le")).decode("ascii")], capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=300, env=child_env(tmp), cwd=str(self.work))
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def test_the_bash_forms_run_as_written(self):
        sh_new, _ps_new, sh_put, _ps_check = self.forms()
        body = doc_program().rstrip("\n")
        code, out, err = self.bash(sh_new.replace("<the program>", body), self.tmp)
        self.assertEqual(code, 0, err)
        folder = Path(re.search(r"^OK folder: (.+?)\r?$", out, re.M).group(1))
        saved = self.saved(get_skill_sim.saved_p1(get_skill_sim.file_answer(PACKAGE, "scripts/scan.py")))
        command = sh_put.replace("<FOLDER>", str(folder)).replace("<SAVED>", str(saved)).replace("<the program>", body)
        code, out, err = self.bash(command, self.tmp)
        self.assertEqual((code, out.replace("\r\n", "\n")), (0, "OK scripts/scan.py verified (144720 bytes)\n"), err)
        self.assertExact(folder, ["scripts/scan.py"])
        # the re-read of 1.0.2: the note says to run a script as a separate command and never to join it to check with `;` or
        # `&&`, because an empty program exits 0 with no OK line: given on a pipe here, `&&` then starts the script anyway (the
        # script is scan.py --help, which prints its usage line)
        script = '"%s" -I -B "%s/scripts/scan.py" --help' % (Path(sys.executable).as_posix(), folder.as_posix())
        code, out, err = self.bash("printf '' | python -I -B - check \"%s\" scripts/scan.py && %s\n" % (folder, script), self.tmp)
        self.assertEqual((code, re.findall(r"^OK ", out, re.M), "usage: scan.py" in out), (0, [], True), (out, err))
        self.assertNotIn("REFUSED", err)
        # what a command of section 3 that was cut short prints (the last read of 1.0.2: the note named a bash message and
        # what it "means"): the put command, cut at sampled points from its first line to its closing EOF, prints a shell
        # error, a here-document warning, a Python error or no OK line. A cut of only the line end after EOF is no cut.
        whole = command.replace("python -I -B -", '"%s" -I -B -' % Path(sys.executable).as_posix(), 1)
        first = whole.index("\n")
        signs = re.compile(r"here-document|syntax error|unexpected (?:EOF|end of file)|^\w*Error\b", re.M)
        # Not run here: a cut just after <<'EOF' (an empty here-document). In Git Bash on Windows, Python 3.13.13 and 3.14.6 then
        # start their interactive prompt and print OSError tracebacks until they are stopped, and Python 3.9.25 to 3.12.11 exit 0
        # at once with no OK line (measured), so those two points are left out
        points = sorted(set(list(range(0, first + 1, 9)) + list(range(first + 2, len(whole), len(whole) // 20)) +
                            list(range(len(whole) - 12, len(whole) - 1))) - {first, first + 1})
        for n in points:       # stdin is an empty pipe: on Windows a bare `python` cut out of the first line, given the NUL
                               # device, waits as an interactive prompt (measured with Python 3.14.6)
            proc = subprocess.run([git_bash(), "-c", whole[:n]], capture_output=True, input=b"", timeout=300,
                                  env=child_env(self.tmp), cwd=str(self.work))
            out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
            self.assertTrue(signs.search(err) or not re.search(r"^OK ", out, re.M), (n, out, err))
        code, out, err = self.bash(command, self.tmp)
        self.assertTrue(re.search(r"^OK ", out, re.M) and not signs.search(err), "negative control: the whole command shows none")

    def test_the_powershell_forms_run_as_written(self):
        _sh_new, ps_new, _sh_put, ps_check = self.forms()
        body = doc_program().rstrip("\n")
        code, out, err = self.powershell(ps_new.replace("<the program>", body), self.tmp)
        self.assertEqual(code, 0, err)
        folder = Path(re.search(r"^OK folder: (.+?)\r?$", out, re.M).group(1))
        self.put_all(folder, ["scripts/scan.py"], "p2")
        code, out, err = self.powershell(ps_check.replace("<FOLDER>", str(folder)).replace("<the program>", body), self.tmp)
        self.assertEqual(code, 0, err)
        self.assertIn("OK 1 verified files and nothing else in %s" % folder, out)
        # the re-read of 1.0.2: an empty program given the same way (an empty here-string) exits 0 with no OK line, so a script
        # joined to check with `; if ($?) { <command> }` starts anyway (script as in the bash test); the note says to run a
        # script as a separate command
        script = '& "%s" -I -B "%s" --help' % (Path(sys.executable).as_posix(), folder / "scripts" / "scan.py")
        text = ps_check.replace("<FOLDER>", str(folder)).replace("<the program>\n", "").rstrip("\n") + "; if ($?) { %s }\n" % script
        self.assertTrue(text.startswith("@'\n'@ | python -I -B - check "), text)
        code, out, err = self.powershell(text, self.tmp)
        self.assertEqual((code, re.findall(r"^OK ", out, re.M), "usage: scan.py" in out), (0, [], True), (out, err))
        self.assertNotIn("REFUSED", err + out)
        # SKILL.md step 2 (the last read of 1.0.2): a tool that starts a new powershell.exe for each command can get 1 back for
        # the scanner's exits 2 and 3; $LASTEXITCODE read in the same command and the "(exit n)" of the RESULT line are the real code
        empty = self.scratch / ("empty_" + uuid.uuid4().hex[:8])
        empty.mkdir()
        for arg, real in ((str(empty), 3), ("--nope", 2)):
            line = '& "%s" -I -B "%s" "%s"' % (Path(sys.executable).as_posix(), folder / "scripts" / "scan.py", arg)
            for tail, process_exit in (("", 1), ('; Write-Output ("LASTEXITCODE=" + $LASTEXITCODE)', 0)):
                proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", line + tail], capture_output=True,
                                      stdin=subprocess.DEVNULL, timeout=300, env=child_env(self.tmp), cwd=str(self.work))
                out = proc.stdout.decode("utf-8", "replace")
                self.assertEqual(proc.returncode, process_exit, (arg, tail, out))
                self.assertEqual(("LASTEXITCODE=%d" % real) in out, bool(tail), out)
                self.assertEqual(len(re.findall(r"^RESULT: .*\(exit %d\)\s*$" % real, out, re.M)), 2 if real == 3 else 0, out)

    def test_an_accented_folder_turned_back_into_its_letters_works_through_the_shells(self):
        # the note's known issue: the recovered path is used in the next command (Git Bash and Windows PowerShell 5.1)
        tmp = self.new_tmp(parent=self.scratch / ("Caf\u00e9 " + uuid.uuid4().hex[:4]))
        folder = Path(ast.literal_eval(self.x("new", tmp=tmp).out.strip()[len("OK folder: "):]))
        self.put_all(folder, ["scripts/scan.py"], "p1")
        body = doc_program().rstrip("\n")
        ran = 0
        forms = ((self.bash, "python -I -B - check \"<FOLDER>\" scripts/scan.py <<'EOF'\n<the program>\nEOF\n"), (self.powershell, self.forms()[3]))
        for runner, form in forms:
            try:
                code, out, err = runner(form.replace("<FOLDER>", str(folder)).replace("<the program>", body), tmp)
            except unittest.SkipTest:
                continue
            ran += 1
            self.assertEqual(code, 0, err)
            self.assertIn("OK 1 verified files and nothing else in '", out, "the path is printed escaped again")
        if not ran:
            self.skipTest("neither bash nor Windows PowerShell is on this machine")

    def test_a_put_command_fits_the_bash_tool_with_room_to_spare(self):
        # measured for the shared design: Git Bash cuts the text after `sh -c` at 8,191 characters and an agent's Bash tool
        # adds about 410 to 440; a put command with a 250-character saved path and this program stays under that
        sh_put = self.forms()[2]
        command = sh_put.replace("<FOLDER>", "C:\\" + "f" * 60 + "\\ssr_ab12cd34").replace("<SAVED>", "C:\\" + "s" * 246)
        command = command.replace("<the program>", doc_program().rstrip("\n"))
        self.assertLess(len(command) + 440, 8191)

    def test_the_python3_and_py_forms_the_note_names_are_the_ones_of_skill_md_and_run_the_program(self):
        sentence = "Use `python3` or `py -3` in place of `python` as `SKILL.md` says."
        self.assertIn(sentence, " ".join(section(3).split()))
        self.assertIn("then `python3 --version` (macOS, Linux), then `py -3 --version` (Windows)", " ".join(read(PACKAGE / "SKILL.md").split()))
        self.assertEqual(re.findall(r"`(python3|py -3)`", sentence), ["python3", "py -3"])
        launcher = ["python3"] if POSIX else ["py", "-3"]           # on Windows `python3` may be the store's stand-in
        exe = shutil.which(launcher[0])
        if exe is None:
            self.skipTest("%s is not on PATH here" % launcher[0])
        proc = subprocess.run([exe] + launcher[1:] + ["-I", "-B", "-", "new"], input=doc_program().encode("ascii"), capture_output=True,
                              cwd=str(self.work), env=child_env(self.tmp), timeout=300)
        out = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(out, r"\AOK folder: .+\n\Z")
        folder = Path(out.strip()[len("OK folder: "):])
        self.assertEqual(self.x("check", folder).code, 0, "a folder made through %s passes check" % " ".join(launcher))


# --------------------------------------------------------------------------- real saved answers (named by the maintainer)

class RealAnswerTests(Agent):
    def test_a_real_plain_text_answer_for_scan_py(self):
        path = os.environ.get("SSR_REAL_P1")
        if not path:
            self.skipTest(REAL_ABSENT % "SSR_REAL_P1")
        folder = self.new()
        r = self.x("put", folder, path, "share-safe-renders/scripts/scan.py")
        self.assertEqual(r.out, "OK scripts/scan.py verified (144720 bytes)\n", r)
        self.assertExact(folder, ["scripts/scan.py"])
        with open(path, "rb") as fh:
            first = fh.readline().decode("utf-8-sig").rstrip("\r\n")
        self.assertEqual(first, note_header_example(), "the note's example header is the real one, display name included")

    def test_a_real_old_shape_answer(self):
        path = os.environ.get("SSR_REAL_OLD_SHAPE")
        if not path:
            self.skipTest(REAL_ABSENT % "SSR_REAL_OLD_SHAPE")
        folder = self.new()
        r = self.x("put", folder, path, "scripts/scan.py", "scripts/make_demo.py")
        self.assertEqual(r.code, 0, r)
        self.assertExact(folder, NAMES)


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
                             r"(\d+) in `test_v102_no_skill_folder\.py`\) and (\d+) precheck tests .*? and (\d+) private-term tests")
PUBLIC_MEASURED = re.compile(r"skipped (\d+) \((\d+) \+ (\d+)\), Ubuntu 22\.04 as root (\d+) \((\d+) \+ (\d+)\) and Ubuntu 26\.04 as root "
                             r"(\d+) \((\d+) \+ (\d+)\)")


def public_figures(tests_readme):
    flat = " ".join(tests_readme.split())
    m = PUBLIC_SENTENCE.search(flat)
    if not m:
        return None
    keys = ("total", "listing", "listing_test_listing", "listing_test_audit_docs", "listing_test_v102", "precheck", "private")
    return dict(zip(keys, (int(x) for x in m.groups())))


class DocumentPinTests(unittest.TestCase):
    def test_the_frontmatter_is_unchanged(self):
        lines = read(PACKAGE / "SKILL.md").split("\n")
        self.assertEqual(lines[:4], ["---", "name: share-safe-renders", DESCRIPTION_LINE, "---"])

    def test_skill_md_has_a_short_section_for_the_new_route_before_the_first_command(self):
        skill = read(PACKAGE / "SKILL.md")
        section_text = skill_section()
        lines = [line for line in section_text.strip("\n").split("\n") if line.strip()]
        self.assertTrue(6 <= len(lines) + 1 <= 10, "6 to 10 lines with the heading")
        flat = " ".join(section_text.split())
        for needle in ("this file in an answer, the other files in an index, each loaded on its own",
                       "load `references/no-skill-folder.md` first and follow it", "a scan needs `scripts/scan.py` alone",
                       "makes a fresh folder in the system temp folder", "only when its length and SHA-256 are the published ones",
                       "checks the folder before anything runs", "Treat that folder as `<SKILL_DIR>` in every command of this skill",
                       "delete it when you are done",
                       "A script goes into it only as the text that loading the file gave you (never from memory, never changed)",
                       "never runs before the check has printed its `OK` lines"):
            self.assertIn(needle, flat)
        for gone in ("### File:", "blocks", "snippet", "saved response", "cut a script"):
            self.assertNotIn(gone, flat, "nothing in the section depends on the old answer shape")
        start = skill.index("## If there is no skill folder")
        self.assertLess(start, min(skill.index("`python --version`"), skill.index("```sh")))
        self.assertLess(start, skill.index("## When to use"))
        self.assertIn("- `<SKILL_DIR>` is the folder that contains this SKILL.md (with no skill folder: the folder that "
                      "`references/no-skill-folder.md` makes and checks, see above);", skill)
        self.assertIn("`no-skill-folder.md` for an agent that has the skill only as text", skill.split("## Files in this skill")[1])

    def test_the_documented_scan_command_runs_python_isolated(self):
        skill = read(PACKAGE / "SKILL.md")
        self.assertIn('```sh\npython -I -B "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"\n```', skill)
        self.assertIn('`py -3 -I -B "<SKILL_DIR>\\scripts\\scan.py" "<PATH>" --json "<REPORT>"`', skill)
        self.assertIn('`python3 -I -B "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"`', skill)
        self.assertIn("`-I` keeps Python from importing a module planted next to the script and `-B` stops it from writing bytecode "
                      "there; the report and the exit codes are the same as without them.", " ".join(skill.split()))
        bare = re.compile(r'(?:python3?|py -3) "<SKILL_DIR>[/\\]scripts')
        for name, text in package_texts().items():
            if name.endswith(".md"):
                with self.subTest(file=name):
                    self.assertEqual(bare.findall(text), [], "every documented script command carries -I -B")
        self.assertTrue(bare.findall('python "<SKILL_DIR>/scripts/scan.py"'), "negative control")

    def test_the_note_has_its_sections_and_says_what_the_program_does(self):
        text = read(DOC)
        flat = " ".join(text.split())
        self.assertEqual(re.findall(r"^## (.*)$", text, re.M), ["1. The files each task needs", "2. The program", "3. Load, write and check",
                                                                "4. Run", "5. Delete", "6. When to stop"])
        self.assertTrue(text.startswith("# No skill folder"))
        # the note is read as text, so it stays short and its file answer comes back in the conversation (the stand-in shows a
        # result of up to INLINE_LIMIT characters); 20,000 until the last read of 1.0.2 added three sentences and one comment
        self.assertLessEqual(len(text), 20500)
        self.assertLess(len(get_skill_sim.file_answer(PACKAGE, "references/no-skill-folder.md")), get_skill_sim.INLINE_LIMIT)
        for needle in ("If the folder exists, ignore this file", "each file is loaded on its own",
                       "A script goes into the folder only as the text that loading it gave you (through `put`, or written as shown and "
                       "then accepted by `check`): never write one from memory, never change one, never cut one out of a text with other "
                       "tools, and never run one before `check` has printed its `OK` lines",
                       "It uses the real path of the temp folder (with no link in it), and on Linux and other POSIX systems it refuses "
                       "when the temp folder, or any folder above it, belongs to another user (root excepted) or is open to other users' writes without "
                       "the sticky bit",
                       "It checks what is there, not who made it: a folder of your own made by hand the same way passes too, so use only "
                       "the folder that `new` printed",
                       "(the header line, and the blank line after it, may each stay or go)",
                       "Each set below was written by the program in section 2 into an otherwise empty folder and run from there",
                       "Run `make_demo.py` from its file in the folder, not from standard input: its last line names the `scan.py` next to it, "
                       "without `-I -B` and with plain paths unquoted: add `-I -B` and double quotes around both paths, as in `SKILL.md`.",
                       "reads no environment variable of its own, starts no other program, deletes nothing",
                       "`new` makes a fresh folder named `ssr_` and 8 more characters directly in the system temp folder",
                       "on Linux and other POSIX systems both are open to your user only",
                       "It takes no folder of yours: every run makes a new one, and it never writes into a folder that already existed",
                       "writes nothing unless every NAME is found with exactly the published length and SHA-256, never replaces a file, "
                       "and checks the whole folder again after writing",
                       "the path as the file index shows it (`share-safe-renders/scripts/scan.py`) works too",
                       "Success is the `OK` line, not the exit code alone: a program that never ran also exits 0 and prints nothing",
                       "Every path goes into these commands in double quotes and follows \"Names in commands\" in `SKILL.md`",
                       "from a folder you trust, such as your home folder (\"Where to run them\" in `SKILL.md`), not from the system temp folder itself",
                       "it is `<SKILL_DIR>` in every command of `SKILL.md` from now on",
                       "with the path exactly as its file index shows it", "The saved file may be plain text or JSON; `put` reads both",
                       "never with a shell here-document or `echo`",
                       "not the shared temp folder of a Linux or macOS machine, and not the user's project", "then delete the scratch file",
                       "`put` repairs the usual slips of such a copy (Windows line ends, a missing or extra final newline, a byte order mark)",
                       "`check` accepts only the exact bytes: plain line ends and exactly one final newline",
                       "Run `check` again before every later run of a script",
                       "Run a script only as a separate command, after you have read those lines: do not join it to `check` with `;` or "
                       "`&&` (a command cut short, or an empty program, can exit 0 without printing an `OK` line).",
                       "An older answer shape, with every file of the skill as a `### File:` block in one saved text, is also understood"):
            self.assertIn(needle, flat)
        # the re-read of 1.0.2: the joined form that the last read had added could start a script with no check
        for gone in ("`&& <command>`", "if ($?)", "joined to `check` so that it cannot start"):
            self.assertNotIn(gone, flat, "the joined form is not offered")
        self.assertEqual(flat.count("### File:"), 1, "one honest sentence about the old shape, nothing more")
        for gone in ("snippet", "skill folder: <", "the second argument is always new", "RESPONSE", "no complete block"):
            self.assertNotIn(gone, flat, "nothing of the 1.0.1 snippet is left")

    def test_the_run_section_uses_the_skill_md_command(self):
        run = " ".join(section(4).split())
        commands = re.findall(r"^```sh\n(.*?)```", section(4), re.S | re.M)
        self.assertEqual(commands, ['python -I -B "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"\n'])
        self.assertIn(commands[0].strip(), read(PACKAGE / "SKILL.md"), "the same command as step 2 of SKILL.md")
        for needle in ("The report is the same as from an installed folder", "`scan.py` uses neither its own path nor its own name",
                       "it never prints the leaked text, only the class, the place, the length and a keyed hash",
                       "`-I` keeps Python from importing a module that sits next to the script, and `-B` keeps it from writing into the folder",
                       "Do not put `<REPORT>`, the re-exported copies or the demo files in that folder", "prints `usage: scan.py`"):
            self.assertIn(needle, run)

    def test_the_delete_step_lists_the_folders_and_names_no_recursive_delete_command(self):
        delete = " ".join(section(5).split())
        for needle in ("delete `<FOLDER>` with your shell's own command for removing a folder and its contents, with the path in double "
                       "quotes, and delete nothing else",
                       "The name of `<FOLDER>` must not be in that list", "not by testing the path you typed",
                       "a delete command can exit 0 on a path it could not remove",
                       "If another `ssr_` folder is listed, leave it and tell the user", "the re-scan of the copies in step 5 of `SKILL.md` included",
                       "delete every folder you made at the end"):
            self.assertIn(needle, delete)
        for name, content in package_texts().items():
            with self.subTest(file=name):
                self.assertEqual(RECURSIVE_DELETE.findall(content), [])
        for sample in ("rm -rf /tmp/x", "Remove-Item -Path x -Recurse -Force", "shutil.rmtree(folder)", "del /s /q x"):
            self.assertTrue(RECURSIVE_DELETE.findall(sample), sample)

    def test_the_listing_command_of_the_delete_step_prints_the_temp_folder_escaped_and_the_ssr_folders(self):
        command = re.findall(r"^```sh\n(python -I -c .*?)\n```$", section(5), re.S | re.M)
        self.assertEqual(len(command), 1)
        code = command[0].split('-c "', 1)[1].rstrip('"')
        tmp = Path(tempfile.mkdtemp(prefix="ssrtest_listcmd_")).resolve() / ("Caf" + chr(0xE9) + " " + uuid.uuid4().hex[:4])
        self.addCleanup(remove_tree, str(tmp.parent))
        tmp.mkdir()
        (tmp / "ssr_abcd1234").mkdir()
        (tmp / "other").mkdir()
        ascii_stdout = "import io, sys; sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=\"ascii\"); "
        proc = subprocess.run([sys.executable, "-I", "-c", ascii_stdout + code], capture_output=True, timeout=60, env=child_env(tmp))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        first, second = proc.stdout.decode("ascii").strip().splitlines()
        self.assertEqual(Path(ast.literal_eval(first)).resolve(), tmp)
        self.assertEqual(ast.literal_eval(second), ["ssr_abcd1234"])
        plain = code.replace("print(ascii(t))", "print(t)")
        self.assertNotEqual(plain, code)
        proc = subprocess.run([sys.executable, "-I", "-c", ascii_stdout + plain], capture_output=True, timeout=60, env=child_env(tmp))
        self.assertIn(b"UnicodeEncodeError", proc.stderr, "negative control: a plain print of the folder fails on such a console")

    def test_the_known_issue_and_the_stop_rules(self):
        flat = " ".join(read(DOC).split())
        for needle in ("Known issue: `new`, `put` and `check` print a path plainly only when it holds nothing but ASCII letters, digits, "
                       "spaces and `. : / \\ ~ + - _`. A path with any other character (often an accented letter in a Windows user name, "
                       "but also an apostrophe as in O'Brien, `&`, parentheses or `$`) is printed as a quoted Python string with escapes",
                       "or between double quotes when the path holds an apostrophe",
                       "each doubled backslash written once, and each escape turned back into its letter",
                       "If you cannot turn it back with certainty, stop: nothing has run yet",
                       "Stop and tell the user what was printed, and do not retry another way on your own",
                       "Give the program exactly as section 2 prints it: do not shorten, rewrite or reformat it",
                       "on Windows the program does not read folder permissions, so it cannot tell that another account changed a file "
                       "after `check`. On Linux and other POSIX systems it refuses such a temp folder itself",
                       "If Python finds no usable temp folder, it would use the working folder, so the program refuses and writes nothing",
                       "In bash, a command of section 3 that was cut short anywhere before the end of its closing `EOF` prints a shell error, "
                       "a here-document warning, a Python error or no `OK` line (some cuts also leave it waiting until it is stopped): stop as above "
                       "(the user may choose the PowerShell form instead).",
                       "Do not use this route on a Windows machine whose temp folder, or a folder above it, other users can write",
                       "On Windows the folder that `new` prints must be inside your own user folder (the folder `~` names in "
                       "PowerShell; an account's own temp folder is there by default); if not, stop and tell the user.",
                       "that folder belongs to another user (root excepted), or others may write to it without the sticky bit"):
            self.assertIn(needle, flat)

    def test_the_known_issue_names_exactly_the_characters_the_program_prints_plainly(self):
        # the audit of 1.0.2: the note said "outside plain ASCII", but an apostrophe, & or parentheses are printed quoted too
        flat = " ".join(read(DOC).split())
        m = re.search(r"print a path plainly only when it holds nothing but ASCII letters, digits, spaces and `([^`]+)`\.", flat)
        self.assertTrue(m)
        listed = set(m.group(1).split(" "))
        pattern = re.search(r're\.fullmatch\(r"(\[[^"]+\]\+)", str\(p\), re\.A\)', doc_program()).group(1)
        for c in [chr(i) for i in range(32, 127)] + ["é", "Ł", "’", "“", " "]:
            in_note = c.isascii() and (c.isalnum() or c == " " or c in listed)
            self.assertEqual(bool(re.fullmatch(pattern, c, re.A)), in_note, ascii(c))
        for named in ("'", "&", "(", ")", "$"):
            self.assertIsNone(re.fullmatch(pattern, named, re.A), "the note names %s as printed quoted" % named)

    def test_the_known_issue_explains_its_example_truly(self):
        m = re.search(r"\(`\\x([0-9a-f]{2})` is the letter (\w) with an? (\w+) accent\)", read(DOC))
        self.assertTrue(m)
        letter = chr(int(m.group(1), 16))
        self.assertEqual(unicodedata.name(letter), "LATIN SMALL LETTER %s WITH %s" % (m.group(2).upper(), m.group(3).upper()))
        example = ast.literal_eval(re.search(r"for example `('D:[^`]+')`", section(5)).group(1))
        self.assertIn(letter, example)
        self.assertNotEqual(unicodedata.name(letter), "LATIN SMALL LETTER E WITH GRAVE", "negative control")

    def test_the_header_example_is_the_header_a_file_answer_starts_with(self):
        # the second audit of 1.0.2 (E10): the display name in the example of step 2 was not pinned (the real answer for
        # scan.py starts with the same line: RealAnswerTests compares it when SSR_REAL_P1 names one)
        self.assertEqual(note_header_example(), "## File: %s/scripts/scan.py (from %s)" % (SKILL_NAME, DISPLAY))
        self.assertEqual(note_header_example(), get_skill_sim.file_answer(PACKAGE, "scripts/scan.py").split("\n", 1)[0])
        self.assertEqual(re.findall(r"^# (.+)$", read(PACKAGE / "SKILL.md"), re.M)[0], DISPLAY, "the display name is the skill's title")
        self.assertNotEqual(note_header_example().replace("Share-Safe", "Share Safe"), note_header_example(), "negative control")

    def test_readme_gives_the_new_route(self):
        readme = read(PACKAGE / "README.md")
        flat = " ".join(readme_install().split())
        for needle in ("references/no-skill-folder.md", "nothing was installed", "That note tells the agent to load the one file a scan needs "
                       "(`scripts/scan.py`)", "writes it into a fresh folder in the system temp folder only when its SHA-256 is the published one",
                       "(for a file shown in the conversation, the note tells the agent to write a scratch file of its own first and to "
                       "delete it afterwards, and allows writing the file straight into that folder and checking it)",
                       "it tells the agent to run the `scan.py` in that folder from a folder it trusts, as `SKILL.md` says, and to delete "
                       "that folder afterwards"):
            self.assertIn(needle, flat)
        # the re-read of 1.0.2: the scratch file is what the note tells the agent (it also allows a straight write), and the scan
        # runs from a trusted folder, not "from there"
        for gone in ("goes through a scratch file", "run the scan from there"):
            self.assertNotIn(gone, " ".join(readme.split()))
        added = [line for line in readme_install().split("\n") if "no-skill-folder" in line or "fresh folder in the system temp folder" in line]
        self.assertEqual(len(added), 2, "the note is two lines")
        table = readme.split("## What is in the folder")[1].split("## Permissions")[0]
        self.assertIn("| `references/no-skill-folder.md` | For an agent that received the skill as text with no folder: the files each task "
                      "needs, a short program that writes them into a fresh temporary folder only after checking each file's SHA-256, and "
                      "how to delete that folder. |", table)
        permissions = " ".join(readme.split("## Permissions")[1].split("## Source and tests")[0].split())
        self.assertIn("`references/no-skill-folder.md` tells the agent itself (not the scripts) to load the scripts a task needs (`scripts/scan.py` "
                      "for a scan), to write them with a short checking program into a fresh folder that the program makes in the system temp "
                      "folder", permissions)
        self.assertIn("(for a file shown in the conversation, the note tells the agent to write a scratch file of its own first and to "
                      "delete it afterwards, and allows writing the file straight into that folder and checking it), and to delete that "
                      "folder afterwards", permissions)
        # the last read of 1.0.2: a sentence that says what an agent does is a promise the text cannot keep
        for promise in ("The agent loads", "the agent runs it", "and deletes that folder afterwards", "An agent pastes",
                        "is the file the agent reads", "The instructions the agent follows"):
            self.assertNotIn(promise, " ".join(readme.split()))
        for gone in ("snippet", "saved response file"):
            self.assertNotIn(gone, readme)

    def test_no_package_line_starts_like_a_file_header(self):
        header = re.compile(r"^#{2,3} File: ", re.M)
        for name, text in package_texts().items():
            with self.subTest(file=name):
                self.assertIsNone(header.search(text), "a header lookalike would use one of the program's 4 header slots")
        self.assertIsNotNone(header.search("text\n## File: share-safe-renders/x.py\n"))
        self.assertIsNone(header.search("the line `## File: x` is quoted in the middle of a line"))

    def test_the_new_text_makes_no_claim_about_a_marketplace_answer(self):
        for label, text in (("note", read(DOC)), ("SKILL.md section", skill_section()), ("README install", readme_install())):
            with self.subTest(text=label):
                self.assertEqual(wrapper_claims(text), [])
        self.assertTrue(wrapper_claims("the marketplace tells you to pipe it"), "negative control")
        self.assertEqual(wrapper_claims("write the files into a temporary folder and delete it afterwards"), [])

    def test_the_tests_readme_documents_the_module_the_program_and_the_simulator(self):
        text = " ".join(read(Path(HERE) / "README.md").split())
        for needle in ("`test_v102_no_skill_folder.py`", "`get_skill_sim.py`", "`gen_table.py`", "`extract_core.py`",
                       "python -I tests/share-safe-renders/get_skill_sim.py packages/share-safe-renders <out_dir>",
                       "python fake_get_skill.py --file share-safe-renders/scripts/scan.py",
                       "scan.py and make_demo.py are the files of 1.0, byte for byte", "92 lines and 6,175 characters",
                       "SSR_REAL_P1", "SSR_REAL_OLD_SHAPE"):
            self.assertIn(needle, text)

    def test_the_public_checkout_skip_figures_are_the_measured_ones(self):
        # The READMEs say how many more tests skip in a checkout of the public repository (no listing/, no tools/, no private
        # deny-list file). Measure it: copy packages/ and tests/ into an empty folder and run the four modules that read those
        # files there. The run inside the copy reaches this test again; the environment variable stops it from recursing.
        if os.environ.get("SSR_NESTED_PUBLIC_RUN") == "1":
            return
        tests_readme = read(Path(HERE) / "README.md")
        stated = public_figures(tests_readme)
        self.assertIsNotNone(stated, "the tests README no longer states the public-checkout figures in the form this test reads")
        work = Path(tempfile.mkdtemp(prefix="ssrtest_public_"))
        self.addCleanup(remove_tree, str(work))
        shutil.copytree(str(PACKAGE), str(work / "packages" / SKILL_NAME), ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(HERE, str(work / "tests" / SKILL_NAME), ignore=shutil.ignore_patterns("__pycache__", "_private_denylist.json"))
        modules = ("test_listing", "test_audit_docs", "test_package_hygiene", "test_v102_no_skill_folder")
        env = dict(child_env(), SSR_NESTED_PUBLIC_RUN="1")
        log = ""
        for module in modules:
            proc = subprocess.run([sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s", "tests/" + SKILL_NAME, "-p",
                                   module + ".py", "-v"], cwd=str(work), capture_output=True, timeout=900, env=env)
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
               "listing_test_v102": measured.get(("test_v102_no_skill_folder", "listing"), 0),
               "precheck": sum(n for (_m, k), n in measured.items() if k == "precheck"),
               "private": sum(n for (_m, k), n in measured.items() if k == "private")}
        got["listing"] = got["listing_test_listing"] + got["listing_test_audit_docs"] + got["listing_test_v102"]
        got["total"] = got["listing"] + got["precheck"] + got["private"]
        self.assertEqual(stated, got, "the tests README's public-checkout figures are not the measured ones")
        flat = " ".join(tests_readme.split())
        self.assertIn("(%d tests skip without those two," % (got["listing"] + got["precheck"]), flat)
        self.assertIn("the maintainer-only private deny-list file (%d tests;" % got["private"], flat)
        self.assertIn("a checkout of it skips %d more tests" % got["total"], " ".join(read(PACKAGE / "README.md").split()))
        windows, _lo, _hi = stated_skips(tests_readme)
        rows = {(r[0], r[1]): int(r[5]) for r in run_table(tests_readme) if r[5].isdigit()}
        m = PUBLIC_MEASURED.search(flat)
        self.assertTrue(m)
        figures = [int(x) for x in m.groups()]
        for (whole, base, extra), row_base in zip((figures[0:3], figures[3:6], figures[6:9]),
                                                  (windows, rows[("Ubuntu 22.04, root", "4.4.2")], rows[("Ubuntu 26.04, root", "8.0.1")])):
            self.assertEqual((base, extra, whole), (row_base, got["total"], row_base + got["total"]))
        self.assertNotEqual(public_figures(tests_readme.replace("runs skip %d more" % got["total"], "runs skip %d more" % (got["total"] - 1))), got)

    def test_the_listing_source_and_the_proposal_carry_the_new_text(self):
        # last statement of the test: a skip ends the test under failfast
        if not os.path.isdir(LISTING):
            self.skipTest(LISTING_ABSENT)
        proposal = read_text(os.path.join(LISTING, "update_v1.0.2_PROPOSAL.md"))
        fields = read_text(os.path.join(LISTING, "listing_fields.md"))
        old_proposal = read_text(os.path.join(LISTING, "update_v1.0.1_PROPOSAL.md"))
        self.assertIn("**Superseded by update_v1.0.2_PROPOSAL.md**", old_proposal.split("\n## ")[0])
        n = unittest.TestLoader().discover(HERE).countTestCases()
        new_text = "\n".join(re.findall(r"^New:\n((?:>.*\n?)+)", proposal, re.M))
        old_text = "\n".join(re.findall(r"^Old:\n((?:>.*\n?)+)", proposal, re.M))
        self.assertIn("%d automated tests" % n, new_text)
        self.assertIn("The suite has %d tests." % n, new_text)
        self.assertIn("606 automated tests", old_text, "Old is the live 1.0 text")
        self.assertNotIn("no-skill-folder", old_text)
        self.assertNotIn("[[", new_text, "a placeholder never sits inside a New block that is pasted into the listing")
        # the re-test result is either still a placeholder in its own section, or filled in there: never inside a New block
        self.assertNotIn("RETEST", new_text)
        retest = proposal.split("## Fresh-buyer re-test")[1].split("\n## ")[0]
        if "[[RETEST RESULT" not in retest:
            self.assertGreater(len(retest.strip()), 200, "the re-test section holds the result once the placeholder is gone")
            self.assertNotIn("[[RETEST", proposal, "no placeholder is left once the result is filled in")
        scan_kb = round((SCRIPTS / "scan.py").stat().st_size / 1000.0)
        windows, lo, hi = stated_skips(read(Path(HERE) / "README.md"))
        for label, text in (("New blocks", new_text), ("listing_fields.md", fields)):
            with self.subTest(text=label):
                flat = " ".join(text.replace("\n> ", " ").split())
                self.assertIn("references/no-skill-folder.md", flat)
                sizes = re.findall(r"scan\.py, about (\d+) KB", flat)
                self.assertGreaterEqual(len(sizes), 2, "the audit of 1.0.2: one wrong copy of two passed while the other was right")
                self.assertEqual(set(sizes), {str(scan_kb)}, "every 'scan.py, about N KB' is the real size")
                self.assertIn("its report is the same: it never prints the leaked text", flat)
                self.assertIn("fresh folder in the system temp folder", flat)
                self.assertIn("SHA-256", flat)
                for gone in ("snippet", "saved response", "copied by hand", "too long to copy by hand"):
                    self.assertNotIn(gone, flat, "no claim of the 1.0.1 route is left")
                self.assertEqual(re.findall(r"\((\d+) of the (\d+) on Windows with Python 3\.14\.6, (\d+) to (\d+) on Linux\)", flat),
                                 [(str(windows), str(n), str(lo), str(hi))])
                # the second audit of 1.0.2: put repairs line ends, a BOM and the final newline, so "differs by one byte" was not
                # exact; and a folder above a Windows temp folder that others can write is as unsafe as the temp folder itself
                for needle in ("refuses any copy whose content differs from the published file (it repairs only line ends, a byte order "
                               "mark and the final newline)", "a copy whose content differs from the published file is refused and "
                               "nothing runs", "whose temp folder, or a folder above it, other users can write"):
                    self.assertIn(needle, flat)
        flat_all = " ".join((proposal + "\n" + fields).split())
        for gone in ("no longer served", "by one byte", "by a single byte", "both Permissions lines"):
            self.assertNotIn(gone, flat_all, "the second audit of 1.0.2 found this wording not exact")
        for needle in ("was not served on 2026-10-15", "all three Permissions lines (Tools used, File scopes, Notes)"):
            self.assertIn(needle, flat_all)
        stated = public_figures(read(Path(HERE) / "README.md"))
        self.assertIn("a public checkout skips %d more tests" % stated["total"], " ".join(fields.split()))
        changelog = proposal.split("## 7. Changelog for the Update dialog")[1]
        first = changelog.split("\n```\n")[1].split("\n")[0]
        self.assertIn("1.0.2", first)
        self.assertIn("v1.2", first)
        self.assertIn("scan.py and make_demo.py are unchanged", changelog)
        # the third audit of 1.0.2: the one-line cmd form and the example session's commands, as the package now gives them
        self.assertIn("or in cmd only after set NoDefaultCurrentDirectoryInExePath=1 (SKILL.md and how-to-export-clean.md: typed first "
                      "in the same cmd, or, when every command starts a new cmd, on the same line with nothing before it: %s)."
                      % CMD_GUARD_ONE_LINE, changelog)
        self.assertIn("the example session starts every command with cd ~; and gives every path in full", changelog)
        self.assertIn("`%s`" % CMD_GUARD_ONE_LINE, proposal.split("## What changed in the facts")[1].split("\n## ")[0])
        # the last read of 1.0.2: a sentence that says what an agent does is a promise the text cannot keep; the New blocks and
        # the listing source say what the text tells it to do
        for label, text in (("New blocks", new_text), ("listing_fields.md", fields)):
            flat = " ".join(text.replace("\n> ", " ").split())
            for promise in ("The agent deletes", "The agent puts", "then the agent stops", "the agent loads the one file",
                            "The agent gives a fixed report", "the agent pastes a file name", "it writes a new file, checks",
                            "and deletes that folder afterwards", "goes through a scratch file"):
                self.assertNotIn(promise, flat, label)
            for told in ("The note tells the agent to delete the folder afterwards", "SKILL.md tells the agent to put the report",
                         "then the note tells the agent to stop and tell you", "which tells it to load the one file a scan needs",
                         "The skill tells the agent to give a fixed report", "the skill tells the agent to paste a file name",
                         # the re-read of 1.0.2: what the note tells and allows; and the subject of the --json sentence is scan.py
                         "(for a file shown in the conversation, the note tells the agent to write a scratch file of its own first and "
                         "to delete it afterwards, and allows writing the file straight into that folder and checking it)",
                         "not loose in the shared temp folder. scan.py refuses to replace an existing --json file"):
                self.assertIn(told, flat, label)
        new_sentences = [s for s in re.split(r"(?<=\.) ", new_text) if "as text" in s or "no-skill-folder" in s]
        self.assertGreaterEqual(len(new_sentences), 3)
        self.assertEqual(wrapper_claims(" ".join(new_sentences)), [])


# --------------------------------------------------------------------------- the suite itself

TEMP_PREFIX = re.compile(r"""(?:prefix=|Scratch\(cls, |gettempdir\(\), )["']ssr_""")


class SuiteHygieneTests(unittest.TestCase):
    def test_no_test_or_tool_here_names_a_temp_folder_like_the_routes_folders(self):
        # the delete step of the note lists every folder in the temp folder whose name starts with ssr_ and tells the agent to
        # report it; a folder that a test run left behind there would show up in an agent's report (buyer re-test of 1.0.2)
        hits = []
        for path in sorted(Path(HERE).rglob("*.py")):
            for n, line in enumerate(path.read_bytes().decode("utf-8").splitlines(), 1):
                if TEMP_PREFIX.search(line):
                    hits.append("%s:%d" % (path.name, n))
        self.assertEqual(hits, [])
        for sample in ('tempfile.mkdtemp(prefix="SSR_x_")', "Scratch(cls, 'SSR_test_')", 'os.path.join(tempfile.gettempdir(), "SSR_y")'):
            self.assertTrue(TEMP_PREFIX.search(sample.replace("SSR_", "ssr_")), sample)     # written in capitals so this file passes
        self.assertIsNone(TEMP_PREFIX.search('tempfile.mkdtemp(prefix="ssrtest_x_")'))


if __name__ == "__main__":
    unittest.main()
