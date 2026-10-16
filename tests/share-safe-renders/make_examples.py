# -*- coding: utf-8 -*-
"""Regenerates the three files in packages/share-safe-renders/examples/ from REAL runs of the package scripts.

    python -I -B tests/share-safe-renders/make_examples.py [OUTDIR]       (default OUTDIR: the package's examples/)

What is real: the demo files (scripts/make_demo.py), every scanner run (scripts/scan.py), the ffmpeg exports and the
re-scans. What is written by hand: the assistant's lines in example_session.md, which follow SKILL.md and are filled
with the real numbers; the file says so at the top. The class meanings, the export commands and the "cannot see"
block are parsed out of SKILL.md, so the example cannot drift from it.

The session follows "Where to run them" in SKILL.md: every command line starts with `cd ~; ` and gives every path in full.
Each line is run without a shell, from an empty folder that stands for the home folder: the part after `cd ~; ` is split
as sh splits it, <SKILL_DIR> (the package folder) and <PROJECT> (a folder that holds renders/) are filled in, `python` is
the interpreter running this file, and `mkdir` is done with os.makedirs. In the scanner's output the real path of that
folder is written <PROJECT> again. The scanner shortens a path part over 40 characters and escapes some characters, so a
temp folder whose path is not plain ASCII with parts of at most 40 characters is not used (NeedsPlainTemp, decided before
anything runs; after that, a path the scanner does not print as given is a failure).

Needs ffmpeg and ffprobe on PATH (the demo MP4 and the exports). Nothing outside a temporary folder is touched, and
OUTDIR is written only when you name it (or by default the package's examples/ folder).
"""
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PKG = os.path.join(REPO, "packages", "share-safe-renders")
SCAN = os.path.join(PKG, "scripts", "scan.py")
MAKE_DEMO = os.path.join(PKG, "scripts", "make_demo.py")
SKILL_MD = os.path.join(PKG, "SKILL.md")
LISTING = os.path.join(REPO, "listing", "share-safe-renders")


PROJECT = "<PROJECT>"     # the full path of the user's project folder (it holds renders/), as the session writes it
HOME = "cd ~; "           # how every command line of the session starts ("Where to run them" in SKILL.md)


class NeedsFfmpeg(Exception):
    pass


class NeedsPlainTemp(Exception):
    """The temp folder's path is not one the scanner prints as it is (a part over 40 characters is shortened, some
    characters are escaped), so the project folder in its output could not be written <PROJECT>."""


def printed_as_is(path):
    """Plain ASCII, and no part (between slashes or backslashes) over the scanner's 40 characters."""
    return re.fullmatch(r"[\x20-\x7e]+", path) is not None and all(len(part) <= 40 for part in re.split(r"[\\/]", path))


def scanner_version():
    return re.search(r'^VERSION = "([^"]+)"', read(SCAN), re.M).group(1)


def read(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8")


def run(args, cwd):
    p = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=300)
    return p.returncode, p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")


def scan(cwd, *args):
    return run([sys.executable, "-I", "-B", SCAN] + list(args), cwd)


def fence(text, lang=""):
    return "```%s\n%s\n```" % (lang, text.rstrip("\n"))


def run_line(line, home, project):
    """Run one command line of the session as a shell would after `cd ~`: from `home`, with <SKILL_DIR> and <PROJECT>
    filled in. The lines hold only double-quoted paths with forward slashes, so shlex splits them as sh does. `mkdir` is
    done with os.makedirs (the same folder, without a shell)."""
    assert line.startswith(HOME), line
    argv = [t.replace("<SKILL_DIR>", PKG).replace(PROJECT, project) for t in shlex.split(line[len(HOME):])]
    assert not any("<" in t for t in argv), argv
    if argv[0] == "mkdir":
        os.makedirs(argv[1])
        return 0, ""
    if argv[0] == "python":
        argv[0] = sys.executable
    return run(argv, home)


# ---------------------------------------------------------------------------------------------------------------
# facts taken from SKILL.md
# ---------------------------------------------------------------------------------------------------------------
def skill_facts():
    text = read(SKILL_MD)
    meanings = {}
    for m in re.finditer(r"^\| (K1|K2|K3|G1|P1|P2|P3|M1|H1, H2, H3) \| (high|medium|low) \| (.+) \|$", text, re.M):
        for cid in m.group(1).split(", "):
            meanings[cid] = m.group(3)
    cmds = {}
    block = re.search(r"## Export commands.*?```sh\n(.*?)```", text, re.S).group(1)
    for line in block.splitlines():
        m = re.search(r"<IN\.(\w+)>", line)
        if m:
            cmds[m.group(1)] = line.strip()
    m = re.search(r"Always these five lines: (.+?)\.\n", text)
    cannot = [s.strip() for s in m.group(1).split(";")]
    cannot = [c[0].upper() + c[1:] for c in cannot]
    return meanings, cmds, cannot


def primary(findings):
    return [f for f in findings if "companion_of" not in f]


def merged_rows(findings, meanings, name=lambda f: f.replace("\\", "/")):
    """One row per (file, sha256, length): K1 and K2 on the same value are one secret. `name` gives the file as the row
    names it."""
    order, rows = [], {}
    for f in sorted(primary(findings), key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["severity"]]):
        key = (f["file"], f["sha256_prefix"], f["length"])
        if key not in rows:
            rows[key] = {"sev": f["severity"], "classes": [], "tags": set(), "file": f["file"], "where": []}
            order.append(key)
        r = rows[key]
        if f["class"] not in r["classes"]:
            r["classes"].append(f["class"])
        r["tags"].update(f.get("tags", []))
        where = "%s, %s" % (f["carrier"], f["location"])
        if f["node_id"] is not None:
            where += ", node %s" % f["node_id"]
        if f["bypassed"]:
            where += ", bypassed"
        if where not in r["where"]:
            r["where"].append(where)
    out = []
    for key in order:
        r = rows[key]
        cls = " + ".join(r["classes"] + sorted(r["tags"]))
        meaning = "; ".join(meanings[c] for c in r["classes"])
        out.append("| %s | %s | %s | `%s` | %s |" % (r["sev"], cls, meaning, name(r["file"]),
                                                    "; ".join("`%s`" % w for w in r["where"][:1])))
    return out


# ---------------------------------------------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------------------------------------------
def build(work):
    """Run everything inside `work` (an empty folder). Returns {file name: text}."""
    if not (shutil.which("ffmpeg") and shutil.which("ffprobe")):
        raise NeedsFfmpeg()
    meanings, export_cmds, cannot = skill_facts()
    out = {}

    # ---------------- sample_report.* ----------------
    code, text = run([sys.executable, "-I", "-B", MAKE_DEMO, "demo"], work)
    if code != 0 or not os.path.exists(os.path.join(work, "demo", "05_mp4_prompt_tag_and_free_box.mp4")):
        raise NeedsFfmpeg()
    code_a, out_a = scan(work, "demo", "--json", "demo_report.json")
    code_b, out_b = scan(work, os.path.join("demo", "04_clean.png"))
    code_x, out_x = run(["ffmpeg", "-loglevel", "error", "-n", "-i", os.path.join("demo", "05_mp4_prompt_tag_and_free_box.mp4"),
                         "-map_metadata", "-1", "-map_chapters", "-1", "-c", "copy", "demo_copy.mp4"], work)
    assert code_x == 0 and not out_x.strip(), "ffmpeg export failed or printed something: " + out_x
    code_c, out_c = scan(work, "demo_copy.mp4")
    report_json = read(os.path.join(work, "demo_report.json"))
    out["sample_report.json"] = report_json

    md = ["# Sample report",
          "",
          "Real output of `scripts/scan.py` " + scanner_version() + " on the six demo files that `scripts/make_demo.py` writes. Nothing here was edited. "
          "Every secret in the demo files is invented, and the report shows none of them. `sample_report.json` is the "
          "`--json` file written by the first command.",
          "",
          "Commands, run from a folder you can write to that is not the skill folder (`<SKILL_DIR>` is the skill folder; the names `demo` and "
          "`demo_report.json` are written into the folder you run them in):",
          "",
          fence('python -I -B "<SKILL_DIR>/scripts/make_demo.py" demo\npython -I -B "<SKILL_DIR>/scripts/scan.py" demo --json demo_report.json', "sh"),
          "",
          "### 1. The demo folder (exit %d)" % code_a,
          "",
          fence(out_a),
          "",
          "How to read it: each `[HIGH]`, `[MEDIUM]` or `[LOW]` line is one finding. `K1+H1` is a vendor key held by a bypassed node; "
          "`K3+H3` is a webhook inside a compressed PNG chunk. The `1 unrecognized file(s) skipped` in the summary line is "
          "`DEMO_EXPECTED.md`, named under `NOTES` as `skipped_other`. Under `NOTES`, `embedded_comfyui_api_json` and `embedded_comfyui_ui_json` say a ComfyUI graph is in the PNG; "
          "that is not a finding by itself. Every class, location form and code is explained in `references/reading-the-report.md`.",
          "",
          "### 2. The one PNG with only an ordinary prompt, scanned alone (exit %d)" % code_b,
          "",
          fence('python -I -B "<SKILL_DIR>/scripts/scan.py" demo/04_clean.png', "sh"),
          "",
          fence(out_b),
          "",
          "### 3. The re-scan loop: export a copy without the metadata, scan the copy (exit %d)" % code_c,
          "",
          fence('ffmpeg -loglevel error -n -i "demo/05_mp4_prompt_tag_and_free_box.mp4" -map_metadata -1 -map_chapters -1 -c copy "demo_copy.mp4"\n'
                'python -I -B "<SKILL_DIR>/scripts/scan.py" demo_copy.mp4', "sh"),
          "",
          fence(out_c),
          "",
          "The copy was made by ffmpeg, a different program from the scanner, so the second scan is a real check. "
          "\"Nothing found\" is not a guarantee: see `references/known-misses.md`.",
          ""]
    out["sample_report.md"] = "\n".join(md)

    # ---------------- example_session.md ----------------
    # Every command line starts with `cd ~; ` and gives every path in full ("Where to run them" in SKILL.md). It runs from
    # `home`, an empty folder that stands for the home folder; `project` is the user's folder that holds renders/.
    home = os.path.join(work, "home")
    project = os.path.join(work, "project")
    if not printed_as_is(project):
        raise NeedsPlainTemp()
    os.makedirs(home)
    shutil.copytree(os.path.join(work, "demo"), os.path.join(project, "renders"))

    def shown(text):
        """The scanner's real output, with the project folder's real path written <PROJECT>."""
        return text.replace(project, PROJECT)

    def rel(path):
        """A file of a report, named as the assistant names it to the user: relative to the project folder (every command
        gives the scanner <PROJECT>/..., so every file of a report starts with the project folder and a slash)."""
        assert path.startswith(project + "/"), path
        return path[len(project) + 1:].replace("\\", "/")

    S = []
    S += ["# Example session",
          "",
          "A worked example of an agent following `SKILL.md`, start to finish. The commands and the scanner output are real runs of the scripts "
          "in this package on the demo files. The skill folder is written `<SKILL_DIR>`, and the full path of the user's project folder (the "
          "folder that holds `renders/`) is written `%s`, in the commands and in the output. Every command starts with `cd ~;` and gives "
          "every path in full, as \"Where to run them\" in `SKILL.md` says; each was run from an empty folder that stood for the home folder. "
          "The assistant's lines were written to follow `SKILL.md` and are filled with the real numbers; this is a worked example, not a "
          "recording of a model." % PROJECT,
          "",
          "---", "",
          "**User:** I'm going to post the six renders in `renders/` on a forum, one at a time. Can you check them first?", ""]

    # act 1
    version_line = HOME + "python --version"
    scan1 = HOME + 'python -I -B "<SKILL_DIR>/scripts/scan.py" "%s/renders" --json "%s/share-safe-report.json"' % (PROJECT, PROJECT)
    _, pyv = run_line(version_line, home, project)
    code1, out1 = run_line(scan1, home, project)
    assert project + "/renders" in out1, "the scanner did not print the paths it was given: " + out1[:300]
    out1 = shown(out1)
    doc1 = json.loads(read(os.path.join(project, "share-safe-report.json")))
    sm = doc1["summary"]
    prim = primary(doc1["findings"])
    sev = {k: sum(1 for f in prim if f["severity"] == k) for k in ("high", "medium", "low")}
    nfiles_notes = len(set(i["file"] for i in doc1["info"] if i["code"].startswith("embedded_comfyui")))
    S += ["**Assistant:** The folder is `renders/` in your project folder, `%s/renders` (step 1). Only the renders will be posted, not the "
          "whole folder, so I will not use `--strict`. I'll run every command from your home folder with every path in full (\"Where to run "
          "them\"), check Python first, then scan the folder and write the report next to it, not inside it (step 2)." % PROJECT, "",
          fence(version_line, "sh"), "", fence(pyv.strip()), "",
          fence(scan1, "sh"), "",
          "Exit code: **%d**. I'm reading the printed report, not the files themselves (step 3). The JSON report is "
          "`%s/share-safe-report.json`; it stays there." % (code1, PROJECT), "",
          fence(out1), "",
          "**Assistant:**", "",
          "**Verdict.** Do not share these files as they are: %d finding(s) in %d of %d file(s) (%d high, %d medium, %d low)."
          % (sm["findings"], sm["files_with_findings"], sm["files_scanned"], sev["high"], sev["medium"], sev["low"]), "",
          "**Findings** (same value in two places is one secret, so those rows are merged)", "",
          "| Severity | Class | Meaning | File | Where |", "| --- | --- | --- | --- | --- |"]
    S += merged_rows(doc1["findings"], meanings, name=rel)
    skipped_names = sorted(rel(i["file"]) for i in doc1["info"] if i["code"] == "skipped_other")
    S += ["",
          "%d PNG file(s) carry an embedded ComfyUI workflow. The prompt text, model names, seeds and node layout travel with the file although "
          "they are not findings." % nfiles_notes,
          "The scanner did not examine %d file(s) in the folder because they are not renders: %s." % (len(skipped_names), ", ".join("`%s`" % n for n in skipped_names)), "",
          "**How to fix**", "",
          "1. Export a copy of each flagged file without its metadata, into a new folder (the originals stay untouched). Every file name here is plain "
          "(letters, digits, `_` and `.`), so the commands can be built from them; a file whose name is not plain would get no command, only a request to rename it "
          "(\"Names in commands\" in `SKILL.md`):", ""]
    flagged = sorted(set(rel(f["file"]) for f in prim))
    mkdir_line = HOME + 'mkdir "%s/reexported"' % PROJECT
    ex_lines = []
    for flagged_name in flagged:
        ext = flagged_name.rsplit(".", 1)[1].lower()
        name = flagged_name.split("/")[-1]
        ex_lines.append(HOME + export_cmds[ext].replace("<IN.%s>" % ext, PROJECT + "/" + flagged_name)
                        .replace("<OUT.%s>" % ext, PROJECT + "/reexported/" + name))
    scan2 = HOME + 'python -I -B "<SKILL_DIR>/scripts/scan.py" "%s/reexported" --json "%s/share-safe-report-2.json"' % (PROJECT, PROJECT)
    S += [fence("\n".join([mkdir_line] + ex_lines), "sh"), "",
          "2. Run those and tell me when the %d copies exist. I will then scan them (`%s`) "
          "and check that the number of files scanned is %d." % (len(flagged), scan2, len(flagged)),
          "3. The files with a key or webhook finding (K1, K2, K3): if they were ever posted or sent before, treat that key or webhook as exposed and "
          "revoke it at the provider. Removing metadata does not take it back.", "",
          "**What this scan cannot see**", ""]
    S += ["- " + c for c in cannot]
    i1 = max(j for j, x in enumerate(S) if x.startswith("**Verdict.**"))
    first_report = "\n".join(S[i1:])
    S += ["", "---", ""]

    # act 2
    S += ["**User:** Please run those exports into a folder called `reexported` and check the result.", ""]
    for line in [mkdir_line] + ex_lines:
        c, o = run_line(line, home, project)
        assert c == 0 and not o.strip(), "export failed or printed something: %s" % o
    code2, out2 = run_line(scan2, home, project)
    out2 = shown(out2)
    doc2 = json.loads(read(os.path.join(project, "share-safe-report-2.json")))
    n_scanned = doc2["summary"]["files_scanned"]
    assert n_scanned == len(flagged), "the example must scan as many copies as were made"
    S += ["**Assistant:** You asked for the exports, so I'll run them, writing only to new names in `reexported/` (step 5). Each ffmpeg command exited 0 and printed nothing.", "",
          fence("\n".join([mkdir_line] + ex_lines), "sh"), "",
          "Now the scan of the copies, with a new report name outside the copies folder:", "",
          fence(scan2, "sh"), "",
          "Exit code: **%d**. The JSON report is `%s/share-safe-report-2.json`; it stays there." % (code2, PROJECT), "", fence(out2), "",
          "**Assistant:**", "",
          "**Verdict.** Nothing found in %d file(s) scanned. That is not a guarantee." % n_scanned, "",
          "**Findings.** None.", "",
          "**How to fix.** %d copies were made and %d were scanned, so every copy was checked. Nothing found in what was scanned; whether to share is your decision. "
          "`04_clean.png` was not re-exported and still carries its embedded ComfyUI prompt. Keep the originals private, and revoke any key or webhook that was in a file you have already shared." % (len(flagged), n_scanned), "",
          "**What this scan cannot see**", ""]
    S += ["- " + c for c in cannot]
    S += ["", "---", ""]

    # act 3
    extras = os.path.join(project, "extras")
    os.makedirs(extras)
    with open(os.path.join(work, "demo", "04_clean.png"), "rb") as fh:
        cut = fh.read()
    with open(os.path.join(extras, "render_cut.png"), "wb") as fh:
        fh.write(cut[: int(len(cut) * 0.6)])
    with open(os.path.join(extras, "loop.webp"), "wb") as fh:
        fh.write(b"RIFF" + struct.pack("<I", 26) + b"WEBPVP8L" + bytes(18))
    with open(os.path.join(extras, "notes.txt"), "wb") as fh:
        fh.write(b"synthetic notes file\n")
    scan3 = HOME + 'python -I -B "<SKILL_DIR>/scripts/scan.py" "%s/extras" --strict --json "%s/share-safe-report-3.json"' % (PROJECT, PROJECT)
    code3, out3 = run_line(scan3, home, project)
    out3 = shown(out3)
    doc3 = json.loads(read(os.path.join(project, "share-safe-report-3.json")))
    S += ["**User:** One more folder, `extras/`. I want to zip the whole thing and send it.", "",
          "**Assistant:** The whole folder will be shared, so I'll add `--strict` (step 2): links and files that are not renders must not be skipped silently. "
          "The report goes next to the folder, with a new name.", "",
          fence(scan3, "sh"), "",
          "Exit code: **%d**. The JSON report is `%s/share-safe-report-3.json`; it stays there." % (code3, PROJECT), "", fence(out3), "",
          "**Assistant:**", "",
          "**Verdict.** Could not scan everything, and found nothing in what could be read. Treat these files as NOT checked.", "",
          "**Findings.** None were found in what could be read, which is not the same as none present:", ""]
    skipped3 = [rel(i["file"]) for i in doc3["info"] if i["code"] == "skipped_other"]
    for e in doc3["errors"]:
        if e["code"] == "unsupported_media":
            S.append("- `%s` (`unsupported_media`): the scanner does not open this format. Export a still as JPEG, or a video as MP4, from the program that made it and scan that, or leave it unchecked." % rel(e["file"]))
        elif e["code"] == "png_truncated":
            S.append("- `%s` (`png_truncated`): the file ends early, so part of it was not read. Re-export or re-copy it." % rel(e["file"]))
        elif e["code"] == "strict_skipped_entries":
            S.append("- (`strict_skipped_entries`): with `--strict`, %d file(s) that are not renders count as not examined; `NOTES` names them: %s. Move them out of the folder or scan without `--strict`; either way they were not examined."
                     % (doc3["summary"]["skipped_unrecognized"], ", ".join("`%s`" % n for n in skipped3)))
        else:
            raise AssertionError("unexpected code " + e["code"])
    embedded3 = sorted(set(rel(i["file"]) for i in doc3["info"] if i["code"].startswith("embedded_comfyui")))
    S += ["", "%d PNG file(s) carry an embedded ComfyUI workflow (%s). The prompt text, model names, seeds and node layout travel with the file although "
          "they are not findings." % (len(embedded3), ", ".join("`%s`" % n for n in embedded3)), "",
          "**How to fix.** Replace or re-export the files above, put them in the folder, and run the same command again with a new report name. "
          "Do not describe `extras/` as checked until that run exits 0.", "",
          "**What this scan cannot see**", ""]
    S += ["- " + c for c in cannot]
    S += [""]
    session = "\n".join(S)
    for real in (work, os.path.realpath(work)):
        assert real not in session, "a real path of this machine is left in the session"
    out["example_session.md"] = session

    # ---------------- the listing's "see it in action" pair (same run as act 1) ----------------
    out["listing/demo_request.md"] = (
        "I'm going to post the six renders in `renders/` on a forum, one at a time. Can you check them first? "
        "(The folder holds the six demo files from `scripts/make_demo.py`, and the page `DEMO_EXPECTED.md` that comes with them.)\n")
    out["listing/demo_result.md"] = (
        "_Demo files: the six synthetic files that `scripts/make_demo.py` writes into `renders/` (invented keys, an invented webhook, a made-up "
        "user name, address and coordinates). The numbers, places and hashes below are the scanner's real, unedited output (`scan.py` "
        + scanner_version() + "); the layout is the one `SKILL.md` prescribes. Nothing was sent or published, and no file was changed._\n\n"
        + first_report + "\n")
    return out


def main(argv):
    dest = argv[1] if len(argv) > 1 else os.path.join(PKG, "examples")
    with tempfile.TemporaryDirectory(prefix="ssrtest_examples_") as td:
        try:
            files = build(td)
        except NeedsFfmpeg:
            sys.stderr.write("make_examples.py: ffmpeg and ffprobe are needed on PATH\n")
            return 3
        except NeedsPlainTemp:
            sys.stderr.write("make_examples.py: the scanner does not print this temp folder's path as it is (a part over 40 "
                             "characters, or a character it escapes); set TMP, TEMP or TMPDIR to a short plain folder\n")
            return 3
    os.makedirs(dest, exist_ok=True)
    for name, text in files.items():
        if name.startswith("listing/"):
            target = os.path.join(LISTING, name.split("/", 1)[1])
            os.makedirs(os.path.dirname(target), exist_ok=True)
        else:
            target = os.path.join(dest, name)
        with open(target, "wb") as fh:
            fh.write(text.encode("utf-8"))
        print("wrote", target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
