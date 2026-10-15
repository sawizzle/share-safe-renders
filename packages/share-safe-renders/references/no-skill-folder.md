# No skill folder: run the scanner from text

Read this only when the skill reached you as text and nothing was installed: the files came as `### File: share-safe-renders/<path>` blocks in a saved response file or in the message, and there is no `share-safe-renders` folder on disk, so `<SKILL_DIR>` in `SKILL.md` points at nothing. If the folder exists, ignore this file.

Write only the files your task needs into a fresh folder in the system temp folder, run them from there exactly as `SKILL.md` says, and delete the folder when you are done. Do not write files the task does not need, do not cut a script out of the response with other tools, and do not retype a script.

## 1. The files each task needs

Neither script imports the other or any other file of the skill, and neither opens a file of the skill while it runs: `scan.py` reads only the paths you pass it and writes only the `--json` report you name (with its temporary file beside it), and `make_demo.py` writes only the folder you name. Each set below was run alone in an otherwise empty folder, with the layout `scripts/<file>`. Size is what you would have to write.

| Task | Script to run | Files to write (in `scripts/`) | Size |
| --- | --- | --- | --- |
| Check renders, workflow JSON or a folder for leaks, and re-scan the re-exported copies (steps 2 and 5 of `SKILL.md`) | `scan.py` | `scan.py` | 145 KB |
| Make the six demo files and scan them (Try it in `README.md`) | `make_demo.py`, `scan.py` | `make_demo.py`, `scan.py` | 171 KB |

The references, the examples and `README.md` are never needed on disk: when `SKILL.md` sends you to one of them (for example `references/reading-the-report.md` or `references/how-to-export-clean.md`), read its block in the response. Run `make_demo.py` from its file, not from standard input: its last line names the `scan.py` next to it.

## 2. Write the files

You need the path of the saved response file and the names from section 1, written as `scripts/scan.py`; pass every name the task needs in one run. That path goes into a command, so it follows "Names in commands" in `SKILL.md` like any other path. The snippet splits the response on its `### File: ` lines and takes each file from between the first and the last fence line of its block, so fenced code inside a markdown file and a last block with no final newline are handled. If a `### File: ` line of the response comes right after a Windows line end (CR LF), every CR LF in the response is turned into a plain line end first; every file of this skill uses plain line ends. It writes nothing, and says why, when the second argument is not `new`, when a name you asked for is not a file name of the skill, when the file holds no blocks, when a name you asked for has no complete block, when two blocks have the same name, or when a block belongs to another skill. A missing or unreadable response file gives a Python error message instead of a stated reason, and nothing is written. Otherwise it writes the names into a new folder that `tempfile.mkdtemp` makes in the system temp folder (on Linux and other POSIX systems only your user can open it), and into no other folder.

```python
import re, sys, tempfile
from pathlib import Path
if len(sys.argv) < 4 or sys.argv[2] != "new":
    sys.exit("usage: python -I -B - RESPONSE new NAME...  (the second argument is always new)")
response, names = sys.argv[1], sys.argv[3:]
for name in names:
    if not re.fullmatch(r"(scripts|references|examples)/[A-Za-z0-9_][A-Za-z0-9_.-]*", name):
        sys.exit("not a file name of the skill: " + name)
text = open(response, encoding="utf-8", newline="").read()
if "\r\n### File: " in text:
    text = text.replace("\r\n", "\n")
parts = re.split(r"(?m)^### File: ", text)[1:]
if not parts:
    sys.exit("no file blocks in this file: it is not a saved response with the skill as text")
files = {}
for part in parts:
    head, _, body = part.partition("\n")
    skill, _, name = head.strip().partition("/")
    if skill != "share-safe-renders":
        sys.exit("a block that is not from share-safe-renders: " + ascii(head[:80]))
    if name in files:
        sys.exit("two blocks for: " + ascii(name))
    block = re.fullmatch(r"\s*(\x60{3,})[^\n]*\n(.*)\n\1\s*", body, re.S)
    files[name] = block.group(2) if block else None
missing = [name for name in names if files.get(name) is None]
if missing:
    sys.exit("no complete block for: " + ", ".join(missing))
folder = Path(tempfile.mkdtemp(prefix="ssr_")).resolve()
for name in names:
    (folder / name).parent.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(files[name].encode("utf-8"))
sys.stdout.reconfigure(errors="backslashreplace")
for name in names:
    print("wrote", (folder / name).as_posix(), len(files[name]), "characters")
print("skill folder:", folder.as_posix())
```

Give the snippet to the interpreter on standard input, with the response path, the word `new` and the names as arguments (use `python3` or `py -3` in place of `python` as `SKILL.md` says). In bash or sh:

```text
python -I -B - "<RESPONSE>" new scripts/scan.py <<'EOF'
<the snippet>
EOF
```

In Windows PowerShell:

```text
@'
<the snippet>
'@ | python -I -B - "<RESPONSE>" new scripts/scan.py
```

Then check the `wrote` lines: `scan.py` is 144,720 characters and `make_demo.py` 26,418. Any other count means a block was not cut where it should be: delete the folder (section 4), tell the user, and stop. The last line, `skill folder: <path>`, names the folder: that folder is `<SKILL_DIR>` for the rest of the task. If the system has no usable temp folder, Python can fall back to the current folder: check that the printed path is not inside the user's project, and if it is, delete that folder and stop.

## 3. Run

Use the commands of `SKILL.md` unchanged, with that folder as `<SKILL_DIR>`, for example the scan of step 2:

```sh
python "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"
```

The report is the same as from an installed folder (`scan.py` uses neither its own path nor its own name): it never prints the leaked text, only the class, the place, the length and a keyed hash, and its exit codes mean what `SKILL.md` says. Do not put `<REPORT>`, the re-exported copies or the demo files in the temporary folder, because it is deleted at the end. A run with `--help` prints `usage: scan.py` when the file is complete; a run that prints no `RESULT:` line is the last row of the exit-code table in `SKILL.md`.

## 4. Delete

When the last scan is done (the re-scan of the copies in step 5 included), delete the folder the snippet printed (its name starts with `ssr_`) with your shell's own command for removing a folder and its contents, with the path in double quotes, and delete nothing else; compare the path with the `skill folder:` line before you run it. The report, the copies and the demo files are in folders the user named and stay there. If a later step needs a file you did not write, run the snippet again with `new` and the names that step needs: it makes another folder, which is `<SKILL_DIR>` from then on, and you delete every folder it printed at the end.

Known issue: on Windows, a user name with accented letters can make the printed path unreadable to an agent that reads the output as UTF-8. The scan commands then exit 2 and nothing wrong runs, but the folder stays behind. `python -I -c "import tempfile; print(ascii(tempfile.gettempdir()))"` prints the temp folder with every such letter written as an escape such as `\xe9`, which you can read and turn back into the real name; delete only the `ssr_` folder the snippet just made, or ask the user to delete that `ssr_` folder in their system temp folder. After any delete, check that the folder is really gone: a delete command can exit 0 on a path it could not read, so a zero exit code proves nothing.

## 5. The response came back inline

If nothing was saved to a file, there is nothing for the snippet to read. `scan.py` is about 145 KB (3,292 lines): it cannot sensibly be copied by hand, and a copy with one wrong character is not the scanner this skill describes, so do not try. Tell the user that the skill arrived only as text in the conversation and nothing has been scanned, and ask them to install it (`README.md`, Install) or to have the response saved to a file, then continue from section 2. Do not fall back to reading the files yourself (rule 1 of `SKILL.md`).
