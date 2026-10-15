# share-safe-renders

A free skill that finds what a render leaks before you share it. One scanner, `scripts/scan.py`, opens PNG, JPEG, MP4/MOV and workflow
JSON files and reports API keys, secret-named fields, Discord and Slack webhook URLs, user names inside home-folder paths, e-mail
addresses, LAN addresses, GPS coordinates, and secrets hidden where a text search does not look: in bypassed ComfyUI nodes, in
JSON stored inside a string, in compressed PNG chunks and in hidden MP4 boxes.

It only reads the files you give it: it never edits, moves or deletes them, and the one file it writes is the JSON report you name. Its report never prints the text it found, only the class, the place, the
length and a short hash. That makes the report safe to hand to an AI agent: a file's metadata cannot put instructions into it. (The one text that comes from outside
the scanner is a file's own name; the printed report escapes it and shortens each path part over 40 characters, and the JSON report keeps names exact and marks them untrusted.
The length is exact. The hash prefix is a keyed hash (HMAC-SHA-256 with a random key made for each run and never stored), so the same value has the same prefix everywhere in one report, but a guess cannot be checked against a prefix, and the prefixes of two reports cannot be compared. A short value such as a user name still has its length in the report: share a report only with people who may know the values.)
The skill tells you how to export a copy without the metadata (commands that were run on the demo files are in
`references/how-to-export-clean.md`) and how to check the copy by scanning it again. The scrubbing is done by other tools, so the check is not circular.
An agent pastes a file name into a command only if the name is plain (ASCII letters, digits, spaces and `. _ ( ) + -`), and only if the folder you name has no `"`, `$`, backtick, `%`, `!` or typographic double quote in it: a shell can run text in a name, and typographic quotes defeat the quoting in Windows PowerShell 5.1. Any other name is not pasted; you copy or rename the file, or move it to a plain-named folder, first.

## Quick start

1. Copy this folder into your agent's skills folder (see "Install" below) and ask: "check these renders before I post them".
2. Or run it by hand: "Try it" below makes six demo files with invented secrets and scans them (exit 1), then scans the clean one (exit 0).
3. The last line of a report is the verdict (exit 2 prints a usage message instead), and the exit code says the same: 0 nothing found, 1 something found, 2 the command was wrong, 3 something could not be scanned. "Nothing found" is not a guarantee.

## What it can tell you

- Which files carry a vendor-shaped key (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face), a value under a secret-looking field name, or a webhook URL.
- Where it sits: file, container, ComfyUI node id, and whether that node was bypassed or muted.
- Which files carry a home-folder path with an account name, an e-mail address, a private-network address, or GPS.
- Which MP4/MOV files carry a tag holding prompt or workflow JSON, or hidden data after the video.
- Which files it could not read. A WebP, GIF, HEIC or damaged file is listed under `COULD NOT FULLY SCAN` and the run exits 3 when nothing else was found (1 if another file has a finding). Links and file types it does not read, met inside a folder, are skipped, counted and named under `NOTES`; the run still exits 0 unless you add `--strict`. A run that scanned no file at all (an empty folder, a folder holding only sub-folders, only links or only unknown types) exits 3. A file it knows it could not read is not reported as clean.

## What it cannot tell you

It does not look at the picture or the sound, and it does not see data hidden in pixels or inside the compressed image or video stream. It does not read C2PA
manifests, WebP, GIF, WebM or HEIC files, or secrets that were split or re-encoded. It does not judge your prompt text. It knows the key formats of eight vendors and the webhook URLs of Discord and Slack only, and
a secret in a field with an ordinary name can be missed. "Nothing found" is not a guarantee. The full list is in `references/known-misses.md`.

## Install

Copy this whole folder (`share-safe-renders`) into your agent's skills folder. For Claude Code that is `~/.claude/skills/` for every project, or `.claude/skills/` inside one project.
Then ask in plain words, for example "check these renders before I post them". `SKILL.md` is the file the agent reads. If your agent does not pick the skill up on its own, say: use the share-safe-renders skill.
If your agent received the skill as text and nothing was installed, there is no folder to copy: `SKILL.md` sends it to `references/no-skill-folder.md`, whose snippet writes
the one file a scan needs (`scripts/scan.py`) into a fresh folder in the system temp folder; the agent runs it from there and deletes that folder afterwards.

You can also run the scanner by hand, without any agent.

## Requirements

- Python 3.9 or newer, standard library only. Nothing is installed or downloaded.
- `ffprobe` in a PATH directory is optional: when present the scanner uses it as a second witness for MP4/MOV tags.
- `ffmpeg` is needed only for the export commands in `references/how-to-export-clean.md`, and for the MP4 in the demo.

Tested: the scripts and the test suite (658 tests) were run on Windows 11 with Python 3.14.6 and ffmpeg and ffprobe 8.1.1, and also with ffmpeg 5.1, 7.1 (its ffprobe is 8.1.1) and 9.0.1, and with Python 3.9.25, 3.10.21, 3.11.15, 3.12.11 and 3.13.13 (ffmpeg 8.1.1). They were also run on Linux x86-64 in Docker containers, as root, with each distribution's own ffmpeg and Python: Ubuntu 22.04 (ffmpeg 4.4.2, Python 3.10.12), Debian 12 (5.1.9, 3.11.2), Ubuntu 24.04 (6.1.1, 3.12.3) and Ubuntu 26.04 (8.0.1, 3.14.4), and once more on Ubuntu 24.04 as a normal user. Every one of these runs passed. A test skips, with a stated reason, where it cannot apply (for example it needs Windows, POSIX, a normal user instead of root, or Pillow): 17 of the 658 skipped on Windows with Python 3.14.6 and 20 to 26 on Linux (with Pillow and PyYAML installed), and each of the 658 ran in at least one of these environments. Those figures are for the author's tree, which also holds a `listing/` folder, a `tools/` folder and one maintainer-only file; the public repository has none of the three, and a checkout of it skips 23 more tests (measured on Windows with Python 3.14.6, on Ubuntu 22.04 and on Ubuntu 26.04; `tests/share-safe-renders/README.md` says which). The export methods behave differently on some builds (`references/how-to-export-clean.md` has the per-build table and says which builds each statement was measured on). Not tested: macOS, other Linux distributions and CPU architectures, other Python versions, other ffmpeg versions, and any agent end to end: the scripts were run directly, and `examples/example_session.md` is
a worked example, not a recording of a model.

## Try it

Do not run these inside the skill folder. Make or pick a folder you can write to (a fresh temporary folder is fine), written `<WORK>` below, and use the full path of the skill folder for `<SKILL_DIR>`. The commands write `demo/`, `demo_report.json` and, for the last step, `demo_copy.mp4` into `<WORK>` and nowhere else. `make_demo.py` refuses to overwrite existing demo files (exit 2): to run it again use a new folder, or add `--overwrite`.

```sh
python "<SKILL_DIR>/scripts/make_demo.py" "<WORK>/demo"
python "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo" --json "<WORK>/demo_report.json"
python "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo/04_clean.png"
```

1. The first command writes six small synthetic files into `demo/` (a fake key and a user-name path in a PNG, a fake webhook in a compressed PNG chunk, a fake key in a bypassed node, a PNG with only an ordinary prompt, an MP4 with a prompt tag and a hidden box, a JPEG with GPS) and `DEMO_EXPECTED.md`, which lists what the scanner should report for each. Every secret is invented and assembled when the script runs.
2. The second scans the folder. It prints the findings and exits with 1; `demo_report.json` holds the same findings as JSON.
3. The third scans the one PNG that has only an ordinary prompt (`04_clean.png`) and exits with 0: nothing found. Its embedded ComfyUI prompt is listed as a note, not a finding.

To see the whole loop, make a copy of the MP4 without its metadata and scan the copy (needs `ffmpeg`):

```sh
ffmpeg -loglevel error -n -i "<WORK>/demo/05_mp4_prompt_tag_and_free_box.mp4" -map_metadata -1 -map_chapters -1 -c copy "<WORK>/demo_copy.mp4"
python "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo_copy.mp4"
```

The second line exits with 0: nothing found in the copy. `examples/sample_report.md` and `examples/sample_report.json` are the real output of the scan above.

On Windows, `py -3` works in place of `python` if `python` is not found. On macOS and Linux use `python3`.

## How it compares

It does not replace `exiftool` or `trufflehog`. `exiftool` shows more tags than this scanner reads, and `trufflehog` has far more vendor secret detectors and can check whether a key is live.
What this adds: it classifies paths, e-mail addresses, LAN addresses, GPS and hidden MP4 boxes; it names the node and says if it was bypassed; it decodes compressed PNG chunks; its report never prints the leaked text; and its exit code does not read a file it knows it could not scan as clean (gaps of that kind were found and fixed while this package was built: HEIC photos, AVIF files with an unusual major brand, an empty folder that exited 0, and text that some limits had left unexamined without saying so: a flood of distinct values of one kind in one text, an MP4 metadata list of more than 4096 entries or a list whose entries do not fit, an EXIF text tag over 1 MiB or a value of a type it cannot read, a PNG chunk far longer than its format allows, a sample table or fixed-layout box whose size does not fit its own count, a location box over 1 MiB).
In a head-to-head on a synthetic corpus, trufflehog skipped PNG, JPEG and MP4 files as shipped and, with workarounds (the strongest combination built from the two tools), flagged 27 of the 68 planted key entries, where the scanner found all 68. Much of that gap is the shape of the corpus, not the file type. Counted by underlying key (the head-to-head report's vendor table, which also counts keys inside bypassed nodes and compressed chunks), it lists 32 OpenAI-legacy keys, of which trufflehog flagged 1 (1 of the corpus's 43 OpenAI-legacy values has the marker trufflehog needs), and 7 lone AWS key ids, of which it flagged none. Excluding OpenAI-legacy values and lone AWS key ids, trufflehog flagged 33 of the 40 remaining effective K1 entries (82%). That count is on the underlying-key basis, so it is not comparable with the 27 of 68. Across all 194 planted entries the scanner found 194, but 91 of those 194 are classes with no detector in trufflehog (values under secret-named fields, paths, e-mail addresses, LAN addresses, GPS and hidden MP4 boxes), so 194 against 27 is not a like-for-like gap. The scanner was built against that corpus, so none of this is an estimate of real-world recall.
The numbers, the exact setup and every caveat are in `references/vs-exiftool-and-trufflehog.md`.

## What is in the folder

| Path | Contents |
| --- | --- |
| `SKILL.md` | The instructions the agent follows: workflow, output format, exit codes, limits. |
| `scripts/scan.py` | The scanner (one file, standard library only). |
| `scripts/make_demo.py` | Writes the six synthetic demo files and `DEMO_EXPECTED.md` into a folder you name (`DEMO_EXPECTED.md` is created by this script: it is not in the zip). |
| `references/reading-the-report.md` | Every class, location form, exit code, error code, and the JSON schema. |
| `references/how-to-export-clean.md` | Export commands per file type, what was verified and what was not, and how to check a copy. |
| `references/what-leaks-and-where.md` | Which containers carry what, in ComfyUI-style PNG and MP4 and in camera JPEG. |
| `references/known-misses.md` | What the scanner does not find. |
| `references/vs-exiftool-and-trufflehog.md` | The comparison, with numbers and caveats. |
| `references/no-skill-folder.md` | For an agent that received the skill as text with no folder: the files each task needs, a snippet that writes them to a temporary folder, and how to delete it. |
| `examples/` | A real sample report (`.md` and `.json`) and a worked example session. |

## Permissions

The scripts read the files and folders you name, and nothing else. They write only the JSON report path you give `scan.py` (plus a temporary file beside it while writing, `<report>.tmp-` and random characters, made so that it can never be an existing file or a link; it is not deleted if writing fails) and the folder you give `make_demo.py`. They read no
environment variable of their own (they do ask the operating system for random numbers: the key of the hash prefix and the name of the temporary file), open no network connection, delete nothing, and start no program except `ffprobe` (optional, `scan.py`) and `ffmpeg` (only to build the demo MP4, `make_demo.py`, skipped
with `--no-mp4`), always with an argument list and never through a shell. To find those two programs they read your PATH and look only in the absolute directories listed on it, never in the current folder (on Windows only `ffprobe.exe` and `ffmpeg.exe` count). `scan.py` refuses to replace an existing file given to `--json` unless it is empty or an earlier report of its own, and refuses a report path inside a folder it is scanning.
If your agent has the skill only as text, the agent itself (not the scripts) reads the saved response file, writes the scripts a task needs (`scripts/scan.py` for a scan) into a temporary folder and deletes that folder afterwards (`references/no-skill-folder.md`).

## Source and tests

The test suite is not part of this package. It is published with the release in the project repository: https://github.com/sawizzle/share-safe-renders. From a checkout of that repository, run `python -I -B -m unittest discover -s tests/share-safe-renders` in its root.

## Licence

This copy, delivered through Agensi, is under Agensi's buyer terms (a personal, non-transferable licence). The same code is published in the public repository named above under MIT OR Apache-2.0, at your option: if you want to use it on a team or at work, use that copy. No warranty. A scan result is information, not a guarantee: check your own files before you rely on it.
