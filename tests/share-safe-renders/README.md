# Tests for share-safe-renders

Run from the repository root, with the isolated, no-bytecode flags:

```
python -I -B -m unittest discover -s tests/share-safe-renders
```

Everything is generated at run time into temporary folders. No real render, folder, name or credential is read. Fake
credentials are assembled from fragments, so no credential-shaped literal exists in any file here (a test checks that).
Tests that need something that is not in `packages/` or `tests/` skip with a stated reason: `ffmpeg` and `ffprobe` on PATH,
Pillow, PyYAML (it must be importable under `-I`: a PyYAML in the user site is hidden by it, a distribution package such as
`python3-yaml` is not), `tools/agensi_precheck_v3.py` and the folder `listing/share-safe-renders` (20 tests skip without those two,
so put them next to `tests/`, as in the repository), the maintainer-only private deny-list file (3 tests; see "The private-term
checks" below), POSIX-only or Windows-only features, Linux (1 test), and a normal user instead of root (4 tests). A run that skips for a reason that does not apply on that machine has not covered those tests;
the section "Where the suite has been run" says where each ran.

`SSR_SKIP_SLOW=1` skips the corpus run (about 40 seconds). `SSR_FULL_CORPUS=1` builds the full corpus, including the 1 GiB
decompression-bomb probes, instead of the reduced one.

| File | What it covers |
| --- | --- |
| `_base.py`, `_build.py` | paths (the package is `packages/share-safe-renders`), temp folders, builders for tiny synthetic PNG, JPEG and MP4 files, fake secrets |
| `test_classes.py`, `test_contract.py`, `test_fixes.py`, `test_hostile.py` | the scanner itself (every class, the exit codes, the JSON fields, the no-echo rule, hostile and degenerate input), carried over from the prototype |
| `test_release_edits.py` | the first release edits of scan.py 1.2.0 (no environment read of its own, PATH read in one function, no deletion, own percent-decoder, the `--json` guard) and the package rules as static checks |
| `test_audit_fixes.py` | the behaviour changes made after the peer-tester style audit: the MP4 `loci` location box, text in metadata-item children, programs found on PATH only, the verdict line printed twice and honest about exit 2, a report path inside a scanned folder refused, skipped entries named, a WSL path labelled a Windows home. Each has a negative control. |
| `test_audit_docs.py` | the wording fixed by the same audit, checked against the scanner: one vocabulary (no "clean copy"), every path quoted in every command, the step 5 count rule, the exit-code rows, `--` placement, the hash claim, known misses stated in the docs, balanced code fences; the description names only Discord/Slack webhooks and stays under 300 characters; the test counts and the skip figures that the READMEs state, against the run table below; two measured platform sentences (ffmpeg 4.4.2 writes no `iCCP` chunk; `not_found` also covers a path that exists but could not be inspected) |
| `test_package_fixes.py` | a bug found while packaging: HEIC/HEIF/AVIF photos are not reported clean (by major brand, by compatible brand, by a `pict` meta box, by file extension) |
| `test_review_fixes.py` | the fixes that followed an independent adversarial review, each with a control that shows the old behaviour: file names that run code through the export commands (run in Windows PowerShell 5.1 where available), the report's temporary file, keyed hash prefixes, limits that left text unexamined, hex labels, empty folders, the head-to-head figures, and the Windows-spelling cases (extended-length and share paths, a trailing-dot name) |
| `test_demo.py` | `scripts/make_demo.py`: six files, `DEMO_EXPECTED.md` against real scans, refusal to overwrite, no ffmpeg |
| `test_skill_docs.py` | SKILL.md frontmatter and structure, verdict wording against the exit codes, every class and code documented, the "known misses" re-run, the head-to-head numbers copied exactly, overclaim lint |
| `test_doc_commands.py`, `doc_commands.py` | every command written in SKILL.md, README.md and references/ runs as written, in a copy of the package |
| `test_shell_quoting.py` | the command text from SKILL.md (the scan command and the ffmpeg export commands) run through PowerShell and cmd (Windows) or sh (macOS, Linux) with spaces in every path, a file name with `$(...)` in it, and the trailing-backslash trap |
| `test_export_claims.py` | the export methods in `references/how-to-export-clean.md`, each re-scanned, with the controls that must still leak (an animated PNG, a still WebP, an MP4 with extra tracks, ffmpeg echoing tags). Where the doc says the result depends on the ffmpeg build (a PNG with EXIF, a still WebP to PNG, the `-n` exit code, the exit code of an animated PNG), the test compares this machine's ffmpeg with the doc's per-build table. Measured on ffmpeg 5.1, 7.1, 8.1.1 and 9.0.1 (Windows); run it with each build first on PATH (see below). It also runs on the Linux builds (4.4.2, 5.1.9, 6.1.1, 8.0.1): a build the doc's table does not list is checked only for what holds on every build, and two tests skip on 4.4.2 with the reason stated (a plain MP4 made by it has no stream-level `encoder` tag, so there is nothing to drop; it writes no `iCCP` chunk into a PNG). Where the result depends on the Pillow version (a plain save keeps a PNG's `eXIf` chunk up to 9.3.0, a JPEG's `COM` comment from 9.4.0 and a JPEG's XMP packet in 11.0.0), the test compares this machine's Pillow with the doc's two tables of Pillow versions (9.0.0 to 12.3.0), runs the documented command on every version whether the tables list it or not, and skips the table comparison with the version named for a Pillow the tables do not list. The 23 versions, their ranges, every cell of the two tables, the two printed lines of the command and the three status rows that cite the tables are also pinned as plain data in the test file, so a version, a range or a result cannot change in the doc alone. |
| `test_examples.py`, `make_examples.py` | the committed examples are regenerated from real runs and compared; the example session follows SKILL.md |
| `test_listing.py` | the listing text: fields, honesty, test count, release checklist, demo, and the changelog's account of the description change and of the documentation changes |
| `test_package_hygiene.py` | no credential-shaped literal, no e-mail address or home path of a person, only the publisher handle in the repository address, text-only package, zip layout, the Agensi precheck; and the private-term checks (below): the mechanism on a synthetic list in every checkout, the real list only where the maintainer-only file exists |
| `test_corpus_score.py`, `corpus/`, `eval/` | the scanner against the synthetic answer-key corpus, and the head-to-head harness and report |
| `test_v101_no_skill_folder.py`, `get_skill_sim.py` | package release 1.0.1 (documentation and tests only: scan.py and make_demo.py are the files of 1.0, byte for byte, pinned by their SHA-256): `references/no-skill-folder.md` for an agent that received the skill as text with no skill folder. The file sets in its table are derived from the code (imports, files opened, use of its own path or name); each set is copied alone into an empty folder whose path has spaces and run on synthetic renders, with the installed package's report as the expected result, and leaving any file out fails. The snippet is taken out of the document verbatim and run against simulated answers built by `get_skill_sim.py` (every file byte for byte; plain fences inside markdown, a last block with no final newline, a CRLF file, an answer saved with CRLF line ends; duplicate blocks, another skill's blocks, missing names and bad names are refused; it takes no folder: any second argument other than `new` is refused, and every run makes a fresh folder of its own in the temp folder). Broken copies of the snippet must fail. The public-checkout skip figures below are measured: the four modules that read `listing/`, `tools/` or the deny-list file are run in a copy without them. One test reads `listing/` and skips without it. |

`get_skill_sim.py` writes a text file shaped like an answer that returns a skill as text (`SKILL.md` inline, then one `### File: ` block per file), for any package folder:
`python -I tests/share-safe-renders/get_skill_sim.py packages/share-safe-renders out.txt` (the output file must not be inside the package folder).

## The private-term checks

`test_package_hygiene.py` also checks every text file of the package, the tests and the listing against a list of private terms (a
person's name, the names of studios and projects, the names of other products). That list is not published, in clear or as hashes. It is
read from `tests/share-safe-renders/_private_denylist.json`, a file that exists only in the maintainer's checkout and must be listed in
`.gitignore`. Without it, the 3 tests that use it skip with the reason "the maintainer-only private deny-list file is not in this
checkout", and every other check in that module still runs. The mechanism itself is tested in every checkout, against a synthetic list
built inside the tests: a text that holds a listed word, phrase or name is caught, and a text that does not is passed.

The file is UTF-8 JSON. Each of these keys holds a non-empty list of strings (a missing or empty list is an error, not a skip, because it
would make the checks pass without checking anything): `unigram_hashes` and `bigram_hashes` (the first 16 hex digits of the SHA-256 of a
lower-case word, or of two neighbouring lower-case words joined by one space; a word is a run of letters and digits),
`unigram_control_words` and `bigram_control_words` (clear-text words whose hashes must be in those two lists, which shows that the lists
are alive) and `forbidden_products` (names that must not appear in any text file, in any case, as plain substrings). A key `note` may hold
free text. This file holds private terms in clear text: never commit, zip or publish it.

## Where the suite has been run

The suite has 658 tests. Each row is one run of `python -I -B -m unittest discover -s tests/share-safe-renders -v` on this tree,
with `listing/`, `tools/` and the private deny-list file next to or inside `tests/`; every run passed (no failure, no error). Skipped tests report their reason with `-v`.
Windows 11 is the author's machine; the Linux rows are Docker containers on it (x86-64) with each distribution's own packages.

| Machine | ffmpeg | Python | Pillow | PyYAML | Skipped |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | 8.1.1 | 3.14.6 | 12.3.0 | hidden by `-I` | 17 |
| Windows 11 | 9.0.1 | 3.14.6 | 12.3.0 | hidden by `-I` | 17 |
| Windows 11 | 7.1 (ffprobe 8.1.1) | 3.14.6 | 12.3.0 | hidden by `-I` | 17 |
| Windows 11 | 5.1 | 3.14.6 | 12.3.0 | hidden by `-I` | 17 |
| Windows 11 | 8.1.1 | 3.12.11 | 12.2.0 | 6.0.3 | 16 |
| Windows 11 | 8.1.1 | 3.9.25, 3.10.21, 3.11.15, 3.13.13 | none | none | 33 each |
| Ubuntu 22.04, root | 4.4.2 | 3.10.12 | 9.0.1 | 5.4.1 | 26 |
| Debian 12, root | 5.1.9 | 3.11.2 | 9.4.0 | 6.0 | 24 |
| Ubuntu 24.04, root | 6.1.1 | 3.12.3 | 10.2.0 | 6.0.1 | 24 |
| Ubuntu 26.04, root | 8.0.1 | 3.14.4 | 12.1.1 | 6.0.3 | 24 |
| Ubuntu 24.04, normal user | 6.1.1 | 3.12.3 | 10.2.0 | 6.0.1 | 20 |
| Ubuntu 22.04, root, no Pillow and no PyYAML | 4.4.2 | 3.10.12 | none | none | 42 |

A checkout of the public repository has only `packages/` and `tests/`: no `listing/`, no `tools/` and no private deny-list file. In it the same
runs skip 23 more tests: 18 listing tests (16 in `test_listing.py`, 1 in `test_audit_docs.py`, 1 in `test_v101_no_skill_folder.py`) and 2 precheck tests because `listing/` and `tools/`
are missing, and 3 private-term tests because the deny-list file is missing. Measured in a copy of this tree with those three removed: Windows 11 with
Python 3.14.6 and ffmpeg 8.1.1 skipped 40 (17 + 23), Ubuntu 22.04 as root 49 (26 + 23) and Ubuntu 26.04 as root 47 (24 + 23); nothing failed, and the
three private-term tests gave the stated reason.

Taken together, each of the 658 tests ran and passed in at least one of these 15 runs, and none failed in any of them. What does
not run where:

- Windows, Python 3.14.6 (17): 6 named-pipe tests, 1 undecodable-file-name test, 2 `sh` tests and 1 test of a POSIX folder whose name
  holds a backslash need POSIX; 4 tests of unreadable files and folders need a normal user on POSIX (`chmod 000` does not lock a
  file on Windows); 1 test pins CPUs and needs Linux; 1 PATH test needs a stand-in executable script; 1 YAML test needs PyYAML,
  which `-I` hides there.
- Linux as root (24, or 26 on ffmpeg 4.4.2): 20 tests need Windows (PowerShell 5.1, `cmd`, the `py` launcher, Windows spellings of
  paths, reserved and trailing-dot names, the Windows lookup order of the current folder); 4 need a normal user instead of root, and
  they ran in the Ubuntu 24.04 run as a normal user (20 skipped there, all of them the Windows ones). On ffmpeg 4.4.2 two more skip:
  the demo MP4 has no stream-level `encoder` tag to drop, and the PNG has no `iCCP` chunk.
- Windows Pythons with no Pillow and no PyYAML (33 = the 17 above plus 16 tests that need Pillow; the test that needs PyYAML is
  among the 17): the Pillow tests ran on the Windows default Python (Pillow 12.3.0, found by a child process because `-I` hides
  the user site), on 3.12.11 and on the Linux runs; the PyYAML test ran on 3.12.11 and on the Linux runs.

macOS was not run, nor any Linux other than the four above, nor an architecture other than x86-64. The Windows rows use the four `ffmpeg`
builds that the doc's per-build table lists; the Linux builds are not in it, so their cells are not compared (see the
`test_export_claims.py` row). To cover every
test on a Debian-style machine: `apt install ffmpeg python3 python3-pil python3-yaml`, copy `listing/` and `tools/` next to
`tests/`, run the suite once as root and once as a normal user.

To run the ffmpeg-dependent modules against another build, put its folder first on PATH, for example in a POSIX-style shell
`PATH="/path/to/ffmpeg-5.1:$PATH" python -I -B -m unittest discover -s tests/share-safe-renders -p "test_export_claims.py"`, or in
PowerShell `$env:PATH = "C:\path\to\ffmpeg-5.1;" + $env:PATH`. A folder that holds only `ffmpeg` (no `ffprobe`) falls back to the ffprobe
that comes next on PATH.

To regenerate the examples after a change: `python -I -B tests/share-safe-renders/make_examples.py`. The tests then compare
a fresh run with the committed files.
