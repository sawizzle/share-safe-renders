# Share-Safe Renders - synthetic test corpus

`make_corpus.py` builds, at run time, a **synthetic** corpus of ComfyUI-style renders (PNG, MP4/MOV, JPEG)
that plants every fault class the "Share-Safe Renders" scanner has to find, plus clean controls,
boundary cases, documented blind spots and hostile files, together with an `answer_key.json` that says exactly
what a correct scanner must (and must not) report.

Nothing here is real. There is no real render, folder, name, e-mail, username, host or credential:

* every fake secret is **assembled from split fragments with a seeded RNG at run time**; no contiguous
  credential-shaped literal exists in `make_corpus.py` or in this README (the builder's self-check scans both),
* the random part of each fake key carries a visible `fxfixture` marker where the alphabet and length allow it,
* identities are obviously invented (`fxuser01`, `fx.user01@...`, `fx-render-02.local`) and every domain used for a
  positive e-mail is fictional and never `example.*`,
* GPS points are in open ocean,
* the builder reads only what it wrote itself (plus its own source and this README for the self-check); subprocesses are
  `ffmpeg`/`ffprobe` and `cmd /c mklink /J` only. No network.

## Build

```
python make_corpus.py OUTDIR            # full corpus (2246 files, 66 MB, 11 to 12 s on Ubuntu 24.04 in Docker, includes the heavy probes)
python make_corpus.py OUTDIR --no-heavy # skip heavy/ (the 20 MB chunks, the 1 GiB bombs, the floods)
python make_corpus.py OUTDIR --force    # rebuild into a directory that already holds a corpus
```

Options: `--seed N` (default 20261012), `--many N` (tiny files in `dirs/many_files`, default 2000),
`--bomb-mib N` (inflated size of the decompression bombs, default 1024), `--no-selfcheck`.

Python 3.9+ standard library only; `ffmpeg` and `ffprobe` on PATH for the MP4/MOV fixtures (without them those
fixtures are skipped and listed under `skipped` in the answer key). OUTDIR must be empty or a previous corpus
(it carries a `.share_safe_corpus_marker` file); `--force` only ever deletes a directory that has that marker,
and removes junctions/symlinks without following them.

Output is byte-for-byte reproducible for a given seed, **Python build and ffmpeg/libx264 build**. The MP4/MOV files
are made by ffmpeg, so another ffmpeg build writes other bytes: of the 287 files of the default test build
(`--no-heavy --many 50`), 35 differ between ubuntu:22.04 (ffmpeg 4.4.2), debian:12 (5.1.9), ubuntu:24.04 (6.1.1) and
ubuntu:26.04 (8.0.1), all of them MP4/MOV content, and `answer_key.json` is the same on all four.

The output does not depend on the number of CPUs. The two small base clips and the 3 MB noise clip are encoded with
`-threads 1` (libx264 otherwise writes the thread count of the machine into the file), and the noise itself is drawn
from the seeded RNG. Measured: that default build, pinned to 1, 8, 15 and 32 CPUs, gave 287 byte-identical files on each
of the four distros above, and the full build (2246 files) was byte-identical at 1 and at 32 CPUs on ubuntu:24.04. The
builder also redraws the noise clip until the encoded file holds no contract-shaped string, so a clip that happens to
contain an e-mail-shaped run never reaches the corpus.

Compressed chunks can differ between interpreters because the zlib behind them differs: the Windows build of Python 3.14.6
ships zlib-ng 2.2.4, and on the same input it wrote other bytes than zlib 1.2.11, 1.2.13, 1.3 and 1.3.1 (the Python 3.10, 3.11,
3.12 and 3.14.4 builds of the four Linux images above, which wrote identical bytes). Between that Windows Python and Ubuntu
26.04, 4 PNG files of the default build differ besides the 35 files with MP4/MOV content (zlib-ng is the likely cause; not isolated further).
The answer key (secrets, locations, hashes) does not change with the interpreter or the machine; only the link kind and note of
two directory-test entries do (junctions on Windows, symlinks on Linux), and the text files are written with CRLF line endings on
Windows. Do not commit a generated corpus: `OUTDIR/never_echo.json` holds the fake
secret values in clear (`.gitignore` here already ignores `_out/` and `out/`).

The build ends with a **self-check**: every planted value is recovered from its file with an independent
decoder (zTXt/iTXt inflate, EXIF GPS parse, raw MP4 bytes), values meant to be compressed are not visible in the
raw bytes, hidden MP4 boxes are invisible to `ffprobe`, well-formed PNG/JPEG decode in ffmpeg and MP4/MOV open in
ffprobe, clean controls contain no contract-shaped string, no file holds an *unplanted* contract-shaped string
(so the answer key is complete), canaries are present, and no file name leaks a never-echo string.

## Folders

| folder | group | exit | what it holds |
|---|---|---|---|
| `pos/` | positive | 1 | one or more planted leaks per file, every class in several carriers and layouts |
| `clean/` | clean | 0 | 43 controls that must produce **zero** findings |
| `boundary/` | boundary | 0 | clean by the literal contract, but a scanner could argue (see Policy) |
| `known_miss/` | known_miss | 0 | documented blind spots; a silent scanner is conformant, a finding is informational |
| `hostile/` | hostile | per file | parser traps and prompt-injection text; must be handled safely |
| `heavy/` | heavy | 1 or 3 | resource-limit probes (about 47 MB): run with a time and memory limit |
| `dirs/` | positive/clean | per test | directory-walk fixtures: nesting, junction and symlink loops, depth, 2000 files |

`dirs/` also contains a few unregistered items described by `dir_tests`: two zero-byte files (`mixed_corrupt/zero.png`,
`only_corrupt/zero.png`), the 2000 tiny files, and the junctions/symlinks.

## Tiers

* **core** - required by the contract.
* **extended** - a reasonable extension (more carriers or spellings, e.g. PNG `eXIf`, XMP GPS, JPEG `COM`,
  bytes after `IEND`, compound key names such as `openai_api_key`, JSON-escaped key names). Missing one is a
  documented gap, not a defect.
* **boundary** - clean by the literal contract; flagging it is a judgement call, not a failure.
* **known_miss** - expected to be silent.

## Classes x carriers (`pos/`, planted instances; from `corpus_matrix.md`)

| class | what | png tEXt | png zTXt | png iTXt | mp4/mov tag | mp4 box | jpeg exif/xmp/com | other |
|---|---|---|---|---|---|---|---|---|
| K1 | vendor keys (OpenAI x3 forms, Anthropic x3, GitHub classic + fine-grained, AWS, Google, Slack x4, Stripe live, Hugging Face) | 22 | - | 8 | 5 | 1 | 1 (COM) | 2 (private chunk, after IEND) |
| K2 | secret-named fields (api_key casings, token, access_token, secret, client_secret, password, authorization, bearer) | 24 | - | 2 | 1 | 2 | - | - |
| K3 | Discord (discord.com, discordapp.com, query string) and Slack webhooks | 5 | - | 1 | 1 | 1 | - | - |
| P1 | Windows, POSIX and macOS home paths | 8 | - | 1 | 1 | - | - | - |
| P2 | e-mail addresses (plus-address, sub-domain, upper-case) | 5 | - | 2 | 1 | 1 | 1 (EXIF) | - |
| P3 | 10/8, 172.16/12 (both edges), 192.168/16, UNC, `.local` `.lan` `.internal` | 6 | - | 3 | 2 | - | - | - |
| G1 | GPS (II and MM byte order, DMS / DM / decimal rationals, altitude IFD, EXIF after XMP) | - | - | - | - | - | 6 EXIF + 1 XMP | 1 (PNG eXIf) |
| H1 | secret in a mode 4 / mode 2 node (positional, named, dict widgets, webhook, subgraph, MP4 `workflow` tag) | 6 | - | - | 1 | - | - | - |
| H2 | JSON in a string in JSON (API input, UI widget, UI properties, whole workflow, 3 levels, iTXt, MP4 tag) | 5 | 1 | 1 | 1 | - | - | - |
| H3 | compressed chunk (zTXt level 0 stored and 9, zTXt after IDAT, iTXt flag 1 with language tags, CJK) | - | 8 | 3 | - | - | - | - |
| M1 | workflow JSON in `comment` `description` `title` `prompt` `workflow` tags; appended `free` `skip` `uuid` boxes (64-bit size too); MOV; moov-first and moov 3 MB into the file | - | - | - | 8 + 1 | 7 | - | - |

Totals of **required** planted instances per class (all folders; `optional` entries excluded), from the
reference run (seed 20261012):

| class | pos core | pos extended | dirs | hostile + heavy | total |
|---|---|---|---|---|---|
| K1 | 29 | 10 | 7 | 22 | 68 |
| K2 | 22 | 7 | 0 | 3 | 32 |
| K3 | 8 | 0 | 0 | 1 | 9 |
| P1 | 8 | 2 | 0 | 1 | 11 |
| P2 | 9 | 1 | 0 | 2 | 12 |
| P3 | 11 | 0 | 0 | 0 | 11 |
| G1 | 5 | 3 | 0 | 0 | 8 |
| H1 | 6 | 1 | 0 | 0 | 7 |
| H2 | 7 | 1 | 0 | 0 | 8 |
| H3 | 11 | 0 | 0 | 1 | 12 |
| M1 | 16 | 0 | 0 | 1 | 17 |

H1/H2/H3 instances plant a K/P secret in a special place; M1 files add the secret inside the hidden JSON as a second
expected finding. "Effective" counts (underlying kind) are in `answer_key.json -> counts`.

The rows count planted instances per class tag, and one entry carries two tags: `pos/H3_zTXt_containing_double_encoded.png` is
a single required entry whose tags are H3 and H2, so it is counted in both the H3 row and the H2 row. The rows therefore add up to
**195**, while the distinct required entries are **194** (checked on a built corpus: 193 distinct entries and rows adding up to 194
without the heavy probes, which add one more K1). The head-to-head report (`eval/H2H_REPORT.md`) counts that entry once, as H3, which
is why it shows H2 = 7 and 194 in total. Nothing else differs between the two tables.

### Layouts exercised

API-format (`{node_id: {class_type, inputs, _meta}}`) in `prompt` chunks; UI-format (`nodes[]`, `widgets_values`)
in `workflow` chunks with names recovered from `inputs[].widget.name` (positional), dict-style
`widgets_values`, `properties`, Note nodes and `extra`; free JSON; A1111-style `parameters` text; env-style and prose
text; pretty-printed and JSON-escaped spellings; secrets in both the prompt and workflow chunk of one file (two
findings); bypassed nodes absent from `prompt` but present in `workflow`; modes 0/1/3 (not bypassed) next to mode 2/4.

Layout variants that catch shortcuts: MP4 with `moov` first (faststart) and with `moov` about 3 MB into the file
(tags and appended boxes that a head-only read misses), a PNG whose only text chunk follows 1.5 MB of IDAT, files whose
extension lies (PNG bytes named `.jpg`, MP4 bytes named `.png`, JPEG bytes named `.png`), `.PNG` upper case, no extension,
a `.jpeg` suffix.

### Clean controls (`clean/`, 43 files)

UUID-heavy API and UI workflows (including subgraph definitions), 20-30 KB base64 and base64url latent blobs and a
`data:` URI, sha256 model hashes (UI `models`, API inputs, A1111 `Lora hashes`), 40/32/24-character hex that is not a
secret, prose that merely mentions token / secret / password / bearer / API key (prompts, notes, node titles), version
strings that look like IPs (`1.2.3.4`, `v2.0.1.7`, `0.3.60.1`), an 8 KB ordinary prompt, seeds up to 2^64-1, trivial
secret-field values (empty, null, false, `none`, `None`, a space), bypassed/muted nodes with nothing secret, model
paths without a username, documentation URLs without webhook ids, placeholder `example.com/.org/.net` addresses,
public IPs just outside the private ranges, hostnames that merely contain `internal` or `lan`, no-metadata
PNG/MP4/JPEG (plus a 1.5 MB noise-pixel PNG with no metadata), PNG with `pHYs gAMA cHRM sRGB sBIT bKGD tIME iCCP` and ordinary text, benign zTXt / compressed iTXt /
double-encoded JSON, plain MP4 and MOV tags, zero-filled `free`/`skip` padding, EXIF without GPS, a GPS IFD with
only a version tag.

## answer_key.json

```
files[relpath] = {
  group, tier, format, expected_exit, expected_exit_in,
  expected: [ {class, carrier, node_id|null, bypassed, location_hint, optional,
               accept_classes, underlying_class?, tags?, tier?, layout?,
               value_sha256_prefix?, value_length?} ],
  extra_ok_classes?, canaries?, strict_location_sanitization?, filename_canary_allowed_in_file_field?, notes? }
dir_tests[]   {id, path, expect_exit_in, expect_files_with_findings, must_not_report_path_containing?, ...}
cli_tests[]   {args ("{corpus}" and "{tmp}" placeholders), expected_exit_in, env?, note}
policy, known_misses_by_design, classes, counts, skipped, never_echo_file
```

How to score a file: every non-optional `expected` entry must be matched by a finding whose `class` is in
`accept_classes`, whose `node_id` (compared as a string) equals `node_id` when it is not null, and whose `bypassed`
equals `bypassed`. H1 entries have `bypassed: true` and accept either `H1` or the underlying `K1`/`K2`/`K3`;
a finding on a mode 0/1/3 node must carry `bypassed: false`. Findings beyond `expected` and `extra_ok_classes`
in a positive file, and any finding in a clean file, are false positives. `carrier` uses the vocabulary
`png-tEXt png-zTXt png-iTXt png-eXIf png-trailer png-other mp4-tag mov-tag mp4-box jpeg-exif jpeg-xmp jpeg-com raw-bytes`;
match on the family (`png-`, `mp4-`, `jpeg-`) if a scanner names carriers differently. `value_sha256_prefix` and
`value_length` are advisory (a scanner may hash the whole URL or just the token). Entries of one file that share a
`value_sha256_prefix` are the same secret seen at several locations (prompt and workflow chunk, say): reporting
each location is preferred, reporting the value once is acceptable. `optional: true` entries (damaged files) may be
omitted. The exit code must be in `expected_exit_in`.

`never_echo.json` lists every planted secret, PII value and prompt-injection canary. No scanner output (stdout,
stderr, JSON report) may contain any of them. Exception: a file's own path may contain its
`filename_canary_allowed_in_file_field`. Entries with `strict_location_sanitization` put attacker text in the
chunk keyword, node id or field name, which are part of `location`: they must be printed sanitised or truncated.

## Policy decisions (the contract left these open)

* **Placeholder e-mails**: not findings when the domain is `example.com/.org/.net/.edu` or a subdomain (core clean);
  `.test/.invalid/.example/.localhost` are placeholders too (boundary). Every other domain is flagged, including
  generic-looking ones. Positive fixtures only use made-up non-`example` domains.
* **Trivial secret values** (core clean): empty or whitespace, null, false/true, 0, `none`, `None`. Placeholder
  text such as `YOUR_API_KEY`, `<your-token>`, `changeme`, `xxxxxxxx`, `********` is boundary.
* **Private IPv4**: exactly 10/8, 172.16/12, 192.168/16. `172.15.x`, `172.32.x`, `192.167.x`, `192.169.x`, `11.x`,
  `9.x` and 3-part strings such as `10.1.2` are core clean. Loopback, link-local, CGNAT, invalid octets and
  `10.0.19045.1` style version strings are boundary.
* **Home paths**: `C:\Users\Public`, `C:\Users\Default`, `/Users/Shared` reveal no username (boundary).
* **Stripe**: only live keys (`sk_live_`) are in the contract; a test-mode key is boundary.
* **Key names**: `token_normalization`, `max_tokens`, `password_protected` are boundary (they contain a secret word but are
  ordinary ComfyUI-style inputs).
* **bypassed**: true iff UI-format mode is 2 or 4. API-format has no mode.

## Known misses by design (`known_miss/`)

Pixel LSB steganography; C2PA / JUMBF manifest content (`caBX`); and corpus extras that go beyond the contract:
UTF-16LE text, base64- or hex-wrapped keys, a key split across two fields, an unnamed positional widget value, GPS in an
MP4 location tag. Expected exit 0; findings are informational.

## Hostile files (`hostile/`, 50 files, and `heavy/`, 9 files)

| theme | files |
|---|---|
| instruction text aimed at an AI agent | tEXt chunk, node title, JSON value (with a fake system-prompt block), **file name**, iTXt system block, zTXt, MP4 comment, chunk keyword, node id, field name, U+E0000 tag characters, bidi controls |
| encoding | CJK + emoji ids (escaped and raw UTF-8), JSON lone surrogates (`\ud800`), invalid UTF-8 bytes, Latin-1 high bytes + NULs, CJK/emoji file name |
| damage | truncated in IDAT (with and without a secret before the cut), truncated inside the secret chunk, wrong CRC on a text chunk (with and without secret), wrong CRC on IDAT only, chunk length 4 GB, missing IEND, corrupt zTXt stream, unknown zTXt method, corrupt zTXt next to a plain secret, random bytes and plain text named `.png`, signature only, zero-byte PNG/MP4/JPEG, MP4 cut before `moov`, MP4 box claiming 3 GB, MP4 last box with size 0, MP4 box smaller than its header, JPEG EXIF cut short, JPEG IFD loop, JPEG GPS count 4 billion, IHDR claiming 2 GB x 2 GB |
| JSON traps | duplicate keys (secret first, empty last), 6000-digit integer, `NaN`/`Infinity`, leading BOM, trailing garbage, 10 levels of string encoding |
| resource probes (`heavy/`) | 20 MB single chunk (filler, and with a secret at the very end), zTXt and iTXt bombs of about 1 MB on disk that inflate to 1 GiB (zeros, and a secret after 1 GiB of spaces), a bomb next to a plain secret, 100,000 text chunks then a secret, JSON nested 50,000 deep, 200,000 empty MP4 boxes then a workflow box |

Exit-code rule behind most expectations: a file that could not be scanned must **never** read as clean. If a scanner
stops early (decompression cap, chunk-count cap, depth cap, `--max-bytes`) it has to surface that as exit 3 (or exit 1
if something else was found), not 0.

## Directory-walk fixtures (`dirs/`)

* `nested_basic` - ordinary recursion, one leak four levels down.
* `walk_junction` - contains `link_out`, a junction (created with `mklink /J`) to the sibling `walk_junction_target`;
  scanning `walk_junction` must report only `real_K1.png`, scanning the target directly reports `hidden_by_junction_K1.png`.
* `junction_loop` - `a/b/loop` is a junction back to the scan root (recursion without a guard never ends).
* `symlink_loop` - the same with a symlink (skipped with a reason in `skipped` if the OS refuses symlinks).
* `file_symlink` - a symlink to a leaking PNG elsewhere in the corpus (boundary tier: the contract says do not follow
  symlinks, so exit 0 is ideal and exit 1 is the weaker behaviour).
* `deep_dir` - a leak 37 directories deep with the reference output path (the depth adapts to keep the path under
  250 characters). Reporting it (exit 1) or hitting a documented depth cap (exit 3) is fine; exit 0 is not.
* `many_files` - 2000 tiny clean PNGs. `empty_dir` (exit 3: a run that read no file is never a pass), `mixed_corrupt`, `only_corrupt` check the exit-code mix.
* sweeps of `pos`, `clean`, `boundary`, `known_miss`, `hostile`, `heavy`.

Junctions never point outside the corpus. `cli_tests` cover usage errors (exit 2), exit 0/1/3 combinations,
`--max-bytes`, `--json`, and stdout piped through cp1252 and ASCII code pages.

## Re-running a single check by hand

```
python make_corpus.py C:\tmp\ssr_corpus
python scan.py C:\tmp\ssr_corpus\pos\K1_openai_legacy_api_tEXt.png --json out.json   # expect exit 1
python scan.py C:\tmp\ssr_corpus\clean                                                # expect exit 0
```
