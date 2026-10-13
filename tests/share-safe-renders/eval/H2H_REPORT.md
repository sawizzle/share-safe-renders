# Share-Safe Renders: head-to-head, scan.py vs trufflehog vs exiftool+trufflehog

> Moved here from the prototype with the numbers unchanged. The commands under "Reproduce" are run from
> `tests/share-safe-renders` (the folder that holds `corpus/` and `eval/`); the scanner under test is
> `packages/share-safe-renders/scripts/scan.py`. The numbers describe scan.py 1.1.0 as prototyped; the four
> release edits of 1.2.0 (no environment read, no file deletion, own percent-decoder, a guard on `--json`) do not change what is detected
> (the unit tests and `tests/share-safe-renders/test_release_edits.py` check that).

Run 2026-10-12 on the synthetic corpus (seed 20261012, 240 registered files, 194 required planted entries). Everything is
reproducible with `eval/h2h.py`; no network was used (trufflehog ran with `--no-verification --no-update` and a dead local
proxy). No planted value appears in this report.

## What was compared

| id | approach |
|---|---|
| A | `scan.py PATH --json` (current prototype) |
| B1 | `trufflehog filesystem FILE --no-verification --no-update --json --results=verified,unverified,unknown`, file as it is |
| B1w | same, on a copy with a 5-byte text prefix (my workaround, see "trufflehog skips media" below; not a supported mode) |
| B2p | `exiftool -a -u -G1 -s -ee3 -api LargeFileSupport=1` to a text file, then trufflehog on that text |
| B2b | same with `-b` (prints raw values only, no tag names; the only mode that exposes hidden box payloads), then trufflehog |
| B2u | B2p + B2b together |
| Bx | B1w + B2u together (every baseline tool at once; visibility also counts the raw bytes). This is the strongest baseline. |

Versions: exiftool 13.59, trufflehog 3.99.2, Python 3.14.6, Windows job object (4 GiB cap, kill-tree). Files were run one process
per file, sequentially.

How B was scored (exiftool classifies nothing, trufflehog classifies vendor secrets only):

* **flagged** = a trufflehog finding whose `Raw`/`RawV2`/secret-part text covers the planted value (substring either way, URL path
  segments accepted). Entries are tied to values through the answer key's `value_sha256_prefix`. Only meaningful for K1 and K3;
  for every other class a hit would be incidental (there were none).
* **family** = any K1/K3-family detector fired anywhere in the file (looser; shown in the JSON only).
* **visible** = the planted value is present in clear in the exiftool dump (literal or JSON-escaped). G1 = lat and lon tags shown;
  M1 = its inner secret or a ComfyUI workflow marker shown; unhashed P1 = every planted user name in the file shown.
* None of B can give a node id or a bypass flag, so B is scored on class-present-in-file only. A is shown both strict
  (class + node id + bypassed + carrier family) and lenient (class present). A's numbers equal `eval/score.py`'s own (cross-checked).

## Headline numbers

```
class  planted | A strict  A lenient | trufflehog FLAGGED the value:  B1   B1w   B2p   B2b   B2u   Bx
K1        68   |    68        68     |                                0   26    23    21    24    27
K2        32   |    32        32     |                                0    0     0     0     0     0
K3         9   |     9         9     |                                0    3     3     3     3     3
P1        11   |    11        11     |                                0    0     0     0     0     0
P2        12   |    12        12     |                                0    0     0     0     0     0
P3        11   |    11        11     |                                0    0     0     0     0     0
G1         8   |     8         8     |                                -    -     -     -     -     -   (no stored value, no classifier)
H1         7   |     7         7     |   underlying secret flagged:   0    1     1     1     1     1   (no bypass flag possible)
H2         7   |     7         7     |   underlying secret flagged:   0    1     1     1     1     1
H3        12   |    12        12     |   underlying secret flagged:   0    1     6     6     6     6
M1        17   |    17        17     |                                -    -     -     -     -     -   (no classifier)
ALL      194   |   194       194
```

Visible in clear (not flagged, a human or model must read the output and classify):

```
class  planted | raw file bytes   B2p   B2b   B2u   Bx
K1        68   |     68           64    65    65    68
K2        32   |     32           30    32    32    32
K3         9   |      9            8     9     9     9
P1        11   |     11           10    10    10    11
P2        12   |     12           11    12    12    12
P3        11   |     11           11    11    11    11
G1         8   |      0            8     8     8     8     (raw bytes: binary rationals; exiftool prints DMS, -b prints decimals)
H1         7   |      7            7     7     7     7
H2         7   |      7            7     7     7     7
H3        12   |      1           12    12    12    12     (exiftool inflates zTXt / compressed iTXt)
M1        17   |      9            9    16    16    17     (hidden free/uuid payloads only appear with -b)
```

Value level: of the 176 planted text values that sit in a corpus file, B2p shows 163 in clear, B2b and B2u 169. The 14 GPS
coordinates appear literally in the `-b` dump (1 in the plain dump, which prints degrees/minutes/seconds). The 4 required entries
the exiftool dumps do not show: PNG private chunk `prVt` (K1), plain bytes after `IEND` (K1), a free box with size 0 (K1) and a
Latin-1/NUL user name (P1). The raw bytes show all four, and B1w flags the first three.

Per carrier (A strict = A lenient everywhere, 194/194): the baselines fall behind on `mp4-box` (14 entries: visible in 0 plain
dumps, 12 `-b` dumps; flagged 2), `png-zTXt`/`iTXt` (B1w flags 5 of 21 K1/K3 entries inside them, B2 flags 11 of 21 because exiftool inflates
them), `png-other` and `png-trailer` (exiftool shows neither).

### trufflehog flagging by vendor (K1/K3 underlying, H-classes included; public prefix only)

```
vendor               planted  A   B1w  B2u  Bx          note
anthropic               8     8    5    7    7
github (classic, fg)   11    11    8    8   10
huggingface             8     8    7    8    8
slack bot/user          6     6    6    5    6
slack webhook           4     4    3    4    4
stripe live             2     2    2    2    2
openai legacy          32    32    1    1    1          corpus keys lack the T3BlbkFJ marker (1 of 43 has it)
aws access key id       7     7    0    0    0          trufflehog needs the id+secret pair; id alone is never reported
openai project          2     2    0    0    0          no marker
google api key          1     1    0    0    0
slack xapp/other        2     2    0    0    0
discord webhook         8     8    0    0    0          no unverified Discord-webhook detector
```

Calibration with 16 hand-made fake credentials in a plain text file: OpenAI keys *with* the marker, Anthropic api03, GitHub,
Slack bot, Stripe, Hugging Face, Slack webhook and an AWS id+secret pair were flagged; marker-less OpenAI, a short `sk-ant-` key,
a lone AWS id, a bare `AIza` key, `xapp-` and a Discord webhook were not. So much of the K1 shortfall is **corpus shape**, not carrier: the corpus
builds keys to scan.py's contract windows, not to vendor structure. Excluding openai-legacy and lone AWS ids, trufflehog flags
33 of 40 remaining effective K1 entries (82%). Read the K1 row above as "on this corpus", not "on real keys".

## Clean controls, false positives, exit-code honesty

| | A | B1 | B1w | B2p | B2b | B2u | Bx |
|---|---|---|---|---|---|---|---|
| files with a finding among the 46 clean controls | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| boundary files flagged (of 8) | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| unplanted findings in positive/hostile/heavy files | 1 (score.py) | 0 | 0 | 0 | 0 | 0 | 0 |
| files holding a required leak that the approach reported as nothing, exit 0 ("false clean") | **0** | 147 | 119 | 118 | 120 | 117 | 114 |

The false-clean row for B includes classes it has no detector for (K2, P*, G1, M1), so it measures "would a user be told": no.
A's one boundary hit is the appended `uuid` box of random binary (M1, a judgement call).

## trufflehog skips media (B1 is not a usable baseline as invoked)

`trufflehog filesystem render.png` sniffs the type from the bytes and logs "skipping file: extension is ignored" for PNG, JPEG and
MP4. Renaming to `.dat` does not help (the mime is sniffed). Result: 238 of 240 files produced `chunks: 0`, exit 0, no output. The two
it did scan are `hostile_plain_text_named_png` and `hostile_random_bytes_named_png`. I found no flag in `filesystem --help-long`
that overrides it. B1w (prefix the copy with `text\n`) and B2 (scan a text dump) are the ways round it.

## Hostile and heavy files (59 files)

| | A | trufflehog (B1w) | exiftool (B2p / B2b) |
|---|---|---|---|
| crashes / timeouts | 0 / 0 | 0 / 0 | B2p: 4 `Out of memory!` exit 1 at the 4 GiB cap on the 4 inflate bombs (1 MiB files); B2b: no crash |
| exit codes vs contract | 59/59 in contract (12 expected-exit-3 files: all exit 3) | always 0 (the 12 "could not scan" files read as clean) | exit 1 on zero-byte x3, random bytes, and the emoji file name (`Win32::FindFile: No support for unicode surrogates`; needed an ASCII copy) |
| worst case time / memory | 1.06 s on the 200k-box MP4; peak 103 MB (20 MB chunk); bombs 0.13 s / 30 MB | 0.7 s / 344 MB; scanned a 1.4 GB dump in 1.2 s | 14.1 s on the 200k-box MP4 (B2p including trufflehog; 19.8 MB dump); `-b` writes a 1 GiB dump per bomb in about 2.4 s at 3.1 GiB peak; plain mode peaks above 4.1 GiB |
| bomb with the secret after 1 GiB of spaces | exit 3 in 0.13 s, secret not found, honestly reported as unscanned | no finding (the value is in the `-b` dump but not a recognised shape) | value visible in the `-b` dump only |
| echo of planted text in the tool's own output | **0 of 240 runs** (stdout, stderr, JSON) | prints the matched secret (`Raw`) in 31 files | exiftool dumps contain secrets in 113 files, PII in 41, planted canaries in 10, planted injection phrases in 8 |

All three tools print the file path, so an instruction-bearing file name is echoed by trufflehog and exiftool. exiftool also adds
`System:Directory` to every dump: it is the directory part of the path as passed, and the harness passed absolute paths, so here it
included the home directory, which is itself a P1 leak. `-x System:All` removed the tag (checked, with absolute paths only; relative paths were
not tried, and exiftool may still echo the path in its per-file header). Without that, a regex layer flags all 46 clean controls for P1.

## Wall time, 240 registered files

| | A | B1 | B1w | B2p | B2b | B2u | Bx |
|---|---|---|---|---|---|---|---|
| one process per file, sequential, seconds | 27.2 | 159.5 | 161.1 | 212.8 | 215.5 | 428.3 | 589.4 |
| per-file floor | 0.09 s | 0.66 s (trufflehog start-up) | 0.67 s | 0.8 s | 0.8 s | | |
| one invocation over 231 files (no heavy/) | 1.96 s | 0.68 s (skips media) | 0.78 s | 1.49 s | 1.50 s | | |

Bulk speed is not an advantage for A: in one invocation trufflehog is faster. A wins only on per-process start-up.

## Decision table

```
class  who finds it (class present in file)                          what only A adds / who else sees it
K1     A 68/68. trufflehog 27/68 (33/40 effective on the vendor-valid subset). A: AWS id alone, marker-less OpenAI, project keys, Google, xapp. Baselines SEE 68/68.
K2     A 32/32 (positional widgets recovered from inputs[].widget).  Nobody else classifies it. Visible 32/32; a regex stand-in over the dumps gets 25/32.
K3     A 9/9. trufflehog 3/9 (Slack yes, Discord 0/8).               A: Discord webhooks. Visible 9/9.
P1-P3  A 34/34. Baselines 0/34.                                      Visible 33/34 in the dumps, 34/34 with raw bytes. Regex stand-in on dumps 33/34 once the dump's own path is stripped.
G1     A 8/8. Baselines 0 (nothing classifies it).                   exiftool shows 8/8; raw bytes show 0/8. Regex stand-in on dumps 0/8 (padding breaks its pattern; a fix is cheap).
H1     A 7/7 with node id and bypassed=true. Baselines 1/7 (value).  Bypass/node attribution: only A.
H2     A 7/7. Baselines 1/7.                                         Escaped text is in the raw bytes (7/7 visible); stand-in 5/7.
H3     A 12/12. trufflehog on raw 0-1/12.                            exiftool inflates it (12/12 visible) so B2 flags 6/12 (same shape limits as K1); stand-in on dumps 11/12.
M1     A 17/17. Baselines have no concept of it.                     Tag payloads show in plain exiftool; hidden free/uuid payloads only with -b (16/17).
```

Things only A does, measured here:

1. **Classification of 91 of 194 entries no baseline can classify** (K2, P1, P2, P3, G1, M1), and attribution of every entry to a node id and bypass flag (strict 194/194; H1 7/7 with `bypassed: true`).
2. **Compressed chunks** classified, including bombs handled with an honest exit 3: H3 12/12; the four inflate bombs exit 3 in 0.13 s at 30 MB peak (exiftool: above 4.1 GiB, or a 1 GiB dump).
3. **Hidden MP4 boxes**: M1 17/17; plain exiftool shows 0 of 14 hidden-box entries, `-b` shows 12.
4. **No-echo safety**: 0 planted values, canaries or injection phrases in any A output across 240 runs; trufflehog prints 31 secrets, exiftool dumps print everything including injected instruction text.
5. **Never reads a leaking or unscannable file as clean**: 0 false-clean files and 12/12 expected exit-3 files exit 3, against 114 to 147 false-clean files and 12/12 exit 0 for trufflehog.

## Kill gate: do the baselines catch everything except location and proof?

**No, not with these tools as they ship.**

* As invoked (B1) trufflehog scans 2 of 240 files and says nothing. This alone fails the gate.
* With the workarounds (Bx), 91 of 194 entries have no classifier at all, K1 is 27/68 and K3 3/9 on this corpus, and 114 files holding
  required leaks print nothing.
* **But the baselines do *see* everything**: Bx shows all 194 required entries in clear. The gap is classification, not visibility.
  A cheap regex layer after exiftool (the repo's stand-in, not a real tool, run over the dumps with the dump's own path stripped;
  `--naive-dumps`) reaches 154/194 on class presence with 1 of 46 clean controls flagged, strongest on K3/P1-P3 (all or nearly all) and weakest on G1 (0/8), M1
  (0/17), K2 (25/32), H2 (5/7). So the defensible A claim is: structure-aware classification of K2/G1/H*/M1 plus node and bypass
  attribution, safe output, and exit-code honesty, not "finds things the others cannot see".

## Where the baselines win

* **trufflehog is better at vendor breadth and validity**: it flags 33 of the 40 key entries outside OpenAI-legacy and lone AWS ids,
  with zero false positives on clean, boundary and positive files; its detector list is far larger than A's nine vendor formats
  (not measured, since the corpus plants only A's formats).
* **Decoders**: trufflehog's BASE64 decoder flags the base64-wrapped key in `known_miss/km_base64_wrapped_key_api.png`; A is silent
  there (known miss by design).
* **Bulk throughput** (one invocation: 0.8 to 1.5 s vs A's 2.0 s) and ecosystem: maintained detectors, verification (off here), CI integrations.
* **exiftool decodes more metadata than any hand parser**: it showed 169 of 176 text values, inflated zTXt, and printed GPS in
  two forms, with no code to maintain.
* A flagged one boundary file and one unplanted record; the baselines flagged none.

## Caveats

* **A is in-sample.** scan.py was built against this corpus and answer key; its 194/194 and 0 false positives are not an estimate
  of real-world recall. The baselines were never tuned to it.
* The corpus keys follow scan.py's contract windows, not vendor structure (43 OpenAI-legacy values, 1 with the marker), which
  penalises trufflehog's K1 row. The calibration above is the correction; both views are given.
* M1, G1 and unhashed P1 visibility is inferred from markers (see `h2h.py` docstring), not from a stored value. One file with two
  hidden boxes may be over-credited.
* B1w is my construction (a prefixed copy); trufflehog custom regex detectors (`--config`) were **not** tested and could close part of the
  classification gap. The regex stand-in is the only evidence on that.
* Windows only, one run per file, no repeat timings; detection numbers re-ran identically on a 33-file subset (0 differences).

## Reproduce

```
python corpus/make_corpus.py OUT/corpus --force
python eval/h2h.py --corpus OUT/corpus --workdir OUT/work --exiftool EXIFTOOL.EXE --trufflehog TRUFFLEHOG.EXE --phases run --dirmode
python eval/h2h.py --corpus OUT/corpus --workdir OUT/work --exiftool EXIFTOOL.EXE --trufflehog TRUFFLEHOG.EXE --phases score --naive-dumps
```
