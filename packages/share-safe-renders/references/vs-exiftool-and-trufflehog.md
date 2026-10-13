# Compared with exiftool and trufflehog

This scanner does not replace either tool. This page says what it adds, what they do better, and gives the measured numbers
with their limits. The measurement is a head-to-head on a **synthetic** corpus, run on 2026-10-12 with the prototype of this
scanner (version 1.1.0). The full report, and the scripts that regenerate it, are in the project repository (`tests/share-safe-renders/eval/H2H_REPORT.md`),
not in this package.

## The short version

- **exiftool** shows nearly every tag in a file. It classifies nothing. It is the better tool for looking at metadata.
- **trufflehog** has far more vendor secret detectors than this scanner, and can verify whether a key is live. It does not look inside PNG, JPEG or MP4 files as shipped (see below).
- **This scanner** reads the PNG, JPEG, MP4/MOV and JSON containers itself and *classifies* what it finds: home-directory user names, e-mail addresses, LAN addresses, GPS, hidden MP4 boxes, secrets in bypassed nodes, compressed PNG chunks; with node id and bypass attribution. Its report never prints the text it found. Its exit code does not read a file it knows it could not scan as clean (the head-to-head found no false clean on its corpus; gaps of that kind were found and fixed afterwards: HEIC photos, AVIF files with an unusual major brand, an empty folder that exited 0, and text that some limits had left unexamined without saying so: a flood of distinct values of one kind in one text, an MP4 metadata list of more than 4096 entries or a list whose entries do not fit, an EXIF text tag over 1 MiB or a value of a type it cannot read, a PNG chunk far longer than its format allows, a sample table or fixed-layout box whose size does not fit its own count, a location box over 1 MiB).

If you can run exiftool and trufflehog and read their output carefully, you can see nearly everything this scanner reports (the exiftool dumps alone showed 189 of the 194 planted entries on this corpus), but you classify it yourself.
What this scanner adds is classification, node and bypass attribution, a report that never prints the leaked text, and an exit code that does not read a file it knows it could not scan as clean, in one command.

## What was measured

Corpus: seed 20261012, 240 registered files, 194 required planted entries. Versions: exiftool 13.59, trufflehog 3.99.2, Python 3.14.6,
Windows. No network was used (trufflehog ran with `--no-verification --no-update`). Files were run one process per file, one run each.

| id | approach |
| --- | --- |
| A | `scan.py PATH --json` |
| B1 | `trufflehog filesystem FILE`, file as it is |
| B1w | trufflehog on a copy with a 5-byte text prefix (a workaround of the measurer, not a supported mode) |
| B2p | exiftool dump (`-a -u -G1 -s -ee3`), then trufflehog on the dump text |
| B2b | exiftool dump with `-b` (raw values only), then trufflehog |
| B2u | B2p and B2b together |
| Bx | B1w and B2u together: every baseline tool at once, the strongest baseline |

### Headline numbers (class present in the file)

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

### What the baselines can see (visible in clear, but not classified)

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

## How to read the numbers

- **The gap is classification more than visibility.** The exiftool dumps (plain and `-b`, the B2u column) *show* 189 of the 194 required entries in clear text. The other 5 are the entries for four planted values that the dumps do not show (a K1 in a private PNG chunk,
  a K1 after `IEND`, a K1 in a `free` box of size 0, and a Latin-1/NUL user name; the size-0 box counts as both a K1 and an M1 entry). They appear only in a raw-byte view of the file, which is a third source and neither tool: the `Bx` and raw-bytes columns above include it.
  trufflehog prints a secret only when it flags it. It *flags* 27 of 68 K1 and 3 of 9 K3 on this corpus; exiftool flags nothing; neither has a class for K2, P1-P3, G1 or M1.
  Much of the K1 gap is corpus shape, not carrier (see "Caveats"): excluding OpenAI-legacy values and lone AWS key ids, trufflehog flagged 33 of the 40 remaining effective K1 entries (82%). That count is on the underlying-key basis of the head-to-head report's vendor table (keys inside bypassed nodes and compressed chunks count too), so it is not comparable with the 27 of 68, which counts entries by class.
  A cheap regex layer over the exiftool dumps reached 154 of 194 on class presence with 1 of 46 clean controls flagged.
- **trufflehog skips media files.** As invoked, it scanned none of the real PNG, JPEG or MP4 files in the corpus (238 had `chunks: 0`, exit 0, no output). The only two files it did scan were a plain-text file and a random-bytes file that were merely named `.png`.
  Renaming a file did not help because the type is sniffed from the bytes. It works on text (the workaround rows B1w and B2).
- **False clean.** Files holding a required leak for which the approach printed nothing and exited 0: A 0; B1w 119; B2p 118; B2b 120; B2u 117; Bx 114 (B1: 147).
  That row includes classes the baselines have no detector for, so it measures "would the user be told", not "was the detector wrong".
- **No echo.** Across 240 runs scan.py printed none of the planted values, canaries or injected instruction text. trufflehog prints the matched secret
  (31 files); exiftool dumps print everything, including text aimed at an AI agent. All three print the file path.
- **Time.** One process per file, 240 files: scan.py 27.2 s, trufflehog 159.5 s, exiftool plus trufflehog 212.8 s. In one invocation over a folder
  trufflehog was faster (0.68 s against 1.96 s, because it skips media). Bulk speed is not an advantage of this scanner.
- **Hostile files.** On decompression bombs scan.py exited 3 in 0.13 s at 30 MB peak; exiftool's plain dump ran out of memory at the 4 GiB cap on four of them.

## Where the other tools are better

- **Vendor breadth and validity.** trufflehog's detector list is far larger than this scanner's list of eight vendors (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe, Hugging Face; the prototype's report counted the formats as nine), it can verify a key against the provider,
  and it is maintained. Excluding OpenAI-legacy values and lone AWS key ids, it flagged 33 of the 40 remaining effective K1 entries (82%), with zero false positives on clean controls. This scanner has no verification.
- **Decoders.** trufflehog decoded a base64-wrapped key that this scanner misses by design.
- **Bulk throughput and ecosystem:** CI integrations, git history scanning, many sources.
- **exiftool shows every tag**, decodes more metadata than a hand-written parser, and printed 169 of 176 planted text values in clear. It also prints the directory part of the path as you passed it (`System:Directory`). With an absolute path, as in the head-to-head, that includes your home directory and user name, which is itself a leak; `-x System:All` removes that tag, but exiftool may still echo the path in its per-file header. This was seen with absolute paths and not tested with relative ones, because exiftool was not re-run for this note.

## Caveats you should weigh

- **The scanner is in-sample.** It was built against this corpus and its answer key. 194 of 194 with no false positives on clean controls is **not an estimate of real-world recall**. The baselines were never tuned to the corpus.
- **The corpus keys follow this scanner's length windows, not vendors' real structure** (43 OpenAI-legacy values, 1 with the marker trufflehog needs; the head-to-head report's vendor table counts 32 OpenAI-legacy entries, of which trufflehog flagged 1, and 7 lone AWS key ids, of which it flagged none). That lowers trufflehog's K1 row. With 16 hand-made fake credentials in a plain text file trufflehog flagged the structurally valid ones; the shortfall is partly corpus shape, not carrier. Read the K1 row as "on this corpus", not "on real keys".
- The B1w workaround is the measurer's construction. trufflehog's custom-regex detectors (`--config`) were **not** tested and could close part of the classification gap.
- M1, G1 and unhashed P1 visibility is inferred from markers, not from a stored value. Windows only, one run per file, no repeat timings.
- The numbers describe the prototype, scan.py 1.1.0. The package's `scan.py` (1.2.0) differs from it in release edits. Two add detection that the corpus does not exercise (the MP4 `loci` location box, and text in the name, mean and unknown children of an MP4 metadata item); the others change no detection (it reads no environment variable of its own, deletes no file, has its own percent-decoder, guards the `--json` path, refuses HEIC photos instead of walking them as MP4, prints the verdict line twice and names skipped entries). Re-scored on the same full corpus (seed 20261012, heavy probes included) it gave the same result as the prototype: 194 of 194 required entries, strict and lenient, no finding in any of the 46 clean controls, 1 of 8 boundary files flagged. That is the same in-sample result, not a new estimate. The package scanner was scored again on the same full corpus after the fixes that followed an independent review, with the same result (194 of 194, strict and lenient; no finding in any of the 46 clean controls; 1 of 8 boundary files flagged; no crash or timeout). One thing changed in the scorer, not in these numbers: the hash in a hashed node id (`id~...`) is now keyed with a random key, so the scorer can no longer recompute it and accepts any `id~` label for a planted node id that is not a plain number.
