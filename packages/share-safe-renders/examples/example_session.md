# Example session

A worked example of an agent following `SKILL.md`, start to finish. The commands and the scanner output are real runs of the scripts in this package on the demo files. The skill folder is written `<SKILL_DIR>`, and the full path of the user's project folder (the folder that holds `renders/`) is written `<PROJECT>`, in the commands and in the output. Every command starts with `cd ~;` and gives every path in full, as "Where to run them" in `SKILL.md` says; each was run from an empty folder that stood for the home folder. The assistant's lines were written to follow `SKILL.md` and are filled with the real numbers; this is a worked example, not a recording of a model.

---

**User:** I'm going to post the six renders in `renders/` on a forum, one at a time. Can you check them first?

**Assistant:** The folder is `renders/` in your project folder, `<PROJECT>/renders` (step 1). Only the renders will be posted, not the whole folder, so I will not use `--strict`. I'll run every command from your home folder with every path in full ("Where to run them"), check Python first, then scan the folder and write the report next to it, not inside it (step 2).

```sh
cd ~; python --version
```

```
Python 3.14.6
```

```sh
cd ~; python -I -B "<SKILL_DIR>/scripts/scan.py" "<PROJECT>/renders" --json "<PROJECT>/share-safe-report.json"
```

Exit code: **1**. I'm reading the printed report, not the files themselves (step 3). The JSON report is `<PROJECT>/share-safe-report.json`; it stays there.

```
Share-Safe Renders scan.py 1.2.0
Scanned 6 file(s): 5 with findings, 12 finding(s), 0 problem(s); 0 link(s) not followed, 1 unrecognized file(s) skipped; ffprobe: used.
RESULT: FINDINGS - do not share these files as they are (exit 1)

FINDINGS (values are never printed: only class, place, length and a hash prefix)
  [HIGH] K2  file=<PROJECT>/renders\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:11/inputs/api_key  node=11  bypassed=no  length=51  sha256=23478fbb  (field=api_key)
  [HIGH] K1  file=<PROJECT>/renders\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:11/inputs/api_key  node=11  bypassed=no  length=51  sha256=23478fbb  (vendor=openai)
  [HIGH] K3+H3  file=<PROJECT>/renders\02_png_ztxt_webhook.png  carrier=png:zTXt  location=zTXt[workflow]:nodes[1]/widgets_values[0]  node=7  bypassed=no  length=120  sha256=dc8fba79  (kind=discord_webhook)
  [HIGH] K2+H1  file=<PROJECT>/renders\03_png_bypassed_node_secret.png  carrier=png:tEXt  location=tEXt[workflow]:nodes[2]/widgets_values[0]/api_key  node=12  bypassed=yes  length=51  sha256=aaf85b49  (field=api_key)
  [HIGH] K1+H1  file=<PROJECT>/renders\03_png_bypassed_node_secret.png  carrier=png:tEXt  location=tEXt[workflow]:nodes[2]/widgets_values[0]  node=12  bypassed=yes  length=51  sha256=aaf85b49  (vendor=openai)
  [HIGH] K1  file=<PROJECT>/renders\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:box:free  location=free:raw  node=-  bypassed=no  length=51  sha256=4ef3e6b6  (vendor=openai)
  [HIGH] G1  file=<PROJECT>/renders\06_jpeg_exif_gps.jpg  carrier=jpeg:exif  location=exif:GPS  node=-  bypassed=no  length=48  sha256=eb2fbc4a  (kind=exif_gps;tags=lat,lon)
  [MEDIUM] P1  file=<PROJECT>/renders\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:9/inputs/image  node=9  bypassed=no  length=12  sha256=d4d4a8e3  (kind=windows_home)
  [MEDIUM] P2  file=<PROJECT>/renders\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt:node:20/inputs/~211edf9e  node=20  bypassed=no  length=23  sha256=5c4f4853  (kind=email)
  [MEDIUM] M1  file=<PROJECT>/renders\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt  node=-  bypassed=no  length=773  sha256=136130ee  (workflow_json_in_tag;format=api;tag=prompt)
  [MEDIUM] M1  file=<PROJECT>/renders\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:box:free  location=free  node=-  bypassed=no  length=59  sha256=67a651a0  (hidden_box;payload=text)
  [LOW] P3  file=<PROJECT>/renders\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt:node:20/inputs/server  node=20  bypassed=no  length=13  sha256=90b5fab9  (kind=private_ipv4)

NOTES
  embedded_comfyui_api_json  file=<PROJECT>/renders\01_png_api_key_and_username.png
  embedded_comfyui_ui_json  file=<PROJECT>/renders\02_png_ztxt_webhook.png
  embedded_comfyui_api_json  file=<PROJECT>/renders\03_png_bypassed_node_secret.png
  embedded_comfyui_ui_json  file=<PROJECT>/renders\03_png_bypassed_node_secret.png
  embedded_comfyui_api_json  file=<PROJECT>/renders\04_clean.png
  skipped_other  file=<PROJECT>/renders\DEMO_EXPECTED.md

KNOWN MISSES (not detected by design)
  - Data hidden in pixel bits (steganography, LSB or otherwise).
  - Secrets, faces, logos or text that appear in the generated pixels themselves.
  - The contents of C2PA / Content Credentials manifests are not decoded or classified.
  - The image or video content itself (what the picture shows).
  - Secrets that were base64-, hex-, rot13- or otherwise re-encoded, or split across fields.
  - ICC profile contents, and audio/video sample data (incl. the first mdat).
  - Data hidden inside the compressed image stream itself (PNG IDAT, JPEG entropy-coded segments).
  - UTF-16 text inside raw (unparsed) regions such as trailing data; UTF-16 whole-chunk text is decoded.
  - Containers other than PNG, JPEG, MP4/MOV and plain JSON (WebP, GIF, WebM, HEIC, AVIF ... are reported as not scanned; in a folder, other unrecognized file types are only counted as skipped).
  - IPv6 addresses, loopback, link-local and CGNAT ranges, and public IPv4 addresses.
  - Vendor key formats other than the eight it knows (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face), webhook URLs other than Discord and Slack, and secrets in fields whose names it does not recognise.

RESULT: FINDINGS - do not share these files as they are (exit 1)
```

**Assistant:**

**Verdict.** Do not share these files as they are: 12 finding(s) in 5 of 6 file(s) (7 high, 4 medium, 1 low).

**Findings** (same value in two places is one secret, so those rows are merged)

| Severity | Class | Meaning | File | Where |
| --- | --- | --- | --- | --- |
| high | K2 + K1 | a value under a secret-looking field name (`api_key`, `token`, `password`, `secret`, `authorization` ...); a string shaped like a vendor API key or token (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face) | `renders/01_png_api_key_and_username.png` | `png:tEXt, tEXt[prompt]:node:11/inputs/api_key, node 11` |
| high | K3 + H3 | a Discord or Slack webhook URL | `renders/02_png_ztxt_webhook.png` | `png:zTXt, zTXt[workflow]:nodes[1]/widgets_values[0], node 7` |
| high | K2 + K1 + H1 | a value under a secret-looking field name (`api_key`, `token`, `password`, `secret`, `authorization` ...); a string shaped like a vendor API key or token (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face) | `renders/03_png_bypassed_node_secret.png` | `png:tEXt, tEXt[workflow]:nodes[2]/widgets_values[0]/api_key, node 12, bypassed` |
| high | K1 | a string shaped like a vendor API key or token (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face) | `renders/05_mp4_prompt_tag_and_free_box.mp4` | `mp4:box:free, free:raw` |
| high | G1 | GPS coordinates (EXIF, XMP, an MP4/MOV location tag or the MP4 `loci` box) | `renders/06_jpeg_exif_gps.jpg` | `jpeg:exif, exif:GPS` |
| medium | P1 | a home-folder path that reveals an account name (Windows, macOS and Linux forms) | `renders/01_png_api_key_and_username.png` | `png:tEXt, tEXt[prompt]:node:9/inputs/image, node 9` |
| medium | P2 | an e-mail address (documentation addresses such as example.com are ignored) | `renders/05_mp4_prompt_tag_and_free_box.mp4` | `mp4:tag, moov/udta/meta/ilst/prompt:node:20/inputs/~211edf9e, node 20` |
| medium | M1 | hidden MP4/MOV data: a tag holding workflow or prompt JSON, or data in a free/uuid/unknown top-level box or after the last box | `renders/05_mp4_prompt_tag_and_free_box.mp4` | `mp4:tag, moov/udta/meta/ilst/prompt` |
| medium | M1 | hidden MP4/MOV data: a tag holding workflow or prompt JSON, or data in a free/uuid/unknown top-level box or after the last box | `renders/05_mp4_prompt_tag_and_free_box.mp4` | `mp4:box:free, free` |
| low | P3 | a private-network address (10.x, 172.16-31.x, 192.168.x) or a .local/.lan/.internal host name | `renders/05_mp4_prompt_tag_and_free_box.mp4` | `mp4:tag, moov/udta/meta/ilst/prompt:node:20/inputs/server, node 20` |

4 PNG file(s) carry an embedded ComfyUI workflow. The prompt text, model names, seeds and node layout travel with the file although they are not findings.
The scanner did not examine 1 file(s) in the folder because they are not renders: `renders/DEMO_EXPECTED.md`.

**How to fix**

1. Export a copy of each flagged file without its metadata, into a new folder (the originals stay untouched). Every file name here is plain (letters, digits, `_` and `.`), so the commands can be built from them; a file whose name is not plain would get no command, only a request to rename it ("Names in commands" in `SKILL.md`):

```sh
cd ~; mkdir "<PROJECT>/reexported"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/01_png_api_key_and_username.png" -map_metadata -1 "<PROJECT>/reexported/01_png_api_key_and_username.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/02_png_ztxt_webhook.png" -map_metadata -1 "<PROJECT>/reexported/02_png_ztxt_webhook.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/03_png_bypassed_node_secret.png" -map_metadata -1 "<PROJECT>/reexported/03_png_bypassed_node_secret.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/05_mp4_prompt_tag_and_free_box.mp4" -map_metadata -1 -map_chapters -1 -c copy "<PROJECT>/reexported/05_mp4_prompt_tag_and_free_box.mp4"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/06_jpeg_exif_gps.jpg" -map_metadata -1 -q:v 2 "<PROJECT>/reexported/06_jpeg_exif_gps.jpg"
```

2. Run those and tell me when the 5 copies exist. I will then scan them (`cd ~; python -I -B "<SKILL_DIR>/scripts/scan.py" "<PROJECT>/reexported" --json "<PROJECT>/share-safe-report-2.json"`) and check that the number of files scanned is 5.
3. The files with a key or webhook finding (K1, K2, K3): if they were ever posted or sent before, treat that key or webhook as exposed and revoke it at the provider. Removing metadata does not take it back.

**What this scan cannot see**

- Pixel-hidden data and what the picture shows
- Data inside IDAT, JPEG entropy data and the first mdat, ICC profile contents and UTF-16 text in raw regions
- Contents of C2PA manifests
- Secrets split, re-encoded or glued to a letter, placeholder values, unrecognised secret field names, vendor key formats outside its eight and webhooks other than Discord and Slack
- Formats it cannot open (WebP, GIF, WebM, HEIC) and addresses other than 10.x, 172.16-31.x and 192.168.x (IPv6, loopback, link-local, CGNAT, public)

---

**User:** Please run those exports into a folder called `reexported` and check the result.

**Assistant:** You asked for the exports, so I'll run them, writing only to new names in `reexported/` (step 5). Each ffmpeg command exited 0 and printed nothing.

```sh
cd ~; mkdir "<PROJECT>/reexported"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/01_png_api_key_and_username.png" -map_metadata -1 "<PROJECT>/reexported/01_png_api_key_and_username.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/02_png_ztxt_webhook.png" -map_metadata -1 "<PROJECT>/reexported/02_png_ztxt_webhook.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/03_png_bypassed_node_secret.png" -map_metadata -1 "<PROJECT>/reexported/03_png_bypassed_node_secret.png"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/05_mp4_prompt_tag_and_free_box.mp4" -map_metadata -1 -map_chapters -1 -c copy "<PROJECT>/reexported/05_mp4_prompt_tag_and_free_box.mp4"
cd ~; ffmpeg -loglevel error -n -i "<PROJECT>/renders/06_jpeg_exif_gps.jpg" -map_metadata -1 -q:v 2 "<PROJECT>/reexported/06_jpeg_exif_gps.jpg"
```

Now the scan of the copies, with a new report name outside the copies folder:

```sh
cd ~; python -I -B "<SKILL_DIR>/scripts/scan.py" "<PROJECT>/reexported" --json "<PROJECT>/share-safe-report-2.json"
```

Exit code: **0**. The JSON report is `<PROJECT>/share-safe-report-2.json`; it stays there.

```
Share-Safe Renders scan.py 1.2.0
Scanned 5 file(s): 0 with findings, 0 finding(s), 0 problem(s); 0 link(s) not followed, 0 unrecognized file(s) skipped; ffprobe: used.
RESULT: NOTHING FOUND in what was scanned (this is not proof of safety; see known misses) (exit 0)

KNOWN MISSES (not detected by design)
  - Data hidden in pixel bits (steganography, LSB or otherwise).
  - Secrets, faces, logos or text that appear in the generated pixels themselves.
  - The contents of C2PA / Content Credentials manifests are not decoded or classified.
  - The image or video content itself (what the picture shows).
  - Secrets that were base64-, hex-, rot13- or otherwise re-encoded, or split across fields.
  - ICC profile contents, and audio/video sample data (incl. the first mdat).
  - Data hidden inside the compressed image stream itself (PNG IDAT, JPEG entropy-coded segments).
  - UTF-16 text inside raw (unparsed) regions such as trailing data; UTF-16 whole-chunk text is decoded.
  - Containers other than PNG, JPEG, MP4/MOV and plain JSON (WebP, GIF, WebM, HEIC, AVIF ... are reported as not scanned; in a folder, other unrecognized file types are only counted as skipped).
  - IPv6 addresses, loopback, link-local and CGNAT ranges, and public IPv4 addresses.
  - Vendor key formats other than the eight it knows (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face), webhook URLs other than Discord and Slack, and secrets in fields whose names it does not recognise.

RESULT: NOTHING FOUND in what was scanned (this is not proof of safety; see known misses) (exit 0)
```

**Assistant:**

**Verdict.** Nothing found in 5 file(s) scanned. That is not a guarantee.

**Findings.** None.

**How to fix.** 5 copies were made and 5 were scanned, so every copy was checked. Nothing found in what was scanned; whether to share is your decision. `04_clean.png` was not re-exported and still carries its embedded ComfyUI prompt. Keep the originals private, and revoke any key or webhook that was in a file you have already shared.

**What this scan cannot see**

- Pixel-hidden data and what the picture shows
- Data inside IDAT, JPEG entropy data and the first mdat, ICC profile contents and UTF-16 text in raw regions
- Contents of C2PA manifests
- Secrets split, re-encoded or glued to a letter, placeholder values, unrecognised secret field names, vendor key formats outside its eight and webhooks other than Discord and Slack
- Formats it cannot open (WebP, GIF, WebM, HEIC) and addresses other than 10.x, 172.16-31.x and 192.168.x (IPv6, loopback, link-local, CGNAT, public)

---

**User:** One more folder, `extras/`. I want to zip the whole thing and send it.

**Assistant:** The whole folder will be shared, so I'll add `--strict` (step 2): links and files that are not renders must not be skipped silently. The report goes next to the folder, with a new name.

```sh
cd ~; python -I -B "<SKILL_DIR>/scripts/scan.py" "<PROJECT>/extras" --strict --json "<PROJECT>/share-safe-report-3.json"
```

Exit code: **3**. The JSON report is `<PROJECT>/share-safe-report-3.json`; it stays there.

```
Share-Safe Renders scan.py 1.2.0
Scanned 1 file(s): 0 with findings, 0 finding(s), 3 problem(s); 0 link(s) not followed, 1 unrecognized file(s) skipped; ffprobe: not needed.
RESULT: COULD NOT SCAN everything and found nothing else - treat as NOT clean (exit 3)

COULD NOT FULLY SCAN (never treat these as clean)
  ERROR unsupported_media  file=<PROJECT>/extras\loop.webp
  ERROR png_truncated  file=<PROJECT>/extras\render_cut.png  carrier=png
  ERROR strict_skipped_entries  file=(all paths)

NOTES
  skipped_other  file=<PROJECT>/extras\notes.txt
  embedded_comfyui_api_json  file=<PROJECT>/extras\render_cut.png

KNOWN MISSES (not detected by design)
  - Data hidden in pixel bits (steganography, LSB or otherwise).
  - Secrets, faces, logos or text that appear in the generated pixels themselves.
  - The contents of C2PA / Content Credentials manifests are not decoded or classified.
  - The image or video content itself (what the picture shows).
  - Secrets that were base64-, hex-, rot13- or otherwise re-encoded, or split across fields.
  - ICC profile contents, and audio/video sample data (incl. the first mdat).
  - Data hidden inside the compressed image stream itself (PNG IDAT, JPEG entropy-coded segments).
  - UTF-16 text inside raw (unparsed) regions such as trailing data; UTF-16 whole-chunk text is decoded.
  - Containers other than PNG, JPEG, MP4/MOV and plain JSON (WebP, GIF, WebM, HEIC, AVIF ... are reported as not scanned; in a folder, other unrecognized file types are only counted as skipped).
  - IPv6 addresses, loopback, link-local and CGNAT ranges, and public IPv4 addresses.
  - Vendor key formats other than the eight it knows (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe live, Hugging Face), webhook URLs other than Discord and Slack, and secrets in fields whose names it does not recognise.

RESULT: COULD NOT SCAN everything and found nothing else - treat as NOT clean (exit 3)
```

**Assistant:**

**Verdict.** Could not scan everything, and found nothing in what could be read. Treat these files as NOT checked.

**Findings.** None were found in what could be read, which is not the same as none present:

- `extras/loop.webp` (`unsupported_media`): the scanner does not open this format. Export a still as JPEG, or a video as MP4, from the program that made it and scan that, or leave it unchecked.
- `extras/render_cut.png` (`png_truncated`): the file ends early, so part of it was not read. Re-export or re-copy it.
- (`strict_skipped_entries`): with `--strict`, 1 file(s) that are not renders count as not examined; `NOTES` names them: `extras/notes.txt`. Move them out of the folder or scan without `--strict`; either way they were not examined.

1 PNG file(s) carry an embedded ComfyUI workflow (`extras/render_cut.png`). The prompt text, model names, seeds and node layout travel with the file although they are not findings.

**How to fix.** Replace or re-export the files above, put them in the folder, and run the same command again with a new report name. Do not describe `extras/` as checked until that run exits 0.

**What this scan cannot see**

- Pixel-hidden data and what the picture shows
- Data inside IDAT, JPEG entropy data and the first mdat, ICC profile contents and UTF-16 text in raw regions
- Contents of C2PA manifests
- Secrets split, re-encoded or glued to a letter, placeholder values, unrecognised secret field names, vendor key formats outside its eight and webhooks other than Discord and Slack
- Formats it cannot open (WebP, GIF, WebM, HEIC) and addresses other than 10.x, 172.16-31.x and 192.168.x (IPv6, loopback, link-local, CGNAT, public)
