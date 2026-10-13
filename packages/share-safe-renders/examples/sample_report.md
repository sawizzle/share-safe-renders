# Sample report

Real output of `scripts/scan.py` 1.2.0 on the six demo files that `scripts/make_demo.py` writes. Nothing here was edited. Every secret in the demo files is invented, and the report shows none of them. `sample_report.json` is the `--json` file written by the first command.

Commands, run from a folder you can write to that is not the skill folder (`<SKILL_DIR>` is the skill folder; the names `demo` and `demo_report.json` are written into the folder you run them in):

```sh
python "<SKILL_DIR>/scripts/make_demo.py" demo
python "<SKILL_DIR>/scripts/scan.py" demo --json demo_report.json
```

### 1. The demo folder (exit 1)

```
Share-Safe Renders scan.py 1.2.0
Scanned 6 file(s): 5 with findings, 12 finding(s), 0 problem(s); 0 link(s) not followed, 1 unrecognized file(s) skipped; ffprobe: used.
RESULT: FINDINGS - do not share these files as they are (exit 1)

FINDINGS (values are never printed: only class, place, length and a hash prefix)
  [HIGH] K2  file=demo\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:11/inputs/api_key  node=11  bypassed=no  length=51  sha256=ac6bf22d  (field=api_key)
  [HIGH] K1  file=demo\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:11/inputs/api_key  node=11  bypassed=no  length=51  sha256=ac6bf22d  (vendor=openai)
  [HIGH] K3+H3  file=demo\02_png_ztxt_webhook.png  carrier=png:zTXt  location=zTXt[workflow]:nodes[1]/widgets_values[0]  node=7  bypassed=no  length=120  sha256=40be9012  (kind=discord_webhook)
  [HIGH] K2+H1  file=demo\03_png_bypassed_node_secret.png  carrier=png:tEXt  location=tEXt[workflow]:nodes[2]/widgets_values[0]/api_key  node=12  bypassed=yes  length=51  sha256=f976cc5f  (field=api_key)
  [HIGH] K1+H1  file=demo\03_png_bypassed_node_secret.png  carrier=png:tEXt  location=tEXt[workflow]:nodes[2]/widgets_values[0]  node=12  bypassed=yes  length=51  sha256=f976cc5f  (vendor=openai)
  [HIGH] K1  file=demo\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:box:free  location=free:raw  node=-  bypassed=no  length=51  sha256=18cbf43c  (vendor=openai)
  [HIGH] G1  file=demo\06_jpeg_exif_gps.jpg  carrier=jpeg:exif  location=exif:GPS  node=-  bypassed=no  length=48  sha256=4fb211c8  (kind=exif_gps;tags=lat,lon)
  [MEDIUM] P1  file=demo\01_png_api_key_and_username.png  carrier=png:tEXt  location=tEXt[prompt]:node:9/inputs/image  node=9  bypassed=no  length=12  sha256=a4ab3a67  (kind=windows_home)
  [MEDIUM] P2  file=demo\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt:node:20/inputs/~ad7ee739  node=20  bypassed=no  length=23  sha256=0d3ae817  (kind=email)
  [MEDIUM] M1  file=demo\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt  node=-  bypassed=no  length=773  sha256=d17693aa  (workflow_json_in_tag;format=api;tag=prompt)
  [MEDIUM] M1  file=demo\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:box:free  location=free  node=-  bypassed=no  length=59  sha256=0f4e377e  (hidden_box;payload=text)
  [LOW] P3  file=demo\05_mp4_prompt_tag_and_free_box.mp4  carrier=mp4:tag  location=moov/udta/meta/ilst/prompt:node:20/inputs/server  node=20  bypassed=no  length=13  sha256=500a12a5  (kind=private_ipv4)

NOTES
  embedded_comfyui_api_json  file=demo\01_png_api_key_and_username.png
  embedded_comfyui_ui_json  file=demo\02_png_ztxt_webhook.png
  embedded_comfyui_api_json  file=demo\03_png_bypassed_node_secret.png
  embedded_comfyui_ui_json  file=demo\03_png_bypassed_node_secret.png
  embedded_comfyui_api_json  file=demo\04_clean.png
  skipped_other  file=demo\DEMO_EXPECTED.md

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

How to read it: each `[HIGH]`, `[MEDIUM]` or `[LOW]` line is one finding. `K1+H1` is a vendor key held by a bypassed node; `K3+H3` is a webhook inside a compressed PNG chunk. The `1 unrecognized file(s) skipped` in the summary line is `DEMO_EXPECTED.md`, named under `NOTES` as `skipped_other`. Under `NOTES`, `embedded_comfyui_api_json` and `embedded_comfyui_ui_json` say a ComfyUI graph is in the PNG; that is not a finding by itself. Every class, location form and code is explained in `references/reading-the-report.md`.

### 2. The one PNG with only an ordinary prompt, scanned alone (exit 0)

```sh
python "<SKILL_DIR>/scripts/scan.py" demo/04_clean.png
```

```
Share-Safe Renders scan.py 1.2.0
Scanned 1 file(s): 0 with findings, 0 finding(s), 0 problem(s); 0 link(s) not followed, 0 unrecognized file(s) skipped; ffprobe: not needed.
RESULT: NOTHING FOUND in what was scanned (this is not proof of safety; see known misses) (exit 0)

NOTES
  embedded_comfyui_api_json  file=demo\04_clean.png

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

### 3. The re-scan loop: export a copy without the metadata, scan the copy (exit 0)

```sh
ffmpeg -loglevel error -n -i "demo/05_mp4_prompt_tag_and_free_box.mp4" -map_metadata -1 -map_chapters -1 -c copy "demo_copy.mp4"
python "<SKILL_DIR>/scripts/scan.py" demo_copy.mp4
```

```
Share-Safe Renders scan.py 1.2.0
Scanned 1 file(s): 0 with findings, 0 finding(s), 0 problem(s); 0 link(s) not followed, 0 unrecognized file(s) skipped; ffprobe: used.
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

The copy was made by ffmpeg, a different program from the scanner, so the second scan is a real check. "Nothing found" is not a guarantee: see `references/known-misses.md`.
