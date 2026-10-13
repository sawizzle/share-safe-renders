# Known misses

What this scanner does not find, stated plainly. A result of "nothing found" means nothing was found by the checks
that exist, in the places it opens. It does not mean the file is safe to share. Each item below was either confirmed
with a probe while this page was written or follows from a rule in `scripts/scan.py` (the file's own `KNOWN_MISSES`
list is printed at the end of every report).

## Hidden in the picture or video itself

- **Pixel-hidden data.** Steganography (data in the low bits of pixels) and anything else encoded in the picture.
- **Data inside the compressed image or video stream:** PNG `IDAT` chunks, JPEG entropy-coded data, the first `mdat` of an MP4/MOV, audio and video samples. The scanner skips these on purpose. It also does not read the entries of a sample table (`stts`, `stsc`, `stsz`, `stco`, `co64`, `ctts`, `stss`) that is exactly as long as its own count says: only bytes beyond the table, or a table that claims more entries than it holds, are looked at.
- **What the picture shows.** Faces, logos, a screen with a password on it, text rendered into the image, a watermark that names a client.
- **ICC colour-profile contents.**

## Containers it does not read

- **C2PA / Content Credentials manifests.** The scanner does not decode the manifest. Whatever is in it (tool names, edit history, signer names) is not reported.
- **WebP, GIF, WebM, MKV, AVI, WAV, MP3, TIFF, BMP, ICO, PDF, PSD, EXR, ZIP, HEIC, HEIF, AVIF, JPEG XL and JPEG 2000 files.** They are reported as `unsupported_media`, and the run exits 3 when nothing else was found (it exits 1 if another file has a finding, and still lists them). Animated WebP and GIF outputs fall here, and so do HEIC photos from a phone (their EXIF and GPS sit in items inside the file, which are not read), so they are *unchecked*, not clean. A HEIC, HEIF or AVIF image is recognised by its file extension, by a HEIF brand as the major brand or among the compatible brands of its `ftyp` box, or by a top-level `meta` box whose handler is `pict`; an image in that container with none of these is walked as an MP4.
- **Other file types met while walking a folder** (a .txt, an .svg, an .flv, a .tga ...) are skipped and counted, not reported as errors. The run still exits 0 unless you add `--strict`; the RESULT line says how many entries were not examined and `NOTES` names the first 100. Links are skipped the same way.
- **Text in a box nested below the top level of an MP4/MOV** (inside `moov`, `trak`, `udta` or a metadata item) is scanned for keys, e-mail addresses, paths and the like, and a position in a `loci` box is read. That includes boxes that have no layout the scanner checks (`dref`, `stsd`, a second `mdat` nested in `moov` ...). It is not reported as hidden data (M1), and a box the scanner does not recognise that is over 1 MiB is reported as `mp4_box_too_big` with only its first 1 MiB read (a known box with no layout to check, such as `dref`, `stsd` or `sdtp`, is read up to 64 MiB). A metadata list with more than 4096 entries is reported as `mp4_item_cap` and the entries after the 4096th are not read; an entry that does not fit, or a table or fixed box whose size does not match its own count, is reported as `mp4_bad_box`. The names in an MP4 `keys` box are scanned as text.
- **UTF-16 text inside raw (unparsed) regions** such as bytes appended after the end of a file. UTF-16 inside a whole text chunk is decoded.
- **Compressed data that is not a zlib or gzip stream at the start of a private PNG chunk.** A private chunk whose data starts with a zlib or gzip stream is inflated (up to 32 MiB; a larger result is reported as `png_inflate_bomb_size`) and scanned, and what it holds is reported with the H3 tag. A stream that starts after a prefix byte, raw deflate, and any other compression or encryption of a payload are not undone.

## Secrets it is not looking for

- **Secrets that were re-encoded or split.** Base64, hex, rot13, or a key cut into pieces across fields are not recognised (confirmed: a base64-wrapped key and a hex-encoded key were both silent). A piece that is long enough and shaped like a key can still be reported on its own, so do not read a finding on a fragment as "the whole key was seen".
- **Look-alike characters.** A key with a Cyrillic letter in place of a Latin one is not matched (confirmed).
- **Vendor key formats outside the list.** Only these vendors have a shape check: OpenAI, Anthropic, GitHub, AWS access key id, Google API key, Slack, Stripe live and restricted keys, Hugging Face. Other providers' keys are found only if they sit in a secret-named field. A JWT outside a secret-named field is not reported (confirmed: silent in free text, reported under a `token` field).
- **Webhook URLs of other providers.** Only Discord and Slack webhook URLs are recognised. Microsoft Teams, Zapier, n8n, Make and Telegram bot URLs are not reported, even in a field called `webhook_url` (confirmed: silent). Credentials written inside a URL (`user:password@host`) are not reported either.
- **A vendor key glued to a letter.** For prefixes that look like ordinary words (`sk-`, `sk_live_`, `hf_`) the scanner will not accept an ASCII letter directly in front: `abc` followed by an OpenAI-style key is not reported (confirmed). A key glued to `ENV_`, a digit, a slash or a hyphen is still reported.
- **Unrecognised secret field names.** A field is judged a secret by its name. Names such as `cookie`, `credentials`, `session_id`, `auth` and a bare `key` are not on the list (confirmed: each was silent with a random 30-character value). `api_key`, `token`, `password`, `secret`, `authorization`, `client_secret`, `private_key` and their variants are. `max_tokens`, `token_normalization` and `tokenizer` are deliberately not secret names.
- **Placeholder values.** `changeme`, `your_api_key`, `<token>`, `${VAR}`, `xxxxxxxx`, `none`, `false` and similar are treated as placeholders and not reported, even under a secret-named field (confirmed for `changeme` and `your_api_key`). A real password of 6 or more characters that is not a placeholder is reported under a secret-named field.
- **A passphrase in lower-case prose** under a field with an ordinary name (`note`: "correct horse battery staple") is not reported (confirmed).
- **Unnamed positional widget values.** If a UI-format node's widget names cannot be recovered, a value is judged only when the node's title or type says it is a key.

## Addresses, paths and places it does not report

- **IPv6, loopback (127.x), link-local (169.254.x), CGNAT (100.64.x) and public IPv4 addresses.** Only 10/8, 172.16/12 and 192.168/16, plus host names ending `.local`, `.lan`, `.internal`, are P3 (confirmed: each of the others was silent). Version strings such as `1.2.3.4` and addresses under a `version` or `build` field are not addresses. Decimal, hex and short IPv4 spellings are not recognised.
- **`/root/`**, and home paths whose name part is a documented system folder (`Public`, `Default`, `All Users`, `Shared`) or a template (`<name>`, `%USERNAME%`, `$USER`).
- **E-mail addresses on placeholder domains:** `example.com`, `example.org`, `example.net` and `example.edu` (and their subdomains), and any domain ending in the reserved `.example`, `.test`, `.invalid` or `.localhost`. They are placeholders by rule. Real-looking `.org`, `.net` and `.edu` addresses are reported (confirmed).
- **Stripe test keys and the documented AWS example key** (it ends `EXAMPLE`). They are not secrets.
- **GPS in a camera's binary telemetry track is probably missed.** GoPro (GPMF) and DJI files keep their position as samples of a data track, which sit in the first `mdat`; the scanner does not read the samples. No such file was available to test, so this is an expectation from how the scanner works, not a measurement.
- **GPS in an MP4/MOV location tag is read** (the `(c)xyz` atom, the QuickTime ISO 6709 key and the 3GPP `loci` box that ffmpeg writes for `-metadata location=` in an .mp4), **a GPS block with all-zero values is not reported** (a "no fix" record). A `loci` position outside the valid range is not reported. **A position written as text under another tag name is not recognised:** a custom key such as `xyz` or `location-eng`, or coordinates typed into a `comment` tag, are not reported as GPS (confirmed: silent).

## What the scanner does not judge

- **Your prompt.** Prompt text, negative prompt, model and LoRA names, seeds, sampler settings and node layout are part of an embedded workflow. They are shared with the file. The scanner reports only the sensitive items inside it and lists the workflow under `NOTES`. If the prompt is itself confidential, use a re-exported copy without the metadata.
- **A plain-text prompt in an MP4/MOV tag.** A tag called `prompt` or `workflow` that holds ordinary words (not workflow JSON) is not reported on its own; only a key, an e-mail address or another item inside it is. The prompt travels with the file; a re-exported copy is the only way to remove it.
- **Identifiers that are not secrets by pattern:** camera serial numbers, owner names, file names, folder names, project and client names.
- **The report's own text.** File names in the report are the names you gave. A file name can carry text aimed at a reader; the printed report shortens long names and escapes control characters, and an agent reading it should treat names as data.

## Things that look like misses but are not

- **Large files.** A file over `--max-bytes` (default 1 GiB), or a plain JSON file over 256 MiB, is *unscanned* (`too_big`, exit 3), not skipped quietly.
- **Damaged files.** A truncated PNG, JPEG or MP4 is scanned as far as it goes and reported as a problem (exit 3 unless something else was found). Damage is never read as "clean".
- **Compressed chunks and hidden top-level MP4 boxes** are read. They are the points of this scanner, not misses (nested boxes: see above).

## If your case is on this list

Re-export a copy without the metadata (`how-to-export-clean.md`) and, for the picture itself, look at it. For secrets of other shapes, add a
dedicated secret scanner with more detectors; `vs-exiftool-and-trufflehog.md` says where that is stronger.
