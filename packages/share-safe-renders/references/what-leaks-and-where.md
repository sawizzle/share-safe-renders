# What leaks, and where it sits

A render is two things in one file: the picture or video, and a set of metadata containers beside it. Sharing the file
shares both. This page lists the containers the scanner opens and what typically ends up in them. **checked** marks a
statement that was reproduced with the demo files from `scripts/make_demo.py` in this package. Every statement
without that mark describes how these tools typically behave and was not re-checked when this page was written
(ComfyUI itself was not run).

## ComfyUI-style PNG

Typical: ComfyUI's image saver writes two PNG text chunks, and most image-saving custom nodes copy that habit.

| Chunk keyword | Holds | Why it leaks |
| --- | --- | --- |
| `prompt` | the **API-format** graph: `{ "<node id>": { "class_type": ..., "inputs": { ... } } }`. It is what actually ran. | every input of every node that ran: prompt text, model and LoRA names, seeds, file paths, and any key or address a node was given as an input |
| `workflow` | the **UI-format** graph: `nodes[]` with `type`, `mode`, `widgets_values`, `inputs`, positions | the same values plus nodes that did **not** run. A bypassed node (mode 4) or muted node (mode 2) keeps its widget values here. |

What ends up in them, with the class the scanner uses:

- **K1, K2** an API key typed into a node widget (a captioning, image-to-text, translation or "call an API" node), or
  pasted into a text field to be sent along. Field names like `api_key`, `token`, `password`, `secret` are caught by name (K2);
  keys with a known vendor shape are caught by shape (K1) wherever they sit.
- **K3** a webhook URL given to a notification node (Discord, Slack).
- **P1** a path that goes through your home folder: a LoadImage input that points at a picture in your Pictures folder, a model path, an output prefix. The account name is the leak.
- **P2** an e-mail address in an author, contact or notes field.
- **P3** a LAN address or `.local` host name of your render box or a remote ComfyUI server.
- **H1** all of the above inside a bypassed or muted node. Disabling a node in the canvas does not remove its values. **checked**: the demo file `03_png_bypassed_node_secret.png` keeps the key in the `workflow` chunk only; the `prompt` chunk has no trace of the node.
- **H2** JSON stored as a string inside JSON. Some nodes keep their settings as a JSON string widget, and some savers wrap the whole metadata in a string, so a plain-text search for `"api_key": "` misses it.
- **H3** compressed chunks. PNG allows `zTXt` and compressed `iTXt`; the text is deflate-compressed on disk, so `strings` and plain-text scanners never see it. **checked**: `02_png_ztxt_webhook.png`.

In a PNG, embedded workflow JSON is **not** a finding by itself: a PNG saved by ComfyUI with default settings has it (one saved with `--disable-metadata`, or re-encoded, does not). The scanner lists it under `NOTES`
and reports only the sensitive items inside it. The prompt text, model names, seeds and node layout travel with the file
all the same, and the scanner does not judge them (see `known-misses.md`). The same graph in an MP4 or MOV tag **is** a finding (M1), a deliberate, conservative choice: players never show that tag, so the prompt rides along unseen.

Other PNG places the scanner opens: other text chunks (including `parameters`-style text written by some other tools), `eXIf`,
`Raw profile type exif` blocks, the names in `sPLT` and `iCCP`, bytes beyond the legal length of fixed chunks, unknown
chunks, and anything after the `IEND` chunk (a second PNG is walked as well).

## MP4 and MOV

A video has no standard "prompt" field, so tools put the graph in a tag.

- **Tags.** iTunes-style atoms under `moov/udta/meta/ilst` (comment, title, description, artist, software ...) and QuickTime `mdta` key/value pairs, where a tool can invent any key name (`prompt`, `workflow`). The scanner reads both, including the name, mean and unknown child boxes of a metadata item. It flags a tag that holds a ComfyUI graph (**M1**) and scans the text inside for the other classes. **checked**: the demo MP4 carries its graph in a `prompt` tag. A graph in a standard tag such as `comment` is reported the same way. A tag that holds plain words is not an M1 (see `known-misses.md`).
- **Location.** An atom named copyright-sign + `xyz` (the scanner writes it `(c)xyz`), an ISO 6709 string, or the 3GPP `loci` box holds the place the clip was recorded (**G1**). **checked**: ffmpeg writes `-metadata location=...` in an .mp4 as a `loci` box, and the built-in reader finds it with ffprobe switched off.
- **XMP.** An XMP packet in a `uuid` box can hold `exif:GPSLatitude` and `exif:GPSLongitude`.
- **Hidden boxes (M1).** A `free`, `skip`, `wide`, `junk` or `uuid` box with a payload that is not padding, a second `mdat`, an unknown top-level box, or bytes after the last box. Players ignore them, so nobody notices them. **checked**: the demo MP4 has a `free` box appended after the video data; the output of ffprobe's `-show_format` and `-show_streams` does not include its content, and `scan.py` reports it. **checked**: an ffmpeg remux with `-c copy` did not carry that box over. Other editors and muxers were not tested.
- **Stream and chapter tags.** `ffprobe` shows format, stream and chapter tags. When `ffprobe` is in a PATH directory (never the current folder), the scanner uses it as a second witness for tags only; what it adds is reported only when the built-in reader did not already report it, and the built-in reader does not depend on it. Tested against ffprobe on real ffmpeg files for the tags `comment`, `description`, `title`, `prompt`, `workflow`, `artist`, `copyright` and `location`.

Not opened: the audio and video sample data themselves (the first `mdat`).

## JPEG and common cameras

- **EXIF (APP1).** Camera make, model and serial, date and time, lens, software, and the **GPS block**: latitude, longitude, altitude, time, direction. Phones write the GPS block when location access for the camera is on. The scanner reports a non-zero GPS block as **G1**, and scans the text tags (artist, copyright, comments, Windows `XPComment` and `XPAuthor`) for the other classes, for example an e-mail address in the artist field. **checked**: `06_jpeg_exif_gps.jpg`.
- **XMP (APP1).** `exif:GPSLatitude` and `exif:GPSLongitude` are reported as G1.
- **COM and other APPn segments.** Free-text comments, vendor blocks, IPTC creator and contact fields: scanned as text.
- **After the end marker.** Bytes after the JPEG end-of-image marker (some tools append a thumbnail or a second image) are scanned; a second JPEG is walked.

Not opened: HEIC and HEIF photos (the iPhone default) and AVIF files. They look like MP4 files from the outside, but their EXIF and GPS sit in items
inside the file that this scanner does not read, so it refuses them (exit 3 when nothing else was found) instead of calling them clean. It recognises them by the file extension (.heic, .heif, .hif, .avif), by a HEIF brand as the major brand or among the compatible brands of the `ftyp` box, or by a top-level `meta` box whose handler is `pict`. Convert to JPEG first, then scan the JPEG.

Not classified: camera serial numbers, owner names and similar identifiers are not a class of their own. They are
visible to anyone with an EXIF viewer and the scanner does not flag them unless the text matches a class above.

## Plain workflow JSON

A `.json` file (a saved workflow, an exported API graph) is scanned like an embedded chunk. Large files over 16 MiB are
scanned as plain text without structure, so node ids and bypass flags are lost, but the detectors still run.

## Places that are not metadata but still leak

- **File names and folder names**: a name like `client_name_final.png`. The report shows names; it does not judge them.
- **The pixels**: a face, a logo, a screen with a password on it, text rendered into the image. Not inspected.
- **The report itself**: it repeats the paths you gave it. If your files are under your home folder, the report contains your account name.
