# How to export a copy without the metadata, and check it

`scan.py` never edits a file. A re-exported copy without the metadata is made by another tool, and the check is a second scan of the
copy: the tool that scrubs and the tool that checks are different programs, so the check is not circular.

Rules for every method below:

- Write to a **new file name**. Never write over the original, and never let a tool write to the file it is reading. Use a name that
  does not exist yet: ffmpeg's `-n` option leaves an existing output file alone, but the exit code depends on the build (measured: 7.1, 8.1.1 and 9.0.1
  print "already exists. Exiting." and exit 0, 5.1 prints it and exits 1), so a reused name makes an old file look like the fresh copy on most builds.
- Check that the export command itself exited 0 and wrote a file before you scan it. A failed command can leave a partial file (an animated PNG does, see below).
- Put double quotes around every path in the commands, never single quotes. Paste a file name into a command only if it passes the rule in `SKILL.md` ("Names in commands"): ASCII letters, digits, spaces
  and `. _ ( ) + -` only (`^[A-Za-z0-9 ._()+-]+$`, the whole name), not starting with `-`, not ending with a dot or a space, not a Windows device name such as `NUL`. Typographic quotes, non-ASCII characters, `%` and `!` (cmd), `$`, a backtick,
  quotes, `;` `&` `|` `^` `<` `>` and line breaks are excluded. For any other name copy the file to a plain name first, or run the command yourself. Single quotes
  do not make such a name safe: Windows PowerShell 5.1 treats a typographic quote (U+2018, U+2019, U+201A, U+201B, U+201C, U+201D, U+201E) as a quote character, so it ends a quoted string and the rest of the name runs as a command.
  The folder above the file name is held to a shorter list: it may hold letters of any language and apostrophes, but not `"`, a typographic double quote, `$`, a backtick, `%`, `!` or a line break; if it does, move the files to a plain-named folder or run the command yourself.
- Run every command on this page from a folder you trust, such as your home folder, with every path in full, and never from inside the folder of the files you export or any other folder of files you received: on Windows, cmd starts an `ffmpeg.bat`, `ffprobe.bat` or `python.bat` from the working folder in place of the real program ("Where to run them" in `SKILL.md`). Use PowerShell or bash; in cmd, first run `set NoDefaultCurrentDirectoryInExePath=1` in the same session, or, if each command starts a new cmd, in front of it on the same line, with nothing before it (not `cd ~;`): `set NoDefaultCurrentDirectoryInExePath=1& <command>`.
- ffmpeg prints a file's tags to the terminal unless you give it `-loglevel error` (the demo MP4's prompt tag appeared in its output, cut at 255 characters, which is enough to show a key). The commands below include it.
- Scan the **copy**, not the original, and read the exit code of that second scan. Exit 0 on the copy means nothing was found in what was
  scanned; that is not a guarantee. Exit 1 means the method left findings in. Exit 2 or 3 means the copy is unchecked, not that the method failed.
  The re-scan is the check on every ffmpeg build, because the builds differ (next section).
- If you share, share the copy, not the original. If the original was already shared or uploaded anywhere, a copy does not
  undo that: revoke or rotate any key or webhook that was in it.

## What was verified, and on which ffmpeg build

Everything marked **verified** was run on the demo files from `scripts/make_demo.py` (or, where the row says so, on another small synthetic file made for the test), on Windows 11
with Python 3.14.6 (Pillow 12.3.0 for the Pillow rows; the Pillow command was also run on the 22 other Pillow releases from 9.0.0 to 12.2.0, see "Pillow versions" below), and the copy was re-scanned with `scan.py`. The ffmpeg builds were 5.1 (an "essentials" build), 7.1 (essentials), 8.1.1 (a "full" build) and
9.0.1 (git build n9.0.1-11 of 2026-08-31), all Windows x64. The 7.1 folder has no ffprobe, so the ffprobe checks of that run used the 8.1.1 ffprobe. "The four builds" on this page are these four Windows builds. Linux and Windows were used for the Pillow rows (see "Pillow versions") and Linux for the statements below that name ffmpeg 4.4.2, the Ubuntu 22.04 package, run in a container. The tests behind this page also ran with the ffmpeg of Debian 12 (5.1.9), Ubuntu 24.04 (6.1.1) and Ubuntu 26.04 (8.0.1); for a build that the per-build table below does not list they check only what holds on every build, so the "by build" results are not recorded for those three, nor for 4.4.2. Nothing here was run on macOS,
and other builds of the same version numbers, or other versions, may behave differently. A method that is not listed as verified is not claimed to work. The re-scan is what decides.

Where the four builds agree, one row says so. Where they differ, the row says **by build** and the next table has the numbers.

| File | Method | Status | Result of the re-scan |
| --- | --- | --- | --- |
| MP4/MOV | ffmpeg remux (no re-encode) with `-map_metadata -1 -map_chapters -1 -c copy` | verified, all four builds | exit 0 on the demo MP4: prompt tag gone, hidden `free` box gone; decoded frames identical to the original. Keeps one video and one audio stream (see below). |
| PNG (text chunks) | ffmpeg re-encode with `-map_metadata -1` | verified, all four builds | exit 0 on all three leaking demo PNGs (plain text chunk, compressed chunk, bypassed node); decoded pixels identical on the one that was compared |
| PNG with EXIF (carrier `png:eXIf`, or a `Raw profile type exif` text chunk) | ffmpeg re-encode with or without `-map_metadata -1` | **by build** | 8.1.1 and 9.0.1: exit 1, GPS (G1) and an e-mail address (P2) still there, now in an `eXIf` chunk of the new file. 5.1 and 7.1: exit 0, the EXIF was not carried. Do not rely on the build you have: use the next row. |
| PNG with EXIF | the Pillow command below (it passes empty `exif`, `comment` and `xmp` values), or ffmpeg to JPEG with `-q:v 2` | verified (ffmpeg: all four builds; Pillow: all 23 versions of "Pillow versions") | exit 0 on a PNG with an `eXIf` chunk and on a PNG with a `Raw profile type exif` text chunk (synthetic, made for this test). A plain `Image.open(src).save(dst)` does **not** work on every Pillow version: it kept the `eXIf` chunk on Pillow 9.0.0 to 9.3.0 (exit 1, G1 and P2). |
| Animated PNG | the ffmpeg PNG command above | verified **not to work**, all four builds | ffmpeg exits non-zero (1 on 5.1, 4294967274 on the others, which is -22 as Windows shows it) and leaves a one-frame file; that file re-scans as exit 0. Check the exit code of the export. |
| Animated PNG | ffmpeg with `-f apng -plays 0` | verified, all four builds | all 5 frames kept, exit 0 on a synthetic 5-frame file |
| Animated PNG | ffmpeg with `-c copy -f apng -plays 0` | verified **not to work**, all four builds | exit 1: the text chunk was copied along |
| Animated PNG | Pillow `save`: a plain one, and the command below as printed | verified **not to work**, all 23 Pillow versions | exit 0 on every version, but only the first frame is written (the copy has no `acTL` chunk) and the copy re-scans as exit 0: silent loss. Table under "Pillow versions". |
| JPEG | ffmpeg re-encode with `-map_metadata -1 -q:v 2` | verified, all four builds | exit 0 on the demo JPEG: EXIF GPS gone. The picture is re-compressed (a generation of quality loss). |
| JPEG | ffmpeg with `-c copy` | verified **not to work**, all four builds | exit 1: the EXIF GPS block was copied along with the picture. Do not use it. |
| PNG and JPEG | the Pillow command below | verified (it does not depend on the ffmpeg build; Pillow: all 23 versions of "Pillow versions") | exit 0 on the demo PNGs and the demo JPEG, and on a PNG with an `eXIf` chunk, a JPEG with a `COM` comment and a JPEG with an XMP packet; the PNG's decoded pixels are identical. The JPEG is re-compressed. |
| PNG and JPEG | Pillow plain `Image.open(src).save(dst)`, without the three empty values | verified **not to work** (on every Pillow version in the table, one of the three files keeps its data) | exit 1 on a PNG with an `eXIf` chunk (Pillow 9.0.0 to 9.3.0), on a JPEG with a `COM` comment (9.4.0 and later) and on a JPEG with an XMP packet (11.0.0). See "Pillow versions". |
| WebP (still) | ffmpeg to JPEG with `-map_metadata -1 -q:v 2`, or the Pillow command below to PNG | verified (ffmpeg: all four builds; Pillow: the command as printed, all 23 versions) | exit 0 on a synthetic WebP whose EXIF held a workflow with a fake key. A plain Pillow `save` to PNG carried that EXIF into the PNG on Pillow 9.0.0 to 9.3.0 (exit 1, K1 and K2) and did not on 9.4.0 and later. Table under "Pillow versions". |
| WebP (still) | ffmpeg to PNG | **by build** | 8.1.1 and 9.0.1: exit 1, K1 and K2 from the EXIF, now in an `eXIf` chunk. 5.1 and 7.1: exit 0. Use the JPEG route. |
| Animated WebP, GIF | ffmpeg | **not verified** | ffmpeg 8.1.1 could not read the one animated WebP made for this test (exit 69). Export from the application that made it. |
| Animated WebP, GIF | the Pillow command below, to PNG | verified **not to work**, all 23 Pillow versions | exit 0 on a synthetic 5-frame WebP and a synthetic 5-frame GIF, but the PNG has only the first frame (silent loss). Export from the application that made it. |
| ComfyUI | start the server with `--disable-metadata`, so new renders carry no workflow | **not verified** (ComfyUI was not run) | this prevents the leak at the source for new files only; scan the result like any other file |
| Any file | exiftool, jpegtran, Photoshop "Save for Web", mobile "remove location" and similar | **not verified** | not run here. Use the re-scan to decide. |

What differs between the builds, measured on the same input files:

| Measured | 5.1 | 7.1 | 8.1.1 | 9.0.1 |
| --- | --- | --- | --- | --- |
| PNG with EXIF through the ffmpeg PNG command: exit of the re-scan | 0 | 0 | 1 | 1 |
| Still WebP (EXIF with a fake key) to PNG: exit of the re-scan | 0 | 0 | 1 | 1 |
| `-n` on an existing output: exit code of ffmpeg (the old file is kept on all four) | 1 | 0 | 0 | 0 |
| Animated PNG through the PNG command: exit code of ffmpeg (Windows) | 1 | 4294967274 | 4294967274 | 4294967274 |

## MP4 and MOV

```sh
ffmpeg -loglevel error -n -i "<IN.mp4>" -map_metadata -1 -map_chapters -1 -c copy "<OUT.mp4>"
```

`-n` keeps ffmpeg from overwriting an existing output (see the rule above about reused names). `-c copy` copies the video and audio streams without re-encoding, so quality is
unchanged and it is fast. `-map_metadata -1` drops the global tags; `-map_chapters -1` drops chapters. The hidden boxes
disappear because ffmpeg rewrites the file from the streams it understands.

Measured details (the same on all four builds, except where a bullet says otherwise):

- The flag matters for standard tags. With a workflow in the `comment` tag, a plain `-c copy` remux without `-map_metadata -1` **kept**
  it (re-scan: exit 1) and the command above removed it (exit 0). With the tag called `prompt` (the demo file) a plain
  remux dropped it as well, and adding `-movflags use_metadata_tags` kept it (measured), so ffmpeg's MP4 writer drops tag names it does not know unless `-movflags use_metadata_tags` is given.
  Do not rely on that: use the flag and re-scan.
- Streams: with no `-map`, ffmpeg keeps one video and one audio stream. On a test file with two audio tracks, a subtitle track and a data stream, the command above kept only the video and the first audio track, and the re-scan still said exit 0.
  Adding `-map 0` before `-map_metadata` kept both audio tracks and the subtitle (not the data stream); that variant has its own re-scan. The demo MP4 has no audio, so audio was exercised only in this extra test. If the file has more than one audio track or has subtitles, compare the streams of the original and the copy (see "Check the copy").
- Tags that stay: the stream-level `handler_name` and `language` stay in the output; they are ordinary and the scanner did not report them. The stream-level `encoder` tag does not stay (measured by running ffprobe with `-show_entries format_tags:stream_tags` on the demo MP4 and on its copy). Whether the demo MP4 has that tag to begin with depends on the ffmpeg that made it: the four builds listed above write it into an MP4 (a value such as `Lavc62.28.101 libx264`) and it is gone from the copy; ffmpeg 4.4.2 (the Ubuntu 22.04 package, run in a container) writes none into an MP4, so there is nothing to drop and the copy has none either. The format-level `encoder` tag of the copy is `Lavf` and the libavformat version of the ffmpeg that exported it (for example `Lavf62.12.101` for 8.1.1), whatever the source file had there. If a stream
  tag could carry something of yours, the re-scan will say so.

For a `.mov` output the same options are expected to behave the same way. That was **not verified**.

## PNG

```sh
ffmpeg -loglevel error -n -i "<IN.png>" -map_metadata -1 "<OUT.png>"
```

This decodes the picture and writes a new PNG. On all four builds the PNG writer does not carry the text chunks (`tEXt`, `zTXt`, `iTXt`) across: a re-encode
**without** `-map_metadata -1` also dropped them (verified, control run). The flag is kept as a belt-and-braces option; the
re-scan, not the flag, is the check. A different ffmpeg version may behave differently.

**EXIF is different, and depends on the build.** On ffmpeg 8.1.1 and 9.0.1 the PNG writer puts a PNG's EXIF into an `eXIf` chunk of the new file, and turns a `Raw profile type exif` text chunk into an `eXIf` chunk. GPS and e-mail addresses inside a PNG's EXIF therefore
survive the command above (measured, with and without the flag: re-scan exit 1, G1 and P2). On ffmpeg 5.1 and 7.1 the same command did not carry the EXIF (re-scan exit 0). So the safe instruction does not depend on your build: if the report shows an `exif:` location, a `tag0x...` or `tag~...` location or the carrier `png:eXIf`, use the Pillow command below, or export a JPEG, and re-scan the copy whichever method you used.

**Animated PNG** (a file with several frames, such as ComfyUI's animated PNG output): the command above fails with "Conversion failed" and leaves a one-frame file behind, and that file re-scans as nothing found. Use:

```sh
ffmpeg -loglevel error -n -i "<IN.png>" -map_metadata -1 -f apng -plays 0 "<OUT.png>"
```

`-plays 0` means loop forever; set it to match the original if it looped a fixed number of times. This kept all frames of the synthetic test file (compare frame counts, see "Check the copy"). Do not use `-c copy -f apng`: it kept the text chunk in the one run that tried it on each build.

Things a re-encode can change, which were **not** all checked: ffmpeg chooses the pixel format; 16-bit and palette PNGs were not tested. The decoded pixels of the demo PNG were identical (compared with ffmpeg's `framemd5` output). Colour profiles: ffmpeg kept the `iCCP` chunk of a test PNG on all four builds, so a
profile name stays in the copy (ffmpeg 4.4.2, the Ubuntu 22.04 package run in a container, writes no `iCCP` chunk into a PNG, so with that build the profile is gone from the copy). The scanner reads a profile's name but not its contents (see `known-misses.md`), so text inside a colour profile is neither found nor removed by these methods.

If you already work in Python with Pillow installed:

```sh
python -c "import sys; sys.path = [p for p in sys.path if p]; from PIL import Image; Image.open(sys.argv[1]).save(sys.argv[2], exif=bytes(), comment=bytes(), xmp=bytes())" "<IN.png>" "<OUT.png>"
python -c "import sys; sys.path = [p for p in sys.path if p]; from PIL import Image; Image.open(sys.argv[1]).save(sys.argv[2], exif=bytes(), comment=bytes(), xmp=bytes())" "<IN.jpg>" "<OUT.jpg>"
```

The paths are passed as arguments and never written into the code, so a file name with a quote or a backslash in it cannot change what the Python code does (the shell that starts Python still reads the name, hence the name rule above). The first statement takes the working folder off Python's search path before Pillow is imported, so a folder named `PIL` or a file named like a part of Python in the working folder (the renders folder, for example) is not run; Python's `-I` option would do that too, but it also hides a Pillow that was installed for your user only. Pillow writes text chunks only when you pass them in (`pnginfo=`).
**EXIF, a JPEG comment and an XMP packet are different, and depend on the Pillow version:** some versions copy them from the source file into the copy by themselves when you pass nothing (table below). So the command passes an empty value for each of the three (`exif=bytes()`, `comment=bytes()`, `xmp=bytes()`), and does not rely on a default of the Pillow you have. Keep the three, and do not pass `pnginfo`, `exif`, `comment`, `xmp` or `icc_profile` from the source.
Pillow keeps a PNG's colour profile by itself (the `iCCP` chunk was still there, on all 23 versions) and drops a JPEG's unless `icc_profile=` is given. A plain `save` of an animated PNG writes only the first frame and still exits 0, and so does the command above: do not use either on animated files. Pillow is not part of this skill and is not required.

### Pillow versions

What a plain `Image.open(src).save(dst)` copies from the source file depends on the Pillow version. Measured on synthetic files, the same bytes for every version, each copy re-scanned with `scan.py`. The first three columns are a plain `save`; the last is the command above, which was run on the same three files and on the other test files (text, compressed and international text chunks, `Raw profile type exif`, a palette PNG, a PNG with transparency, a JPEG with EXIF, XMP and COM together):

| Pillow versions run | PNG with an `eXIf` chunk: plain `save` | JPEG with a `COM` comment: plain `save` | JPEG with an XMP packet: plain `save` | The command above, on every file |
| --- | --- | --- | --- | --- |
| 9.0.0, 9.0.1, 9.1.0, 9.1.1, 9.2.0, 9.3.0 | exit 1: G1 and P2 kept | exit 0 | exit 0 | exit 0 |
| 9.4.0, 9.5.0, 10.0.0, 10.0.1, 10.1.0, 10.2.0, 10.3.0, 10.4.0 | exit 0 | exit 1: P2 kept | exit 0 | exit 0 |
| 11.0.0 | exit 0 | exit 1: P2 kept | exit 1: G1 kept | exit 0 |
| 11.1.0, 11.2.1, 11.3.0, 12.0.0, 12.1.0, 12.1.1, 12.2.0, 12.3.0 | exit 0 | exit 1: P2 kept | exit 0 | exit 0 |

The XMP packet in the probe JPEG held GPS coordinates only; on 11.0.0 a packet that also held an e-mail address kept both G1 and P2 in a plain `save` (8 recorded environments). So there is no Pillow version in this table on which a plain `save` is safe for all three files, and a plain `save` is not an instruction this skill gives. The 23 versions in the table are every final release from 9.0.0 to 12.3.0 that PyPI listed on 2026-10-13. Every cell of both tables was measured for each of the 23, from PyPI wheels, on Linux x86-64 with Python 3.10.12 and on Windows with Python 3.10.21. On Linux the two printed lines of the command were run by `bash -c`, with `python` standing for that interpreter; on Windows each line was split into arguments and run without a shell. Every cell of both tables was measured again on 2026-10-15, after the search-path statement was added to the command, in the same 159 combinations of Python and Pillow (the four distribution packages included), with the same results. The cells were measured again with the other Pythons that PyPI has a wheel of that version for, and were the same: on Linux Python 3.11.2 (19 of the versions), 3.12.3 (15) and 3.14.4 (6), on Windows 3.9.25 (18), 3.11.15 (19), 3.12.11 (16), 3.13.13 (10) and 3.14.6 (6). The distribution packages python3-pil 9.0.1 (Ubuntu 22.04), 9.4.0 (Debian 12), 10.2.0 (Ubuntu 24.04) and 12.1.1 (Ubuntu 26.04) gave the same results as the same version from PyPI. In the Pillow source the cause is a fallback to the source file's own data: `exif` for a PNG up to 9.3.0, `comment` for a JPEG from 9.4.0, `xmp` for a JPEG in 11.0.0 only. A Pillow version that is not in the table was not run: the command above does not use those fallbacks, but the re-scan of the copy is what decides. On the PNG test files, including the palette PNG and the PNG with transparency, the decoded pixels of the copy were identical to the source's on every version.

Two more files, run the same way on the same 23 versions: a still WebP whose EXIF holds a workflow with a fake key, saved to PNG, and an animated PNG of 5 frames whose text chunk holds a fake key. Each copy was re-scanned; "the command above" is the command as printed, with the two paths filled in.

| Pillow versions run, same 23 | Still WebP to PNG: plain `save` | Still WebP to PNG: the command above | Animated PNG: plain `save` | Animated PNG: the command above |
| --- | --- | --- | --- | --- |
| 9.0.0, 9.0.1, 9.1.0, 9.1.1, 9.2.0, 9.3.0 | exit 1: K1 and K2 kept | exit 0 | exit 0, one frame | exit 0, one frame |
| 9.4.0, 9.5.0, 10.0.0, 10.0.1, 10.1.0, 10.2.0, 10.3.0, 10.4.0, 11.0.0, 11.1.0, 11.2.1, 11.3.0, 12.0.0, 12.1.0, 12.1.1, 12.2.0, 12.3.0 | exit 0 | exit 0 | exit 0, one frame | exit 0, one frame |

On every version the copy of the animated PNG is one frame with no `acTL` chunk, and its decoded pixels are those of the first frame of the source; its text chunk is not carried over, which is why the copy re-scans as exit 0 although four frames are gone.

## JPEG

```sh
ffmpeg -loglevel error -n -i "<IN.jpg>" -map_metadata -1 -q:v 2 "<OUT.jpg>"
```

This re-encodes the picture (quality level 2, high), so there is a small quality loss. **Do not use `-c copy` for a JPEG:** the
EXIF block travels with the compressed picture and the GPS position stays (verified on all four builds: re-scan exit 1). ffmpeg also kept the colour profile of a test JPEG.

A lossless way to drop EXIF from a JPEG exists in other tools. None was run here, so none is claimed. The Pillow command above also works for a JPEG (it re-compresses at Pillow's default quality).

## Formats the scanner does not open (WebP, GIF and similar)

`scan.py` exits 3 on these (`unsupported_media`), so they are unchecked. To check what you would share, export a still image and scan that. For a still WebP:

```text
ffmpeg -loglevel error -n -i "<IN.webp>" -map_metadata -1 -q:v 2 "<OUT.jpg>"
```

Do not export a PNG with ffmpeg from a WebP: on ffmpeg 8.1.1 and 9.0.1 the EXIF came through into the PNG's `eXIf` chunk in the test (exit 1; 5.1 and 7.1 did not carry it, exit 0, but do not depend on that). The test WebP carried a ComfyUI-style `prompt:` and `workflow:` text in two EXIF tags; that this is how ComfyUI saves WebP is **not verified** here. For an animated WebP or a GIF there is no verified command; export again from the application that made it, as an MP4 or as stills, and scan that.

## Workflow JSON

A `.json` workflow has no export command in this skill. The user opens it in the application that wrote it (or a text editor), removes or replaces the value the report names at that node id and location, and saves a new file. The scanner does not edit it. Scan the new file; the re-scan decides.

## ComfyUI and other generators

Prevent the leak for future renders:

- Start ComfyUI with `--disable-metadata` so it does not write the prompt and workflow into saved files. **Not verified**: ComfyUI
  was not run while this skill was built. Check a new render with the scanner: for a PNG, a `NOTES` line `embedded_comfyui_api_json` or `embedded_comfyui_ui_json`
  means the workflow is still being written; for an MP4 or MOV, an M1 finding with `workflow_json_in_tag` means the same. If neither appears, that is not a guarantee either.
- Keep keys out of node widgets. Use the environment or the node pack's own secret storage, so a key is not part of the graph that gets saved.

For renders that already exist, use the methods above, then re-scan.

## Check the copy

```sh
python -I -B "<SKILL_DIR>/scripts/scan.py" "<COPY>" --json "<REPORT>"
```

1. Run it on the copies (each file by name, or the folder of copies), with a new `<REPORT>` name that is not inside that folder. Read the exit code.
2. Exit 0 and `Scanned N file(s)` with N equal to the number of copies you made: nothing was found in what was scanned. N lower than the number of copies means a copy is missing or the export failed: those copies were not checked, whatever the exit code says. A scan that reads no file at all (an empty folder, a folder with only sub-folders) is exit 3 (`nothing_scannable`), never exit 0.
3. Exit 1: the method did not remove everything. The report says what is left. Try another method (see the table), or re-render without the leak.
4. Exit 3: the copy could not be fully scanned. Treat it as unchecked.
5. Compare to the original if you like: scan the original too and look at which classes disappeared. The hash prefixes of two reports cannot be compared, and neither can the hashed parts of a location (`~xxxxxxxx`, `kw~`, `box~`, `tag~`, `id~`) or a shortened file name: each run uses its own random key. Compare the classes, the carriers and the file names. Do not share the original.
6. A re-scan cannot tell that a copy lost a stream or frames. Compare the original and the copy:

```sh
ffprobe -v error -show_entries stream=index,codec_type -of compact "<IN.mp4>"
ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 "<IN.png>"
```

The first lists the streams of a video, the second counts the frames of an image or video. Run each on the original and on the copy; the lists and counts should match, except for the streams the MP4 section says are dropped.

A result of "nothing found" is not a guarantee. `known-misses.md` lists what the scanner cannot see, and none of the methods
above touches the picture itself.
