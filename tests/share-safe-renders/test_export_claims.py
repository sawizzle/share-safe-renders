# -*- coding: utf-8 -*-
"""references/how-to-export-clean.md says which export methods were verified. Re-run each claim on the demo files:
the command text is read out of the doc, the copy is re-scanned with scan.py, and the controls (the same file exported
a way the doc says does NOT work) must still leak."""
import json
import os
import re
import struct
import subprocess
import sys
import unittest

from _base import PKG, SCAN, ScanCase, have_ffmpeg, read_bytes, read_text
import _build as B
import doc_commands as DC

DOC = read_text(os.path.join(PKG, "references", "how-to-export-clean.md"))
TEMPLATES = {}
APNG = None
for _c in DC.extract("how-to-export-clean.md", DOC):
    m = re.search(r"<IN\.(\w+)>", _c.text)
    if m and _c.text.startswith("ffmpeg"):
        if "-f apng" in _c.text:
            APNG = _c
        else:
            TEMPLATES.setdefault(m.group(1), _c)         # the first command of each file type is the documented one
PILLOW = {m.group(1): _c for _c in DC.extract("how-to-export-clean.md", DOC) if "PIL" in _c.text
          for m in [re.search(r"<IN\.(\w+)>", _c.text)] if m}
WEBP = re.search(r"```text\n(ffmpeg [^\n]*<IN\.webp>[^\n]*)\n```", DOC).group(1)


# ----------------------------------------------------------------------------------------------------------------------
# What a Pillow save copies from the source file depends on the PILLOW VERSION (table "Pillow versions" in how-to-export-clean.md, run on
# every release from 9.0.0 to 12.3.0): a plain save keeps a PNG's eXIf chunk up to 9.3.0, a JPEG's COM comment from 9.4.0 and a JPEG's XMP
# packet in 11.0.0 only. So there is no version on which a plain save is safe for all three, and the documented command passes an empty
# value for each. A test that depends on the version compares this machine's Pillow with the row of that table; for a version the table
# does not list it checks only what must hold on every version: the documented command leaves nothing the scanner knows.
# ----------------------------------------------------------------------------------------------------------------------
PLAIN_SAVE = "import sys; from PIL import Image; Image.open(sys.argv[1]).save(sys.argv[2])"      # the command the doc gave before: no empty values
# Since the audit of 1.0.2 the documented code first takes the working folder off Python's search path (a PIL package or a module
# named like part of Python, planted in the working folder, ran through the command before), then imports Pillow.
SEARCH_PATH_STATEMENT = "sys.path = [p for p in sys.path if p]; "


def pillow_table(head):
    """(the header line, [(set of Pillow versions, [the other cells of the row])]) of the table of how-to-export-clean.md whose header line starts with `head`."""
    lines = [ln for ln in DOC.splitlines() if ln.startswith(head)]
    assert len(lines) == 1, "the table headed %r is missing from how-to-export-clean.md (or is there twice)" % head
    rows = []
    for line in DOC.split(lines[0])[1].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append(({v.strip() for v in cells[0].split(",")}, cells[1:]))
    return lines[0], rows


def pillow_rows():
    """[(set of Pillow versions, [re-scan exit of a plain save of a PNG with eXIf, of a JPEG with a COM comment, of a JPEG with XMP,
    of the documented command])] read from the doc's table."""
    header, table = pillow_table("| Pillow versions run |")
    cols = [c.strip() for c in header.strip().strip("|").split("|")]
    assert "eXIf" in cols[1] and "COM" in cols[2] and "XMP" in cols[3] and "command" in cols[4], cols
    return [(versions, [int(re.match(r"exit (\d)", c).group(1)) for c in cells]) for versions, cells in table]


def pillow_rows_two():
    """[(set of Pillow versions, [re-scan exit of a plain save of a still WebP to PNG, of the documented command on it, then the same two for an
    animated PNG, as the doc's cell text])] read from the doc's second table."""
    header, table = pillow_table("| Pillow versions run, same 23 |")
    cols = [c.strip() for c in header.strip().strip("|").split("|")]
    assert "WebP" in cols[1] and "plain" in cols[1] and "WebP" in cols[2] and "command" in cols[2], cols
    assert "Animated PNG" in cols[3] and "plain" in cols[3] and "Animated PNG" in cols[4] and "command" in cols[4], cols
    return [(versions, cells) for versions, cells in table]


PILLOW_ROWS = pillow_rows()
PILLOW_ROWS_TWO = pillow_rows_two()
PILLOW_COUNT = sum(len(versions) for versions, _ in PILLOW_ROWS)


def documented_pillow(version):
    """The exits the doc's Pillow table gives for this Pillow version, or None when the doc did not run that version."""
    hits = [exits for versions, exits in PILLOW_ROWS if version in versions]
    assert len(hits) <= 1, (version, "is listed in two rows")
    return hits[0] if hits else None


def documented_webp_plain_exit(version):
    """The re-scan exit the doc's second table gives for a plain save of the still WebP to PNG on this Pillow version, or None when the doc did not run it."""
    hits = [int(re.match(r"exit (\d)", cells[0]).group(1)) for versions, cells in PILLOW_ROWS_TWO if version in versions]
    assert len(hits) <= 1, (version, "is listed in two rows")
    return hits[0] if hits else None


# ----------------------------------------------------------------------------------------------------------------------
# What the two Pillow tables and the three status rows that cite them claim, as plain data in this file (nothing is read from a measurement file: the
# probe's own record is not part of this tree). The command as printed in the doc was run on each of these 23 releases; a version, a range of
# versions or a result edited in the doc fails a test below until this block is edited too, so the change shows up in both files.
# ----------------------------------------------------------------------------------------------------------------------
PILLOW_RELEASES = ("9.0.0", "9.0.1", "9.1.0", "9.1.1", "9.2.0", "9.3.0", "9.4.0", "9.5.0", "10.0.0", "10.0.1", "10.1.0", "10.2.0", "10.3.0", "10.4.0",
                   "11.0.0", "11.1.0", "11.2.1", "11.3.0", "12.0.0", "12.1.0", "12.1.1", "12.2.0", "12.3.0")
PILLOW_FALLS_BACK_ON_EXIF = PILLOW_RELEASES[:6]          # 9.0.0 to 9.3.0: a plain save writes the source's own EXIF back
PILLOW_TABLE_ONE = [        # (versions, cells: plain save of a PNG with eXIf, of a JPEG with COM, of a JPEG with XMP, the command as printed on every file)
    (PILLOW_FALLS_BACK_ON_EXIF, ["exit 1: G1 and P2 kept", "exit 0", "exit 0", "exit 0"]),
    (("9.4.0", "9.5.0", "10.0.0", "10.0.1", "10.1.0", "10.2.0", "10.3.0", "10.4.0"), ["exit 0", "exit 1: P2 kept", "exit 0", "exit 0"]),
    (("11.0.0",), ["exit 0", "exit 1: P2 kept", "exit 1: G1 kept", "exit 0"]),
    (("11.1.0", "11.2.1", "11.3.0", "12.0.0", "12.1.0", "12.1.1", "12.2.0", "12.3.0"), ["exit 0", "exit 1: P2 kept", "exit 0", "exit 0"]),
]
PILLOW_TABLE_TWO = [        # (versions, cells: still WebP to PNG with a plain save, with the command as printed; animated PNG with a plain save, with the command)
    (PILLOW_FALLS_BACK_ON_EXIF, ["exit 1: K1 and K2 kept", "exit 0", "exit 0, one frame", "exit 0, one frame"]),
    (PILLOW_RELEASES[6:], ["exit 0", "exit 0", "exit 0, one frame", "exit 0, one frame"]),
]
ROW_ANIMATED_PNG_PILLOW = ("| Animated PNG | Pillow `save`: a plain one, and the command below as printed | verified **not to work**, all 23 Pillow versions | "
                           "exit 0 on every version, but only the first frame is written (the copy has no `acTL` chunk) and the copy re-scans as exit 0: "
                           "silent loss. Table under \"Pillow versions\". |")
ROW_STILL_WEBP_PILLOW = ("| WebP (still) | ffmpeg to JPEG with `-map_metadata -1 -q:v 2`, or the Pillow command below to PNG | verified (ffmpeg: all four builds; "
                         "Pillow: the command as printed, all 23 versions) | exit 0 on a synthetic WebP whose EXIF held a workflow with a fake key. "
                         "A plain Pillow `save` to PNG carried that EXIF into the PNG on Pillow 9.0.0 to 9.3.0 (exit 1, K1 and K2) and did not on 9.4.0 and later. "
                         "Table under \"Pillow versions\". |")
ROW_ANIMATED_WEBP_GIF_PILLOW = ("| Animated WebP, GIF | the Pillow command below, to PNG | verified **not to work**, all 23 Pillow versions | "
                                "exit 0 on a synthetic 5-frame WebP and a synthetic 5-frame GIF, but the PNG has only the first frame (silent loss). "
                                "Export from the application that made it. |")
PILLOW_MEASURED_LINES = {   # the two lines of the doc, character for character, as they were run on the 23 releases (measured again on
    # 2026-10-15 after the search-path statement was added: the same 159 combinations of Python and Pillow, every cell the same)
    "png": 'python -c "import sys; sys.path = [p for p in sys.path if p]; from PIL import Image; Image.open(sys.argv[1]).save(sys.argv[2], exif=bytes(), comment=bytes(), xmp=bytes())" "<IN.png>" "<OUT.png>"',
    "jpg": 'python -c "import sys; sys.path = [p for p in sys.path if p]; from PIL import Image; Image.open(sys.argv[1]).save(sys.argv[2], exif=bytes(), comment=bytes(), xmp=bytes())" "<IN.jpg>" "<OUT.jpg>"',
}


def jpeg_plus(raw, *segments):
    """`raw` (a JPEG Pillow can decode) with extra segments added after its leading APPn segments. Plain bytes, so the source file is the same on every Pillow version."""
    i = 2
    while raw[i] == 0xFF and 0xE0 <= raw[i + 1] <= 0xEF:
        i += 2 + struct.unpack(">H", raw[i + 2:i + 4])[0]
    return raw[:i] + b"".join(segments) + raw[i:]


# ----------------------------------------------------------------------------------------------------------------------
# What the doc says differs between ffmpeg builds (a table in how-to-export-clean.md, measured on 5.1, 7.1, 8.1.1 and 9.0.1).
# A test that exercises one of those behaviours compares this machine's result with the cell for the build it runs on; for a build
# the doc has not measured it checks only what holds on every build (the re-scan result is 0 or 1 and, if 1, has the shape the doc gives).
# ----------------------------------------------------------------------------------------------------------------------
def per_build_table():
    head = "| Measured | 5.1 | 7.1 | 8.1.1 | 9.0.1 |"
    assert head in DOC, "the per-build table is missing from how-to-export-clean.md"
    builds = [c.strip() for c in head.strip("|").split("|")][1:]
    rows = {}
    for line in DOC.split(head)[1].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows[cells[0]] = dict(zip(builds, cells[1:]))
    return builds, rows


BUILDS, BUILD_ROWS = per_build_table()


def documented(row_start):
    """The cells (build -> text) of the per-build row whose label starts with `row_start`."""
    hits = [v for k, v in BUILD_ROWS.items() if k.startswith(row_start)]
    assert len(hits) == 1, (row_start, sorted(BUILD_ROWS))
    return hits[0]


def ffmpeg_build():
    """'5.1', '7.1', '8.1.1' or '9.0.1' when the ffmpeg on PATH is a version the doc measured, else None."""
    import shutil
    exe = shutil.which("ffmpeg")
    if not exe:
        return None
    first = subprocess.run([exe, "-version"], stdout=subprocess.PIPE, timeout=60).stdout.decode("utf-8", "replace").splitlines()[0]
    m = re.match(r"ffmpeg version n?(\d+)\.(\d+)(?:\.(\d+))?", first)
    if not m:
        return None
    key = "%s.%s" % m.group(1, 2) + (".%s" % m.group(3) if m.group(3) else "")
    return key if key in BUILDS else None


def run_text(command, replacements, **kw):
    """Run a documented command line, with its placeholders replaced, as an argument list (quotes removed like a shell would)."""
    import shlex
    line = command
    for k, v in replacements.items():
        line = line.replace(k, v)
    if os.name == "nt":
        argv = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in shlex.split(line, posix=False)]
    else:
        argv = shlex.split(line)
    if argv[0] == "python":
        argv[0] = sys.executable
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, **kw)


def frame_md5(path):
    p = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "framemd5", "-"], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=120)
    assert p.returncode == 0, p.stderr
    return [ln for ln in p.stdout.decode().splitlines() if not ln.startswith("#")]


@unittest.skipUnless(have_ffmpeg(), "ffmpeg/ffprobe not on PATH")
class ExportCase(ScanCase):
    def setUp(self):
        ScanCase.setUp(self)
        self.ws = DC.Workspace()
        self.addCleanup(self.ws.close)

    def export(self, ext, src):
        """Run the doc's command for this file type on `src`; return the output path."""
        cmd = TEMPLATES[ext]
        out = self.ws.new_path(ext)
        argv = [t.replace("<IN.%s>" % ext, src).replace("<OUT.%s>" % ext, out) for t in cmd.argv_template()]
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-400:])
        self.assertTrue(os.path.exists(out))
        return out

    def rescan(self, path):
        report = self.ws.new_path("json")
        p = subprocess.run([sys.executable, "-I", "-B", SCAN, path, "--json", report], stdout=subprocess.PIPE, timeout=120)
        return p.returncode, json.loads(read_text(report)), p.stdout.decode("utf-8", "replace")

    def scan_before(self, path):
        code, doc, _ = self.rescan(path)
        self.assertEqual(code, 1, "the demo file must leak before it is exported")
        return doc


class TestMp4(ExportCase):
    def test_remux_removes_the_prompt_tag_and_the_hidden_box_and_keeps_the_frames(self):
        src = self.ws.demo_file("mp4")
        before = self.scan_before(src)
        self.assertIn("M1", {f["class"] for f in before["findings"]})
        out = self.export("mp4", src)
        code, doc, text = self.rescan(out)
        self.assertEqual(code, 0, text)
        self.assertEqual(doc["summary"]["files_scanned"], 1)             # the proof scanned something
        self.assertEqual(frame_md5(src), frame_md5(out))                 # no re-encode: the decoded frames are identical
        tags = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_streams", out],
                              stdout=subprocess.PIPE, timeout=60).stdout
        self.assertIn("handler_name", json.loads(tags)["streams"][0]["tags"])      # stream tags stay, as the doc says

    def test_standard_tag_survives_a_plain_remux_and_not_the_documented_one(self):
        src = os.path.join(self.dir, "std_tag.mp4")
        j = '{"7":{"class_type":"RemoteRender","inputs":{"server":"192.168.77.20"}}}'
        p = subprocess.run(["ffmpeg", "-v", "error", "-n", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10:duration=1",
                            "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-metadata", "comment=" + j, src],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if p.returncode != 0:
            self.skipTest("this ffmpeg has no libx264")
        self.assertEqual(self.rescan(src)[0], 1)
        plain = os.path.join(self.dir, "plain.mp4")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-c", "copy", plain], check=True, timeout=120)
        self.assertEqual(self.rescan(plain)[0], 1, "a plain remux keeps a standard tag (the doc says so)")
        out = self.export("mp4", src)
        self.assertEqual(self.rescan(out)[0], 0)

    def test_the_prompt_tag_of_the_demo_file_is_dropped_by_a_plain_remux_too(self):
        # the doc says this, and also says not to rely on it
        src = self.ws.demo_file("mp4")
        plain = self.ws.new_path("mp4")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-c", "copy", plain], check=True, timeout=120)
        self.assertEqual(self.rescan(plain)[0], 0)
        self.assertIn("unless `-movflags use_metadata_tags` is given", DOC)

    def test_use_metadata_tags_would_have_kept_it(self):
        src = self.ws.demo_file("mp4")
        kept = self.ws.new_path("mp4")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-c", "copy", "-movflags", "use_metadata_tags", kept],
                       check=True, timeout=120)
        self.assertEqual(self.rescan(kept)[0], 1)


class TestPng(ExportCase):
    def test_every_leaking_demo_png_is_clean_after_the_documented_command(self):
        for name in ("01_png_api_key_and_username.png", "02_png_ztxt_webhook.png", "03_png_bypassed_node_secret.png"):
            src = os.path.join(self.ws.demo, name)
            self.scan_before(src)
            out = self.export("png", src)
            code, doc, text = self.rescan(out)
            self.assertEqual((code, doc["summary"]["files_scanned"]), (0, 1), name + text)
            self.assertEqual(doc["info"], [], "no embedded workflow note either: " + name)

    def test_decoded_pixels_are_identical(self):
        src = os.path.join(self.ws.demo, "01_png_api_key_and_username.png")
        self.assertEqual(frame_md5(src), frame_md5(self.export("png", src)))

    def test_the_flag_is_not_what_removes_the_text_in_this_ffmpeg(self):
        # the doc says a re-encode without -map_metadata -1 also dropped the chunks (a control run)
        src = os.path.join(self.ws.demo, "01_png_api_key_and_username.png")
        out = self.ws.new_path("png")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, out], check=True, timeout=120)
        self.assertEqual(self.rescan(out)[0], 0)
        self.assertIn("also dropped them (verified, control run)", DOC)

    @unittest.skipUnless(DC.pillow_available(), "Pillow is not installed")
    def test_pillow_save_drops_the_chunks_and_keeps_the_pixels(self):
        self.assertEqual(sorted(PILLOW), ["jpg", "png"])
        for name in ("01_png_api_key_and_username.png", "02_png_ztxt_webhook.png", "03_png_bypassed_node_secret.png"):
            src = os.path.join(self.ws.demo, name)
            out = self.ws.new_path("png")
            p = run_text(PILLOW["png"].text, {"<IN.png>": src, "<OUT.png>": out})
            self.assertEqual(p.returncode, 0, p.stdout)
            self.assertEqual(self.rescan(out)[0], 0, name)
            if name.startswith("01"):
                self.assertEqual(frame_md5(src), frame_md5(out))


class TestJpeg(ExportCase):
    def test_reencode_removes_the_gps_block(self):
        src = self.ws.demo_file("jpg")
        before = self.scan_before(src)
        self.assertEqual({f["class"] for f in before["findings"]}, {"G1"})
        out = self.export("jpg", src)
        code, doc, text = self.rescan(out)
        self.assertEqual((code, doc["summary"]["files_scanned"]), (0, 1), text)

    def test_copy_keeps_the_gps_block(self):
        src = self.ws.demo_file("jpg")
        out = self.ws.new_path("jpg")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-map_metadata", "-1", "-c", "copy", out], check=True, timeout=120)
        code, doc, text = self.rescan(out)
        self.assertEqual(code, 1, text)
        self.assertEqual({f["class"] for f in doc["findings"]}, {"G1"})
        self.assertIn("Do not use `-c copy` for a JPEG", DOC)

    @unittest.skipUnless(DC.pillow_available(), "Pillow is not installed")
    def test_pillow_save_drops_the_gps_block(self):
        src = self.ws.demo_file("jpg")
        out = self.ws.new_path("jpg")
        p = run_text(PILLOW["jpg"].text, {"<IN.jpg>": src, "<OUT.jpg>": out})
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.rescan(out)[0], 0)

    @unittest.skipUnless(DC.pillow_available(), "Pillow is not installed")
    def test_pillow_command_is_safe_against_a_file_name_that_is_python_code(self):
        # the old command wrote the path into the Python source; a name with a quote in it ran as code
        src = self.ws.demo_file("jpg")
        evil = os.path.join(self.dir, "a'+str(open('PIL_INJECTED_FLAG','w'))+'.jpg")
        try:
            with open(evil, "wb") as fh:
                fh.write(read_bytes(src))
        except OSError:
            self.skipTest("this file system does not allow a quote in a file name")
        out = self.ws.new_path("jpg")
        p = run_text(PILLOW["jpg"].text, {"<IN.jpg>": evil, "<OUT.jpg>": out}, cwd=self.dir)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "PIL_INJECTED_FLAG")))
        # the control: the old form really did run the name as code
        old = [sys.executable, "-c", "from PIL import Image; Image.open(r'%s').save(r'%s')" % (evil, out + "2.jpg")]
        subprocess.run(old, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.dir, timeout=120)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "PIL_INJECTED_FLAG")), "the old template executed the file name")


class TestTheProofLoop(ExportCase):
    def test_a_reused_output_name_gives_a_stale_file_and_exit_0_which_is_why_the_doc_warns(self):
        src = self.ws.demo_file("png")
        out = self.ws.new_path("png")
        with open(out, "wb") as fh:
            fh.write(read_bytes(os.path.join(self.ws.demo, "04_clean.png")))       # an old, unrelated clean file
        cmd = TEMPLATES["png"]
        argv = [t.replace("<IN.png>", src).replace("<OUT.png>", out) for t in cmd.argv_template()]
        before = read_bytes(out)
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertIn(b"already exists", p.stdout)                # (on every measured build, with the exit code the per-build table gives)
        self.assertEqual(read_bytes(out), before, "-n must leave the existing file alone")
        build = ffmpeg_build()
        if build:
            self.assertEqual(str(p.returncode), documented("`-n` on an existing output")[build], "ffmpeg %s" % build)
        self.assertEqual(documented("`-n` on an existing output"), {"5.1": "1", "7.1": "0", "8.1.1": "0", "9.0.1": "0"})
        self.assertIn("a reused name makes an old file look like the fresh copy", " ".join(DOC.split()))
        self.assertEqual(self.rescan(out)[0], 0)                  # the stale file scans clean: nothing was exported


def frames(path):
    p = subprocess.run(["ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0", "-show_entries",
                        "stream=nb_read_frames", "-of", "csv=p=0", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return int(p.stdout.decode().strip() or 0)


def streams(path):
    p = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_type", "-of", "csv=p=0", path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return p.stdout.decode().split()


def tags_of(path):
    """(format-level tags, tags of the first stream) of a file, as ffprobe reports them."""
    p = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format_tags:stream_tags", "-of", "json", path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    d = json.loads(p.stdout)
    return d["format"].get("tags", {}), d["streams"][0].get("tags", {})


def ffmpeg_name():
    """'ffmpeg version 4.4.2-0ubuntu0.22.04.1' (the first three words of the first line of `ffmpeg -version`)."""
    p = subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, timeout=60)
    return " ".join(p.stdout.decode("utf-8", "replace").splitlines()[0].split()[:3])


def libavformat_tag():
    """The format-level `encoder` tag the ffmpeg on PATH writes: 'Lavf' and the version of ITS libavformat, which is not the ffmpeg version
    (ffmpeg 8.1.1 has libavformat 62.12.101 and writes Lavf62.12.101). Read from the 'libavformat  62. 12.101 / ...' line of `ffmpeg -version`."""
    p = subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, timeout=60)
    m = re.search(r"^libavformat\s+(\d+)\.\s*(\d+)\.\s*(\d+)", p.stdout.decode("utf-8", "replace"), re.M)
    assert m, "`ffmpeg -version` prints no libavformat line"
    return "Lavf%s.%s.%s" % m.groups()


# Pillow lives in the user's site-packages on some machines, which `python -I` hides, so test files are built in a child process.
PIL_MAKE = r"""
import json, sys
from PIL import Image, PngImagePlugin, ImageCms
mode, path, secret = sys.argv[1], sys.argv[2], sys.argv[3]


def exif_blob(artist):
    ex = Image.Exif()
    ex[0x013B] = artist
    gps = ex.get_ifd(0x8825)
    gps[1], gps[2], gps[3], gps[4] = "N", (34.0, 3.0, 8.0), "W", (118.0, 14.0, 37.0)
    ex[0x8825] = gps   # measured: Pillow 9.4 and 10.2 leave out a GPS block that was only filled in through get_ifd(); 12.3 keeps it
    return ex.tobytes()


if mode == "exif":
    Image.new("RGB", (32, 24), (10, 120, 200)).save(path, exif=exif_blob(secret))
elif mode == "raw":
    ex = exif_blob(secret)
    info = PngImagePlugin.PngInfo()
    info.add_text("Raw profile type exif", "\nexif\n%8d\n%s\n" % (len(ex), ex.hex()))
    Image.new("RGB", (32, 24)).save(path, pnginfo=info)
elif mode == "anim":
    fr = [Image.new("RGB", (32, 24), (i * 40, 100, 50)) for i in range(5)]
    info = PngImagePlugin.PngInfo()
    info.add_text("prompt", "k " + secret)
    fr[0].save(path, save_all=True, append_images=fr[1:], duration=100, loop=0, pnginfo=info)
elif mode in ("animwebp", "animgif"):
    fr = [Image.new("RGB", (32, 24), (i * 40, 100, 50)) for i in range(5)]
    if mode == "animwebp":
        ex = Image.Exif()
        ex[0x013B] = secret
        fr[0].save(path, save_all=True, append_images=fr[1:], duration=100, loop=0, lossless=True, exif=ex.tobytes())
    else:
        fr[0].save(path, save_all=True, append_images=fr[1:], duration=100, loop=0, comment=("contact " + secret).encode())
elif mode == "webp":
    ex = Image.Exif()
    ex[0x0110] = "prompt:" + json.dumps({"11": {"class_type": "Cap", "inputs": {"api_key": secret}}})
    ex[0x010F] = "workflow:" + json.dumps({"nodes": []})
    Image.new("RGB", (32, 24), (200, 100, 10)).save(path, exif=ex.tobytes())
elif mode == "icc":
    prof = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    Image.new("RGB", (32, 24), (1, 2, 3)).save(path, icc_profile=prof)
elif mode == "jpeg":
    Image.new("RGB", (32, 24), (10, 120, 200)).save(path)
"""


def pil_make(mode, path, secret="x"):
    p = subprocess.run([sys.executable, "-c", PIL_MAKE, mode, path, secret], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if p.returncode != 0:
        raise unittest.SkipTest("Pillow could not make a %s test file: %s" % (mode, p.stdout.decode("utf-8", "replace")[-200:]))
    return path


def pil_n_frames(path):
    """The number of frames the Pillow of a child interpreter finds in an image file (1 for a still)."""
    p = subprocess.run([sys.executable, "-c", "import sys; from PIL import Image; print(getattr(Image.open(sys.argv[1]), 'n_frames', 1))", path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return int(p.stdout.decode().strip())


@unittest.skipUnless(have_ffmpeg() and DC.pillow_available(), "needs ffmpeg and Pillow")
class TestPngWithExif(ExportCase):
    """Finding: the PNG command was called verified, but it keeps a PNG's EXIF (GPS and e-mail) in an eXIf chunk."""

    def make(self, kind):
        return pil_make(kind, os.path.join(self.dir, kind + ".png"), "jane.doe" + "@" + "acme-films.com")

    def test_the_ffmpeg_png_command_on_a_png_with_exif_gives_the_result_the_doc_states_for_this_build(self):
        # Measured on four builds: 8.1.1 and 9.0.1 write the EXIF into an eXIf chunk of the new PNG (re-scan exit 1); 5.1 and 7.1 do not
        # (re-scan exit 0). So the test does not assume either: it compares with the doc's per-build table, and for any build it checks
        # the part that holds everywhere - a re-scan decides, and when it finds something it is the EXIF (G1, P2) in an eXIf chunk.
        build = ffmpeg_build()
        want = documented("PNG with EXIF through the ffmpeg PNG command")
        seen = set()
        for kind in ("exif", "raw"):
            src = self.make(kind)
            self.assertEqual(sorted({f["class"] for f in self.scan_before(src)["findings"]}), ["G1", "P2"])
            out = self.export("png", src)
            noflag = self.ws.new_path("png")
            subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, noflag], check=True, timeout=120)
            for label, path in (("with -map_metadata -1", out), ("without it", noflag)):
                code, doc, text = self.rescan(path)
                seen.add(code)
                self.assertIn(code, (0, 1), "%s %s: %s" % (kind, label, text))
                if code == 1:
                    self.assertEqual(sorted({f["class"] for f in doc["findings"]}), ["G1", "P2"])
                    self.assertEqual({f["carrier"] for f in doc["findings"]}, {"png:eXIf"})
                if build:
                    self.assertEqual(str(code), want[build], "ffmpeg %s, %s %s: the doc says the re-scan exits %s" % (build, kind, label, want[build]))
        self.assertEqual(len(seen), 1, "the flag makes no difference to whether the EXIF survives")
        flat = " ".join(DOC.split())
        for needle in ("PNG with EXIF", "**by build**", "`eXIf` chunk", "the re-scan, not the flag, is the check"):
            self.assertIn(needle, flat)
        self.assertEqual(want, {"5.1": "0", "7.1": "0", "8.1.1": "1", "9.0.1": "1"})          # what was measured, and written down

    def test_pillow_and_the_jpeg_route_remove_it(self):
        for kind in ("exif", "raw"):
            src = self.make(kind)
            out = self.ws.new_path("png")
            self.assertEqual(run_text(PILLOW["png"].text, {"<IN.png>": src, "<OUT.png>": out}).returncode, 0)
            self.assertEqual(self.rescan(out)[0], 0, kind)
            jpg = self.ws.new_path("jpg")
            subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-map_metadata", "-1", "-q:v", "2", jpg], check=True, timeout=120)
            self.assertEqual(self.rescan(jpg)[0], 0, kind)

    def test_a_colour_profile_name_survives_pillow_and_the_scanner_does_not_read_its_contents(self):
        # the Pillow half of the old test: it holds on every Pillow version (the doc says so for every version of its table)
        src = pil_make("icc", os.path.join(self.dir, "icc.png"))
        out = self.ws.new_path("png")
        p = run_text(PILLOW["png"].text, {"<IN.png>": src, "<OUT.png>": out})
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn(b"iCCP", read_bytes(out))
        self.assertIn("ICC colour-profile contents", read_text(os.path.join(PKG, "references", "known-misses.md")))
        self.assertIn("(the `iCCP` chunk was still there, on all %d versions)" % PILLOW_COUNT, " ".join(DOC.split()))

    def test_a_colour_profile_name_survives_ffmpeg_on_the_builds_the_doc_measured(self):
        # the ffmpeg half: the doc says ffmpeg kept the iCCP chunk on the four builds it measured. ffmpeg 4.4.2 (Ubuntu 22.04) writes none: measured here.
        src = pil_make("icc", os.path.join(self.dir, "icc.png"))
        kept = b"iCCP" in read_bytes(self.export("png", src))
        if ffmpeg_build():
            self.assertTrue(kept, "the doc says ffmpeg %s keeps the iCCP chunk" % ffmpeg_build())
        elif not kept:
            line = subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, timeout=60).stdout.decode("utf-8", "replace").splitlines()[0]
            self.skipTest("%s writes no iCCP chunk into a PNG (measured); the doc's claim covers only the four builds it measured" % line.split(" Copyright")[0])


@unittest.skipUnless(DC.pillow_available(), "Pillow is not installed")
class TestPillowVersions(ExportCase):
    """Finding: the doc called a plain Pillow save safe (it 'writes neither' EXIF nor text), measured on Pillow 12.3.0 only. On 9.0.0 to 9.3.0 it keeps
    a PNG's eXIf chunk, from 9.4.0 a JPEG's COM comment, and on 11.0.0 also a JPEG's XMP packet. The documented command passes an empty value for each."""

    MAIL = B.mail("jane.doe", "acme-films.com")

    def sources(self):
        """name -> (path, finding classes, carriers). The PNG is written by the Pillow under test (its eXIf chunk is what a plain save may copy); the
        JPEGs are a metadata-free Pillow JPEG plus one segment added here as plain bytes, and the demo JPEG."""
        plain = read_bytes(pil_make("jpeg", os.path.join(self.dir, "plain.jpg")))
        return {
            "png_exif": (pil_make("exif", os.path.join(self.dir, "exif.png"), self.MAIL), ["G1", "P2"], {"png:eXIf"}),
            "jpeg_com": (self.write("com.jpg", jpeg_plus(plain, B.seg(0xFE, ("contact " + self.MAIL).encode()))), ["P2"], {"jpeg:com"}),
            "jpeg_xmp": (self.write("xmp.jpg", jpeg_plus(plain, B.seg(0xE1, B.xmp_packet("34,3.133N", "118,14.617W")))), ["G1"], {"jpeg:xmp"}),
            "jpeg_exif": (self.ws.demo_file("jpg"), ["G1"], {"jpeg:exif"}),
        }

    @staticmethod
    def ext(path):
        return "png" if path.endswith(".png") else "jpg"

    def test_every_source_leaks_before_a_copy_is_made(self):
        for name, (path, classes, carriers) in self.sources().items():
            doc = self.scan_before(path)
            self.assertEqual(sorted({f["class"] for f in doc["findings"]}), classes, name)
            self.assertEqual({f["carrier"] for f in doc["findings"]}, carriers, name)

    def test_the_documented_command_leaves_nothing_the_scanner_knows_on_this_pillow(self):
        # runs on every Pillow version, listed in the doc or not: a version that breaks the command must fail here
        for name, (path, _, _) in self.sources().items():
            ext = self.ext(path)
            out = self.ws.new_path(ext)
            p = run_text(PILLOW[ext].text, {"<IN.%s>" % ext: path, "<OUT.%s>" % ext: out})
            self.assertEqual(p.returncode, 0, p.stdout)
            code, doc, text = self.rescan(out)
            self.assertEqual((code, doc["summary"]["files_scanned"]), (0, 1), "Pillow %s, %s: %s" % (DC.pillow_version(), name, text))

    def test_a_plain_save_keeps_what_the_doc_table_says_for_this_pillow(self):
        version = DC.pillow_version()
        row = documented_pillow(version)
        if row is None:
            self.skipTest("Pillow %s is not one of the %d versions in the table of Pillow versions in how-to-export-clean.md"
                          % (version, PILLOW_COUNT))
        sources = self.sources()
        for name, want in (("png_exif", row[0]), ("jpeg_com", row[1]), ("jpeg_xmp", row[2])):
            path = sources[name][0]
            out = self.ws.new_path(self.ext(path))
            p = subprocess.run([sys.executable, "-c", PLAIN_SAVE, path, out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            self.assertEqual(p.returncode, 0, p.stdout)
            code, doc, text = self.rescan(out)
            self.assertEqual(code, want, "Pillow %s, plain save of %s: the doc table says the re-scan exits %d\n%s" % (version, name, want, text))
            if code == 1:
                self.assertEqual({f["carrier"] for f in doc["findings"]}, sources[name][2], name)       # it is the carrier that was copied, nothing else

    def test_a_save_that_is_told_to_keep_the_data_is_found_on_every_pillow(self):
        # negative control for the two tests above: the same Pillow, told to write the source's own EXIF back, gives a copy the re-scan flags.
        # `exif=` is honoured by the PNG and the JPEG writer of every version, so this control does not depend on the version.
        keep = "import sys; from PIL import Image; im = Image.open(sys.argv[1]); im.save(sys.argv[2], exif=im.info['exif'])"
        sources = self.sources()
        for name in ("png_exif", "jpeg_exif"):
            path, classes, carriers = sources[name]
            out = self.ws.new_path(self.ext(path))
            p = subprocess.run([sys.executable, "-c", keep, path, out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            self.assertEqual(p.returncode, 0, p.stdout)
            code, doc, text = self.rescan(out)
            self.assertEqual(code, 1, "Pillow %s: a save that writes the EXIF back must leak (%s)\n%s" % (DC.pillow_version(), name, text))
            self.assertEqual({f["carrier"] for f in doc["findings"]}, carriers, name)
        # and without the three empty values, the documented command would fail the test above on every version in the table: on 9.0.0 to
        # 9.3.0 through the PNG, on 9.4.0 and later through the JPEG comment (the table says so, and test_a_plain_save_keeps_... runs it)
        self.assertTrue(all(1 in exits[:3] for _, exits in PILLOW_ROWS))


class TestPillowTableInTheDoc(unittest.TestCase):
    """The table of Pillow versions and the command it describes, read from the doc (no Pillow needed)."""

    def test_the_table_lists_each_version_once_and_the_command_is_exit_0_on_all(self):
        listed = [v for versions, _ in PILLOW_ROWS for v in versions]
        self.assertEqual(len(listed), len(set(listed)), "a Pillow version is listed in two rows")
        self.assertEqual(len(listed), PILLOW_COUNT)
        self.assertGreaterEqual(len(listed), 23)
        counts = {int(n) for n in re.findall(r"all (\d+) (?:Pillow )?versions", " ".join(DOC.split()))}
        self.assertEqual(counts, {PILLOW_COUNT}, "the prose counts the versions of the table: %s" % sorted(counts))
        for v in listed:
            self.assertRegex(v, r"^(9|10|11|12)\.\d+\.\d+$")
        for versions, exits in PILLOW_ROWS:
            self.assertEqual(len(exits), 4, sorted(versions))
            self.assertTrue(all(e in (0, 1) for e in exits), sorted(versions))
            self.assertEqual(exits[3], 0, "the documented command must exit 0 on every listed version: %s" % sorted(versions))
            self.assertIn(1, exits[:3], "a plain save keeps something on every listed version: %s" % sorted(versions))
        self.assertEqual(documented_pillow("9.0.1"), [1, 0, 0, 0])
        self.assertEqual(documented_pillow("9.4.0"), [0, 1, 0, 0])
        self.assertEqual(documented_pillow("11.0.0"), [0, 1, 1, 0])
        self.assertEqual(documented_pillow("12.3.0"), [0, 1, 0, 0])
        self.assertIsNone(documented_pillow("8.4.0"))
        # The two tables against the plain data at the top of this file: each of the 23 releases is in exactly one row of each table, with the
        # cells the command as printed was measured to give. A version moved, dropped or renamed, a range split differently or a result changed fails here.
        key = lambda v: [int(n) for n in v.split(".")]
        self.assertEqual(len(PILLOW_RELEASES), 23)
        self.assertEqual(list(PILLOW_RELEASES), sorted(set(PILLOW_RELEASES), key=key))
        for name, head, pinned in (("first", "| Pillow versions run |", PILLOW_TABLE_ONE), ("second", "| Pillow versions run, same 23 |", PILLOW_TABLE_TWO)):
            rows = pillow_table(head)[1]
            self.assertEqual([(tuple(sorted(v, key=key)), cells) for v, cells in rows], [(tuple(v), cells) for v, cells in pinned], name + " table")
            self.assertEqual(sorted((v for vs, _ in rows for v in vs), key=key), list(PILLOW_RELEASES), name + " table")
        # and the status rows of the doc that cite them say what the command was run on, in these words
        lines = DOC.splitlines()
        for row in (ROW_ANIMATED_PNG_PILLOW, ROW_STILL_WEBP_PILLOW, ROW_ANIMATED_WEBP_GIF_PILLOW):
            self.assertEqual(lines.count(row), 1, row)
        # the XMP column of the first table is for a GPS-only packet: with an e-mail in the packet 11.0.0 kept G1 and P2 too (8 recorded environments)
        flat = " ".join(DOC.split())
        self.assertIn("The XMP packet in the probe JPEG held GPS coordinates only; on 11.0.0 a packet that also held an e-mail address kept both G1 and P2 in a plain `save`", flat)

    def test_the_documented_commands_pass_an_empty_value_for_each_thing_a_version_copies(self):
        self.assertEqual(sorted(PILLOW), ["jpg", "png"])
        code = {ext: cmd.text.split('" "<IN')[0].split('-c "', 1)[1] for ext, cmd in PILLOW.items()}      # the Python code between the quotes
        self.assertEqual(code["png"], code["jpg"])
        guarded = PLAIN_SAVE.replace("import sys; ", "import sys; " + SEARCH_PATH_STATEMENT, 1)
        self.assertNotEqual(guarded, PLAIN_SAVE)
        self.assertTrue(code["png"].startswith(guarded[:-1] + ", "), "the doc's code is the plain save with arguments added, after the search-path statement")
        for needle in ("exif=bytes()", "comment=bytes()", "xmp=bytes()"):
            self.assertIn(needle, code["png"])
        self.assertNotEqual(code["png"], PLAIN_SAVE, "the doc must not go back to the plain save")
        self.assertEqual(code["png"], guarded[:-1] + ", exif=bytes(), comment=bytes(), xmp=bytes())")      # and nothing from the source is passed back in
        # the two lines as printed, quotes and placeholders included, are the lines the tables of Pillow versions were measured with
        self.assertEqual({ext: cmd.text for ext, cmd in PILLOW.items()}, PILLOW_MEASURED_LINES)

    def test_the_doc_does_not_call_a_plain_save_safe(self):
        flat = " ".join(DOC.split())
        for old in ("and EXIF only when you pass `exif=`", "A plain `save` writes neither", "verified (Pillow does not depend"):
            self.assertNotIn(old, flat, old)
        for needle in ("depend on the Pillow version", "there is no Pillow version in this table on which a plain `save` is safe for all three files",
                       "the re-scan of the copy is what decides", "the decoded pixels of the copy were identical to the source's on every version"):
            self.assertIn(needle, flat)
        # where and with what the cells were measured (the older sentence said Python 3.10 for all of them and 12.3.0 also on Windows, and so named only part of the runs)
        for old in ("Python 3.10 for all of them", "12.3.0 also on Windows with Python 3.14.6"):
            self.assertNotIn(old, flat, old)
        for needle in ("Every cell of both tables was measured for each of the 23, from PyPI wheels, on Linux x86-64 with Python 3.10.12 and on Windows with Python 3.10.21.",
                       "On Linux the two printed lines of the command were run by `bash -c`, with `python` standing for that interpreter; "
                       "on Windows each line was split into arguments and run without a shell.",
                       "Every cell of both tables was measured again on 2026-10-15, after the search-path statement was added to the command, "
                       "in the same 159 combinations of Python and Pillow (the four distribution packages included), with the same results.",
                       "The distribution packages python3-pil 9.0.1 (Ubuntu 22.04), 9.4.0 (Debian 12), 10.2.0 (Ubuntu 24.04) and 12.1.1 (Ubuntu 26.04)",
                       "on Linux Python 3.11.2 (19 of the versions), 3.12.3 (15) and 3.14.4 (6), on Windows 3.9.25 (18), 3.11.15 (19), 3.12.11 (16), 3.13.13 (10) and 3.14.6 (6)",
                       "A plain `save` of an animated PNG writes only the first frame and still exits 0, and so does the command above: do not use either on animated files."):
            self.assertIn(needle, flat)
        # 159 = the 23 versions on Linux 3.10.12 and on Windows 3.10.21, the other Pythons' counts and the 4 distribution packages
        others = re.search(r"on Linux Python 3\.11\.2 \((\d+) of the versions\), 3\.12\.3 \((\d+)\) and 3\.14\.4 \((\d+)\), on Windows 3\.9\.25 "
                           r"\((\d+)\), 3\.11\.15 \((\d+)\), 3\.12\.11 \((\d+)\), 3\.13\.13 \((\d+)\) and 3\.14\.6 \((\d+)\)", flat)
        self.assertEqual(2 * len(PILLOW_RELEASES) + sum(int(n) for n in others.groups()) + 4, 159)


@unittest.skipUnless(have_ffmpeg() and DC.pillow_available(), "needs ffmpeg and Pillow")
class TestAnimatedPng(ExportCase):
    """Finding: the PNG command fails on an animated PNG and leaves a one-frame file that re-scans as nothing found."""

    def make(self):
        return pil_make("anim", os.path.join(self.dir, "anim.png"), self.fake.hf())

    def test_the_documented_png_command_fails_and_leaves_a_one_frame_file_that_passes_the_rescan(self):
        src = self.make()
        self.assertEqual(frames(src), 5)
        self.assertEqual(self.scan_before(src)["summary"]["findings"], 1)
        out = self.ws.new_path("png")
        argv = [t.replace("<IN.png>", src).replace("<OUT.png>", out) for t in TEMPLATES["png"].argv_template()]
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertNotEqual(p.returncode, 0, "the export command itself fails")
        build = ffmpeg_build()
        if build and os.name == "nt":
            self.assertEqual(str(p.returncode), documented("Animated PNG through the PNG command")[build], "ffmpeg %s" % build)
        self.assertTrue(os.path.exists(out))
        self.assertEqual(frames(out), 1)
        self.assertEqual(self.rescan(out)[0], 0, "this is why the doc says to check the export's exit code and the frame count")

    def test_the_apng_command_keeps_every_frame_and_drops_the_text(self):
        src = self.make()
        out = self.ws.new_path("png")
        argv = [t.replace("<IN.png>", src).replace("<OUT.png>", out) for t in APNG.argv_template()]
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(frames(out), 5)
        self.assertEqual(self.rescan(out)[0], 0)

    def test_copy_into_apng_keeps_the_text_chunk_and_a_plain_pillow_save_loses_frames(self):
        src = self.make()
        cc = self.ws.new_path("png")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-map_metadata", "-1", "-c", "copy", "-f", "apng", "-plays", "0", cc],
                       check=True, timeout=120)
        self.assertEqual(self.rescan(cc)[0], 1)
        pil = self.ws.new_path("png")
        self.assertEqual(run_text(PILLOW["png"].text, {"<IN.png>": src, "<OUT.png>": pil}).returncode, 0)
        plain = self.ws.new_path("png")
        p = subprocess.run([sys.executable, "-c", PLAIN_SAVE, src, plain], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout)
        # the doc's status row and second Pillow table: both forms exit 0 and write the first frame only, with no animation chunk, and the
        # copy re-scans as exit 0 (the silent loss); the test file has five frames, so a copy of one frame is a loss of four
        for name, path in (("the documented command", pil), ("a plain save", plain)):
            self.assertEqual(frames(path), 1, name)
            self.assertNotIn(b"acTL", read_bytes(path), name)
            self.assertEqual(self.rescan(path)[0], 0, name)
        # the doc's row for an animated WebP and a GIF: the documented command loses their frames the same way (a 5-frame file of each kind;
        # a Pillow that cannot write one of the two formats skips that part, and the test skips as a whole if it can write neither)
        ran = []
        for mode, fname in (("animwebp", "anim.webp"), ("animgif", "anim.gif")):
            try:
                other = pil_make(mode, os.path.join(self.dir, fname), "jane.doe" + "@" + "acme-films.com")
            except unittest.SkipTest:
                continue
            self.assertEqual(pil_n_frames(other), 5, fname)
            out = self.ws.new_path("png")
            p = run_text(PILLOW["png"].text, {"<IN.png>": other, "<OUT.png>": out})
            self.assertEqual(p.returncode, 0, p.stdout)
            self.assertNotIn(b"acTL", read_bytes(out), fname)
            self.assertEqual(pil_n_frames(out), 1, fname)
            self.assertEqual(self.rescan(out)[0], 0, fname)
            ran.append(fname)
        for needle in ("Do not use `-c copy -f apng`", "only the first frame", "`-plays 0`"):
            self.assertIn(needle, DOC)
        if not ran:
            self.skipTest("this Pillow can write neither an animated WebP nor an animated GIF")


@unittest.skipUnless(have_ffmpeg() and DC.pillow_available(), "needs ffmpeg and Pillow")
class TestStillWebp(ExportCase):
    """Finding: 'export a PNG, JPEG or MP4' for an unsupported WebP carried the EXIF key into the new PNG."""

    def make(self):
        return pil_make("webp", os.path.join(self.dir, "cf.webp"), self.fake.openai_legacy())

    def test_the_documented_jpeg_route_is_checked_and_the_png_route_depends_on_the_build(self):
        src = self.make()
        code, doc, text = self.rescan(src)
        self.assertEqual((code, [e["code"] for e in doc["errors"]]), (3, ["unsupported_media"]))
        out = self.ws.new_path("jpg")
        p = run_text(WEBP, {"<IN.webp>": src, "<OUT.jpg>": out})
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.rescan(out)[0], 0)                       # the documented route: clean on every build
        png = self.ws.new_path("png")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-map_metadata", "-1", png], check=True, timeout=120)
        code, doc, text = self.rescan(png)
        self.assertIn(code, (0, 1), text)
        if code == 1:                                                   # the build carried the WebP's EXIF into the PNG
            self.assertEqual({f["class"] for f in doc["findings"]}, {"K1", "K2"})
            self.assertEqual({f["carrier"] for f in doc["findings"]}, {"png:eXIf"})
        build = ffmpeg_build()
        if build:
            self.assertEqual(str(code), documented("Still WebP")[build], "ffmpeg %s: the doc gives the re-scan exit of the WebP to PNG route" % build)
        self.assertEqual(documented("Still WebP"), {"5.1": "0", "7.1": "0", "8.1.1": "1", "9.0.1": "1"})
        self.assertIn("Do not export a PNG with ffmpeg from a WebP", DOC)

    def test_the_pillow_command_makes_a_png_from_the_webp_and_a_plain_save_depends_on_the_pillow_version(self):
        # the table row says "or the Pillow command below to PNG": the PNG writer's fallback to the source's EXIF is the one of a PNG source
        src = self.make()
        out = self.ws.new_path("png")
        p = run_text(PILLOW["png"].text, {"<IN.png>": src, "<OUT.png>": out})
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.rescan(out)[0], 0, "Pillow %s: the documented command carried the WebP's EXIF into the PNG" % DC.pillow_version())
        want = documented_webp_plain_exit(DC.pillow_version())
        if want is None:
            self.skipTest("Pillow %s is not in the doc's tables of Pillow versions: only the documented command was checked" % DC.pillow_version())
        plain = self.ws.new_path("png")
        p = subprocess.run([sys.executable, "-c", PLAIN_SAVE, src, plain], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout)
        code, doc, text = self.rescan(plain)
        self.assertEqual(code, want, "Pillow %s: the doc's second table says a plain save of the WebP to PNG re-scans as exit %d\n%s" % (DC.pillow_version(), want, text))
        if code == 1:
            self.assertEqual({f["class"] for f in doc["findings"]}, {"K1", "K2"})
            self.assertEqual({f["carrier"] for f in doc["findings"]}, {"png:eXIf"})


@unittest.skipUnless(have_ffmpeg(), "ffmpeg/ffprobe not on PATH")
class TestMp4Streams(ExportCase):
    """Finding: the MP4 command keeps one video and one audio stream; the doc said it 'copies the video and audio streams'."""

    def make(self):
        sub = os.path.join(self.dir, "s.srt")
        with open(sub, "w") as fh:
            fh.write("1\n00:00:00,000 --> 00:00:00,900\nhello\n")
        out = os.path.join(self.dir, "multi.mp4")
        p = subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10:duration=1", "-f", "lavfi",
                            "-i", "sine=frequency=440:duration=1", "-f", "lavfi", "-i", "sine=frequency=660:duration=1", "-i", sub,
                            "-map", "0:v", "-map", "1:a", "-map", "2:a", "-map", "3:s", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                            "-c:a", "aac", "-c:s", "mov_text", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if p.returncode != 0:
            self.skipTest("this ffmpeg has no libx264, aac or mov_text")
        return out

    def test_extra_tracks_are_dropped_without_a_warning_and_the_rescan_cannot_tell(self):
        src = self.make()
        self.assertEqual(streams(src), ["video", "audio", "audio", "subtitle"])
        out = self.export("mp4", src)
        self.assertEqual(streams(out), ["video", "audio"])
        self.assertEqual(self.rescan(out)[0], 0)
        mapped = self.ws.new_path("mp4")
        subprocess.run(["ffmpeg", "-v", "error", "-n", "-i", src, "-map", "0", "-map_metadata", "-1", "-map_chapters", "-1", "-c", "copy", mapped],
                       check=True, timeout=120)
        self.assertEqual(streams(mapped)[:4], ["video", "audio", "audio", "subtitle"])
        self.assertEqual(self.rescan(mapped)[0], 0)
        text = " ".join(DOC.split())
        for needle in ("keeps one video and one audio stream", "`-map 0` before `-map_metadata`", "Check the copy"):
            self.assertIn(needle, text)

    # The stream-level `encoder` tag. Whether the DEMO MP4 has one depends on the ffmpeg that made it. Measured: the MP4 muxer of Windows 5.1, 7.1,
    # 8.1.1 and 9.0.1 (the builds the doc names) and of Linux 5.1.9, 6.1.1 and 8.0.1 writes it; the MP4 muxer of Linux 4.4.2 writes none, not even
    # when asked with -metadata:s:v:0 encoder=...; every one of those builds writes it into a MOV. So: what holds on every build is asserted about
    # the COPY; on a build the doc names the demo MP4 MUST have the tag (a demo MP4 that lost it fails the test); on any other build the
    # "it was dropped" half is skipped only if a plain MP4 made by the same ffmpeg has none either, and fails if it has one.
    def plain_video(self, fmt):
        """A one-second video in `fmt` ('mp4' or 'mov') made by this ffmpeg without any option of make_demo.py: the control for "does this
        ffmpeg write a stream-level encoder tag at all"."""
        out = os.path.join(self.dir, "plain." + fmt)
        for codec in (["-c:v", "libx264", "-pix_fmt", "yuv420p"], ["-c:v", "mpeg4"]):
            if os.path.exists(out):
                os.remove(out)
            p = subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x48:rate=10:duration=1", "-an"]
                               + codec + ["-f", fmt, out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            if p.returncode == 0:
                return out
        self.skipTest("this ffmpeg has neither libx264 nor mpeg4 to make a plain %s with" % fmt)

    def test_the_copy_of_the_demo_mp4_has_no_stream_encoder_tag_and_the_exporters_format_encoder_tag(self):
        out = self.export("mp4", self.ws.demo_file("mp4"))
        fmt_after, st_after = tags_of(out)
        self.assertNotIn("encoder", st_after)       # (on 4.4.2, whose MP4 muxer writes none, this assertion cannot fail)
        self.assertEqual(fmt_after.get("encoder", "<no format-level encoder tag>"), libavformat_tag())
        self.assertIn("handler_name", st_after)                       # the doc: these two stay
        self.assertIn("language", st_after)

    def test_the_stream_encoder_tag_of_the_demo_mp4_is_dropped_where_the_build_wrote_one(self):
        src = self.ws.demo_file("mp4")
        out = self.export("mp4", src)
        _, st_before = tags_of(src)
        build = ffmpeg_build()
        if build:                                       # the doc says these four builds write it into the demo MP4: lacking it is a failure
            self.assertIn("encoder", st_before, "ffmpeg %s: the doc says this build writes a stream-level encoder tag into the demo MP4, "
                          "and the demo MP4 has only %s" % (build, sorted(st_before)))
        if "encoder" not in st_before:                  # a build the doc did not measure: a plain MP4 from the same ffmpeg tells the two causes apart
            _, st_plain = tags_of(self.plain_video("mp4"))
            self.assertNotIn("encoder", st_plain, "%s writes a stream-level encoder tag into a plain MP4 but not into the demo MP4 "
                             "(it has only %s): make_demo.py no longer lets the muxer write it" % (ffmpeg_name(), sorted(st_before)))
            self.skipTest("%s is not a build the doc measured, and a plain MP4 made by it has no stream-level encoder tag either "
                          "(only %s), so the demo MP4 has none for the command to drop" % (ffmpeg_name(), sorted(st_plain)))
        self.assertNotIn("encoder", tags_of(out)[1])

    def test_a_stream_encoder_tag_in_a_mov_source_is_not_in_the_copy(self):
        # Every build tested writes the tag into a MOV, so this source has one even where the demo MP4 has none. Where the MP4 muxer writes no
        # stream-level tag (4.4.2) the copy cannot have one and the first assertion below cannot fail; the other one still can.
        src = self.plain_video("mov")
        _, st_before = tags_of(src)
        if "encoder" not in st_before:
            self.skipTest("the MOV that %s made has no stream-level encoder tag (only %s), so this source has none to drop" % (ffmpeg_name(), sorted(st_before)))
        out = self.export("mp4", src)                                # the documented MP4 command, a MOV in, an MP4 out
        self.assertNotIn("encoder", tags_of(out)[1])
        self.assertEqual(tags_of(out)[0].get("encoder", "<no format-level encoder tag>"), libavformat_tag())

    def test_the_format_encoder_tag_is_the_exporters_whatever_the_source_had(self):
        raw = read_bytes(self.ws.demo_file("mp4"))
        hits = list(re.finditer(rb"Lavf\d+\.\d+\.\d+", raw))
        self.assertEqual(len(hits), 1, "the demo MP4 holds exactly one libavformat identification string")
        fake = b"Zzzz" + b"0" * (len(hits[0].group(0)) - 4)                # same length, so no box size changes
        src = os.path.join(self.dir, "other_encoder.mp4")
        with open(src, "wb") as fh:
            fh.write(raw[:hits[0].start()] + fake + raw[hits[0].end():])
        self.assertEqual(tags_of(src)[0].get("encoder"), fake.decode(), "the premise: the source names another encoder")
        out = self.export("mp4", src)
        fmt_after = tags_of(out)[0]
        self.assertNotEqual(fmt_after.get("encoder"), fake.decode())
        self.assertEqual(fmt_after.get("encoder", "<no format-level encoder tag>"), libavformat_tag())

    def test_the_doc_states_the_encoder_tag_facts_it_measured(self):
        text = " ".join(DOC.split())
        for needle in ("The stream-level `encoder` tag does not stay",
                       "depends on the ffmpeg that made it",
                       "ffmpeg 4.4.2",                                # the one build whose demo MP4 has no stream-level encoder tag
                       "writes none into an MP4",
                       "there is nothing to drop",
                       "`Lavf` and the libavformat version"):
            self.assertTrue(needle in text, "how-to-export-clean.md no longer says: " + needle)
        for needle in ("The stream-level `encoder` tag of the demo file was dropped",     # false where the demo file never had one
                       "`Lavf` and the ffmpeg version",              # the value is the libavformat version (Lavf58.76.100 is ffmpeg 4.4.2)
                       "left it out of the copy of a MOV"):          # credits the command for what the MP4 muxer of 4.4.2 does with any command
            self.assertFalse(needle in text, "how-to-export-clean.md says again: " + needle)

    def test_the_documented_command_prints_nothing(self):
        src = self.ws.demo_file("mp4")
        out = self.ws.new_path("mp4")
        argv = [t.replace("<IN.mp4>", src).replace("<OUT.mp4>", out) for t in TEMPLATES["mp4"].argv_template()]
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertEqual((p.returncode, p.stdout), (0, b""))
        again = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.assertIn(b"already exists", again.stdout)                 # -n still reports a reused name at this log level


class TestEveryExportTemplateHidesTheTagsAndIsQuoted(unittest.TestCase):
    def test_templates(self):
        for ext, cmd in TEMPLATES.items():
            self.assertIn("-loglevel error -n -i", cmd.text, ext)
            self.assertRegex(cmd.text, r'-i "<IN\.%s>".* "<OUT\.%s>"$' % (ext, ext))
        self.assertIsNotNone(APNG)
        self.assertRegex(APNG.text, r'-i "<IN\.png>".* "<OUT\.png>"$')
        self.assertIn("-loglevel error", WEBP)


if __name__ == "__main__":
    unittest.main()
