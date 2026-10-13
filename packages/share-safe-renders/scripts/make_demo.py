#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_demo.py - build six small SYNTHETIC demo files for trying scan.py.

Purpose   Give you something harmless to scan: files that leak on purpose, plus one control with only an ordinary prompt, so you can see
          what the scanner reports (and what it does not print) before you point it at your own renders.
Usage     python make_demo.py OUTDIR [--no-mp4] [--overwrite]
Inputs    OUTDIR: the folder to write into. It is created if it does not exist.
Outputs   Inside OUTDIR only:
            01_png_api_key_and_username.png   PNG text chunk, API-format workflow: a fake key and a path with a user name
            02_png_ztxt_webhook.png           PNG compressed (zTXt) chunk: a fake Discord webhook
            03_png_bypassed_node_secret.png   PNG, UI-format workflow: a fake key held by a BYPASSED node
            04_clean.png                      PNG with an ordinary prompt and nothing sensitive
            05_mp4_prompt_tag_and_free_box.mp4  MP4 made with ffmpeg: a prompt tag plus a hidden appended `free` box
            06_jpeg_exif_gps.jpg              JPEG with hand-written EXIF GPS (an open-ocean point)
            DEMO_EXPECTED.md                  what scan.py should report for each file
Exit      0 = the files that could be built were written (the MP4 is skipped, with a message, when ffmpeg is
              not on PATH or when --no-mp4 is given)
          2 = refused: bad OUTDIR, or a target file already exists and --overwrite was not given
          3 = a file could not be written
Safety    Everything is generated at run time. Every fake secret is assembled from short fragments with a fixed
          random seed, so no credential-shaped literal exists in this source file. The fake user name, path,
          address and coordinates are invented. Nothing is read from your machine, nothing is sent anywhere,
          nothing is deleted. The only program this script can start is ffmpeg (an argument list, never a shell
          string, only for the MP4 and only if it is on PATH, never in the current folder); --no-mp4 starts no program at all.
Python    3.9+, standard library only.
"""
import argparse
import json
import os
import random
import re
import string
import struct
import subprocess
import sys
import zlib

SEED = 20261012
ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "-_"
DIGITS = string.digits

# ---------------------------------------------------------------------------------------------------------------
# What each file should produce.  `classes` are the class ids scan.py reports for that file on its own (the human
# report merges companions, e.g. K1+H1; DEMO_EXPECTED.md lists both).  The test-suite scans the real files and
# compares against this table, so the table cannot drift from the scanner.
# ---------------------------------------------------------------------------------------------------------------
DEMO_FILES = [
    {"name": "01_png_api_key_and_username.png", "needs_ffmpeg": False, "exit": 1,
     "holds": "an API-format workflow in a PNG text chunk (`prompt`): a node input named api_key holding a fake "
              "OpenAI-style key, and a LoadImage input whose path contains a user name",
     "classes": ["K1", "K2", "P1"],
     "where": "png:tEXt; the key at node 11, the path at node 9"},
    {"name": "02_png_ztxt_webhook.png", "needs_ffmpeg": False, "exit": 1,
     "holds": "a UI-format workflow in a COMPRESSED PNG chunk (`workflow`, zTXt): a fake Discord webhook URL in "
              "a notification node",
     "classes": ["K3", "H3"],
     "where": "png:zTXt; node 7"},
    {"name": "03_png_bypassed_node_secret.png", "needs_ffmpeg": False, "exit": 1,
     "holds": "two text chunks: `prompt` (API format, without the bypassed node) and `workflow` (UI format) in which "
              "node 12 is BYPASSED (mode 4) yet still holds a fake key in a widget",
     "classes": ["K1", "K2", "H1"],
     "where": "png:tEXt (workflow chunk only); node 12, bypassed=yes"},
    {"name": "04_clean.png", "needs_ffmpeg": False, "exit": 0,
     "holds": "a normal prompt chunk (what was typed, model name, seed) and nothing sensitive: the control file",
     "classes": [],
     "where": "nothing is reported; the NOTES block says an embedded API-format workflow exists"},
    {"name": "05_mp4_prompt_tag_and_free_box.mp4", "needs_ffmpeg": True, "exit": 1,
     "holds": "an MP4 whose `prompt` tag carries workflow JSON with a LAN address and an e-mail address, and a "
              "`free` box appended after the video data that holds a fake key (ffprobe does not show that box)",
     "classes": ["M1", "P2", "P3", "K1"],
     "where": "mp4:tag (M1, P2, P3) and mp4:box:free (M1, K1)"},
    {"name": "06_jpeg_exif_gps.jpg", "needs_ffmpeg": False, "exit": 1,
     "holds": "a tiny grey JPEG with an EXIF block written by hand: camera make/model and a GPS position",
     "classes": ["G1"],
     "where": "jpeg:exif"},
]


def pick(rnd, alphabet, n):
    return "".join(rnd.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------------------------------------------
# fake values, assembled from fragments at run time
# ---------------------------------------------------------------------------------------------------------------
class FakeValues(object):
    def __init__(self, seed=SEED):
        self.r = random.Random(seed)

    def openai_style_key(self):
        # prefix joined from two fragments; "DEMOFAKE" marks it as invented
        return "s" + "k-" + "DEMOFAKE" + pick(self.r, ALNUM, 40)

    def discord_webhook(self):
        return ("https://discord.com/api/" + "web" + "hooks/" + pick(self.r, DIGITS, 18) + "/" +
                pick(self.r, URLSAFE, 68))

    def user_name(self):
        return "demo_user_42"

    def email(self):
        # a made-up top-level domain: scan.py deliberately ignores example.com / .test style placeholder
        # addresses, so a documentation address would not show up in the demo
        return "demo.person" + "@" + "mail." + "zzdemo"

    def lan_address(self):
        return "192.168.77.20"


# ---------------------------------------------------------------------------------------------------------------
# PNG
# ---------------------------------------------------------------------------------------------------------------
PNG_SIG = b"\x89PNG\r\n\x1a\n"


def png_chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data +
            struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))


def png_text(keyword, text):
    return png_chunk(b"tEXt", keyword.encode("latin-1") + b"\x00" + text.encode("utf-8"))


def png_ztxt(keyword, text):
    return png_chunk(b"zTXt", keyword.encode("latin-1") + b"\x00\x00" + zlib.compress(text.encode("utf-8"), 9))


def make_png(text_chunks, width=48, height=32):
    """A real, viewable RGB PNG (a soft gradient) with the given text chunks placed before the image data."""
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    rows = []
    for y in range(height):
        row = bytearray([0])                       # filter type 0
        for x in range(width):
            row += bytes((40 + x * 3 % 180, 60 + y * 5 % 160, 120 + (x + y) * 2 % 100))
        rows.append(bytes(row))
    idat = png_chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
    return PNG_SIG + ihdr + b"".join(text_chunks) + idat + png_chunk(b"IEND", b"")


def jdump(obj):
    return json.dumps(obj, separators=(",", ":"))


# ---------------------------------------------------------------------------------------------------------------
# ComfyUI-shaped JSON
# ---------------------------------------------------------------------------------------------------------------
def api_node(class_type, inputs, title=None):
    return {"class_type": class_type, "inputs": inputs, "_meta": {"title": title or class_type}}


def base_api_prompt():
    """The ordinary part of an API-format prompt (loader, prompt text, sampler)."""
    return {
        "3": api_node("KSampler", {"seed": 123456, "steps": 20, "cfg": 7.0, "sampler_name": "euler",
                                   "scheduler": "normal", "denoise": 1.0, "model": ["4", 0],
                                   "positive": ["6", 0], "latent_image": ["5", 0]}),
        "4": api_node("CheckpointLoaderSimple", {"ckpt_name": "demo_model.safetensors"}),
        "5": api_node("EmptyLatentImage", {"width": 512, "height": 512, "batch_size": 1}),
        "6": api_node("CLIPTextEncode", {"text": "a lighthouse on a cliff at dawn, oil painting", "clip": ["4", 1]}),
    }


def ui_node(nid, ntype, widget_names, widget_values, mode=0, title=None):
    node = {"id": nid, "type": ntype, "pos": [40 * nid, 80], "size": [260, 90], "flags": {}, "order": nid,
            "mode": mode,
            "inputs": [{"name": n, "type": "STRING", "widget": {"name": n}, "link": None} for n in widget_names],
            "outputs": [], "properties": {"Node name for S&R": ntype}, "widgets_values": widget_values}
    if title:
        node["title"] = title
    return node


def ui_workflow(nodes):
    return {"id": "00000000-0000-4000-8000-000000000000", "revision": 0, "last_node_id": 99, "last_link_id": 0,
            "nodes": nodes, "links": [], "groups": [], "config": {}, "extra": {"ds": {"scale": 1.0}},
            "version": 0.4}


def build_png_01(fv):
    prompt = base_api_prompt()
    bs = chr(92)                                  # a backslash; the Windows-style path is joined from pieces
    prompt["9"] = api_node("LoadImage", {"image": bs.join(["C:", "Users", fv.user_name(), "Pictures", "ref_photo.png"])})
    prompt["11"] = api_node("RemoteCaption", {"api_key": fv.openai_style_key(), "image": ["9", 0]},
                            title="Remote caption")
    return make_png([png_text("prompt", jdump(prompt))])


def build_png_02(fv):
    wf = ui_workflow([
        ui_node(1, "CheckpointLoaderSimple", ["ckpt_name"], ["demo_model.safetensors"]),
        ui_node(7, "DiscordNotify", ["webhook_url", "message"], [fv.discord_webhook(), "render finished"],
                title="Notify channel"),
    ])
    return make_png([png_ztxt("workflow", jdump(wf))])


def build_png_03(fv):
    prompt = base_api_prompt()                      # a bypassed node is not part of the API-format prompt
    wf = ui_workflow([
        ui_node(4, "CheckpointLoaderSimple", ["ckpt_name"], ["demo_model.safetensors"]),
        ui_node(6, "CLIPTextEncode", ["text"], ["a lighthouse on a cliff at dawn, oil painting"]),
        ui_node(12, "RemoteCaption", ["api_key", "instruction"], [fv.openai_style_key(), "describe the picture"],
                mode=4, title="Remote caption (bypassed)"),
    ])
    return make_png([png_text("prompt", jdump(prompt)), png_text("workflow", jdump(wf))])


def build_png_04(fv):
    return make_png([png_text("prompt", jdump(base_api_prompt()))])


# ---------------------------------------------------------------------------------------------------------------
# JPEG with hand-written EXIF (grey 16x16, DC-only blocks, standard DC Huffman table)
# ---------------------------------------------------------------------------------------------------------------
def tiff_with_gps(make, model, lat, lon):
    """A little-endian TIFF block: IFD0 (Make, Model, GPSInfo pointer) and a GPS IFD with N/S, E/W and the
    latitude and longitude as three rationals each."""
    def ascii_val(s):
        return s.encode("ascii") + b"\x00"

    n0, n1 = 3, 4
    off_ifd0 = 8
    size_ifd0 = 2 + 12 * n0 + 4
    off_data0 = off_ifd0 + size_ifd0                         # Make / Model strings
    make_b, model_b = ascii_val(make), ascii_val(model)
    off_make = off_data0
    off_model = off_make + len(make_b)
    off_gps = off_model + len(model_b)
    size_gps = 2 + 12 * n1 + 4
    off_rat = off_gps + size_gps

    def rationals(dms):
        return b"".join(struct.pack("<II", num, den) for num, den in dms)

    lat_b, lon_b = rationals(lat[1]), rationals(lon[1])
    out = b"II" + struct.pack("<HI", 42, off_ifd0)
    out += struct.pack("<H", n0)
    out += struct.pack("<HHII", 0x010F, 2, len(make_b), off_make)
    out += struct.pack("<HHII", 0x0110, 2, len(model_b), off_model)
    out += struct.pack("<HHII", 0x8825, 4, 1, off_gps)
    out += struct.pack("<I", 0)
    out += make_b + model_b
    out += struct.pack("<H", n1)
    out += struct.pack("<HHI", 0x0001, 2, 2) + lat[0].encode("ascii") + b"\x00\x00\x00"
    out += struct.pack("<HHII", 0x0002, 5, 3, off_rat)
    out += struct.pack("<HHI", 0x0003, 2, 2) + lon[0].encode("ascii") + b"\x00\x00\x00"
    out += struct.pack("<HHII", 0x0004, 5, 3, off_rat + len(lat_b))
    out += struct.pack("<I", 0)
    out += lat_b + lon_b
    return out


def jpeg_segment(marker, payload):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def jpeg_entropy_dc_only(dc_values):
    """Entropy-coded data for 8x8 grey blocks that carry only a DC value (standard luminance DC table, an AC
    table whose only code is end-of-block)."""
    dc_codes = {0: "00", 1: "010", 2: "011", 3: "100", 4: "101", 5: "110", 6: "1110", 7: "11110",
                8: "111110", 9: "1111110", 10: "11111110", 11: "111111110"}
    bits = ""
    prev = 0
    for v in dc_values:
        diff = v - prev
        prev = v
        cat = abs(diff).bit_length()
        bits += dc_codes[cat]
        if cat:
            bits += format(diff if diff > 0 else diff + (1 << cat) - 1, "0%db" % cat)
        bits += "0"                                           # end of block
    bits += "1" * (-len(bits) % 8)
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    return raw.replace(b"\xff", b"\xff\x00")


def build_jpeg_06(fv):
    exif = b"Exif\x00\x00" + tiff_with_gps(
        "DemoCam", "DC-1", ("N", [(12, 1), (34, 1), (5600, 100)]), ("W", [(156, 1), (47, 1), (2400, 100)]))
    dqt = b"\x00" + bytes([16] * 64)
    sof = struct.pack(">BHHB", 8, 16, 16, 1) + bytes([1, 0x11, 0])
    dht_dc = b"\x00" + bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]) + bytes(range(12))
    dht_ac = b"\x10" + bytes([1] + [0] * 15) + b"\x00"
    sos = bytes([1, 1, 0x00, 0, 63, 0])
    return (b"\xff\xd8" +
            jpeg_segment(0xE0, b"JFIF\x00" + bytes([1, 1, 0, 0, 1, 0, 1, 0, 0])) +        # JFIF 1.1, 1:1 pixels, no thumbnail
            jpeg_segment(0xE1, exif) +
            jpeg_segment(0xDB, dqt) + jpeg_segment(0xC0, sof) +
            jpeg_segment(0xC4, dht_dc) + jpeg_segment(0xC4, dht_ac) +
            jpeg_segment(0xDA, sos) + jpeg_entropy_dc_only([4, 12, 20, 8]) + b"\xff\xd9")


# ---------------------------------------------------------------------------------------------------------------
# MP4 (ffmpeg makes the video and the prompt tag; this script appends the hidden box)
# ---------------------------------------------------------------------------------------------------------------
def mp4_prompt_json(fv):
    prompt = base_api_prompt()
    prompt["20"] = api_node("RemoteRender", {"server": fv.lan_address(), "contact": fv.email()}, title="Render box")
    return jdump(prompt)


def same_dir(a, b):
    """True or False when two paths do or do not name the same folder, whatever their spelling (an extended-length prefix, a
    share path, a short name, a junction, a symbolic link); None when that cannot be told."""
    try:
        sa, sb = os.stat(a), os.stat(b)
        if sa.st_ino or sb.st_ino:
            return os.path.samestat(sa, sb)
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))
    except (OSError, ValueError):
        return None


def find_program(name):
    """Full path of `name`, looked up only in the absolute directories listed on PATH, never in the current folder
    (on Windows the library lookup searches the current folder first, so a planted ffmpeg.exe there would run).
    On Windows only `<name>.exe` counts. This is the only place this script reads the environment (PATH)."""
    try:
        here = os.getcwd()
    except OSError:
        here = None
    for d in os.get_exec_path():
        if not d or not os.path.isabs(d):
            continue
        if here is not None and same_dir(d, here) is not False:      # the current folder under any spelling, or an entry we cannot identify
            continue
        cand = os.path.join(d, name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def run_ffmpeg(exe, args):
    """Run ffmpeg with an argument list (no shell). Returns (ok, reason)."""
    try:
        r = subprocess.run([exe] + args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.SubprocessError) as ex:
        return False, type(ex).__name__
    if r.returncode != 0:
        return False, "ffmpeg exited with %d" % r.returncode
    return True, ""


def build_mp4_05(fv, path):
    """Build the MP4 next to its final name as <name>.part, append the hidden box, then rename it into place.
    Returns (written, reason). ffmpeg is told never to overwrite (-n), and nothing is deleted: a partial
    <name>.part left by a failed run is reported, and the user removes it."""
    exe = find_program("ffmpeg")
    if not exe:
        return False, "ffmpeg is not on PATH"
    part = path + ".part"
    if os.path.exists(part):
        return False, "an earlier run left %s; remove it and try again" % os.path.basename(part)
    base = ["-hide_banner", "-loglevel", "error", "-n", "-f", "lavfi", "-i",
            "testsrc=size=64x48:rate=10:duration=1", "-an", "-movflags", "use_metadata_tags",
            "-metadata", "prompt=" + mp4_prompt_json(fv), "-f", "mp4"]
    reason = ""
    for codec in (["-c:v", "libx264", "-pix_fmt", "yuv420p"], ["-c:v", "mpeg4"]):
        ok, reason = run_ffmpeg(exe, base + codec + [part])
        if ok:
            break
        if os.path.exists(part):                # a failed try may leave a partial file; the next try would trip on it
            return False, "ffmpeg failed (%s) and left %s; remove it and try again" % (reason, os.path.basename(part))
    else:
        return False, reason
    payload = b"hidden: " + fv.openai_style_key().encode("ascii")
    with open(part, "ab") as fh:                # a top-level `free` box after the media data: legal, invisible to players
        fh.write(struct.pack(">I", 8 + len(payload)) + b"free" + payload)
    os.replace(part, path)
    return True, ""


# ---------------------------------------------------------------------------------------------------------------
# DEMO_EXPECTED.md
# ---------------------------------------------------------------------------------------------------------------
def expected_markdown(written, skipped):
    lines = [
        "# Demo files: what scan.py should report",
        "",
        "These files were generated at run time by `make_demo.py`. Every secret, name, address and coordinate in them is",
        "invented. The scanner never prints the values, so this page lists classes and places only. Class ids are",
        "explained in `references/reading-the-report.md` in the skill folder.",
        "",
        "| File | What it holds | Classes scan.py should report | Where | Exit when scanned alone |",
        "| --- | --- | --- | --- | --- |",
    ]
    for d in DEMO_FILES:
        if d["name"] not in written:
            continue
        classes = ", ".join(d["classes"]) if d["classes"] else "none"
        lines.append("| `%s` | %s | %s | %s | %d |" % (d["name"], d["holds"], classes, d["where"], d["exit"]))
    leaking = sum(1 for d in DEMO_FILES if d["name"] in written and d["exit"] == 1)
    lines += ["", "Scanning the whole folder gives exit 1 (findings), because %d of the files leak on purpose." % leaking,
              "Its summary line says `1 unrecognized file(s) skipped`: that is this page, which is not a render.",
              "Scanning `04_clean.png` alone gives exit 0 (nothing found in what was scanned).", ""]
    if "05_mp4_prompt_tag_and_free_box.mp4" in written:
        lines += ["The MP4 was built with ffmpeg. The `free` box at the end is invisible to `ffprobe` and to players;",
                  "scan.py reads the box structure itself, so it sees it.", ""]
    if skipped:
        lines += ["Not written in this run:", ""] + ["- `%s`: %s" % (n, why) for n, why in skipped] + [""]
    lines += ["Details that can differ on your machine: `ffprobe: used` or `ffprobe: absent` in the summary line, the",
              "path separators in file names, and (for the MP4) which tag names your ffmpeg writes.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------------------------------
# (a backslash is a path separator only on Windows; in sh it is an escape character)
_PLAIN = re.compile(r"[A-Za-z0-9_./:\\-]+" if os.name == "nt" else r"[A-Za-z0-9_./:-]+")               # characters no shell reads as syntax
_PASTEABLE = re.compile(r"[A-Za-z0-9 ._()+:/\\-]+" if os.name == "nt" else r"[A-Za-z0-9 ._()+:/-]+")       # safe inside double quotes in PowerShell, cmd and sh


def quote(p):
    """The path as it is when it holds nothing a shell reads as syntax, otherwise in double quotes (a space, a parenthesis,
    a quote of any kind, $, a backtick, ; & | < > ^ % !, a line break ...).  Only call it for a pasteable() path."""
    return p if _PLAIN.fullmatch(p) else '"%s"' % p


def pasteable(p):
    """True when a command line holding this path in double quotes cannot run anything but the program named in it: only
    letters, digits, spaces and . _ ( ) + - : / (and, on Windows only, the backslash: it separates folders there, but in sh
    it is an escape character, so on macOS and Linux it makes the answer False).  A typographic quote, any other non-ASCII
    character, $, a backtick, a quote, % and ! (cmd), ; & | ^ < > or a line break makes the answer False."""
    return bool(_PASTEABLE.fullmatch(p))


def check_written(path, kind):
    """Cheap check that what was written has the right outline (not a scan)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if kind == "png":
        return data.startswith(PNG_SIG) and data.endswith(png_chunk(b"IEND", b""))
    if kind == "jpg":
        return data.startswith(b"\xff\xd8") and b"\xff\xd9" in data[-4:]
    return len(data) > 1000 and data[4:8] == b"ftyp"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="make_demo.py", description="Build six small synthetic demo files for scan.py.")
    ap.add_argument("outdir", metavar="OUTDIR", help="folder to write into (created if missing)")
    ap.add_argument("--no-mp4", action="store_true", help="skip the MP4 (the only file that needs ffmpeg)")
    ap.add_argument("--overwrite", action="store_true", help="replace demo files that already exist in OUTDIR")
    args = ap.parse_args(argv)

    out = os.path.abspath(args.outdir)
    if os.path.exists(out) and not os.path.isdir(out):
        sys.stderr.write("make_demo.py: OUTDIR exists and is not a folder\n")
        return 2
    names = [d["name"] for d in DEMO_FILES] + ["DEMO_EXPECTED.md"]
    clash = [n for n in names if os.path.exists(os.path.join(out, n))]
    if clash and not args.overwrite:
        sys.stderr.write("make_demo.py: refusing to overwrite existing file(s): %s\n"
                         "  use a new folder, or add --overwrite to replace the demo files only\n" % ", ".join(clash))
        return 2
    try:
        os.makedirs(out, exist_ok=True)
    except OSError:
        sys.stderr.write("make_demo.py: cannot create OUTDIR\n")
        return 2

    fv = FakeValues()
    builders = {"01_png_api_key_and_username.png": (build_png_01, "png"),
                "02_png_ztxt_webhook.png": (build_png_02, "png"),
                "03_png_bypassed_node_secret.png": (build_png_03, "png"),
                "04_clean.png": (build_png_04, "png"),
                "06_jpeg_exif_gps.jpg": (build_jpeg_06, "jpg")}
    written, skipped, failed = [], [], False
    for d in DEMO_FILES:
        name, path = d["name"], os.path.join(out, d["name"])
        if d["needs_ffmpeg"]:
            if args.no_mp4:
                skipped.append((name, "skipped because --no-mp4 was given"))
                continue
            ok, why = build_mp4_05(fv, path)
            if not ok:
                skipped.append((name, "skipped: " + why))
                continue
            kind = "mp4"
        else:
            data = builders[name][0](fv)
            kind = builders[name][1]
            try:
                with open(path, "wb") as fh:
                    fh.write(data)
            except OSError:
                sys.stderr.write("make_demo.py: could not write %s\n" % name)
                failed = True
                continue
        if check_written(path, kind):
            written.append(name)
        else:
            sys.stderr.write("make_demo.py: %s was written but does not look right\n" % name)
            failed = True
    try:
        with open(os.path.join(out, "DEMO_EXPECTED.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(expected_markdown(written, skipped))
    except OSError:
        sys.stderr.write("make_demo.py: could not write DEMO_EXPECTED.md\n")
        failed = True

    print("Demo folder: %s" % out)
    for n in written:
        print("  wrote   %s" % n)
    for n, why in skipped:
        print("  SKIPPED %s (%s)" % (n, why))
    print("%d of %d demo files written (none of them has been scanned yet)." % (len(written), len(DEMO_FILES)))
    scan_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan.py")
    if pasteable(scan_py) and pasteable(out):
        print("Next: python %s %s" % (quote(scan_py), quote(out)))
    else:
        print("Next: run scan.py on that folder. A path here has a character that a shell can read as syntax, so no "
              "command line is printed: type it yourself, with the paths in quotes that suit your shell.")
    return 3 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
