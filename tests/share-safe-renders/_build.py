# -*- coding: utf-8 -*-
"""Builders for tiny SYNTHETIC test files (PNG, JPEG, MP4) and fake secrets.

Everything is generated at run time.  Fake credentials are assembled from split
fragments, so no contiguous credential-shaped literal exists in this source file.
"""
import json
import random
import string
import struct
import zlib

ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "-_"
UPDIG = string.ascii_uppercase + string.digits
LOWHEX = "0123456789abcdef"


class Fake(object):
    """Deterministic fake-value factory.  Vendor prefixes are joined from fragments."""

    def __init__(self, seed=424242):
        self.r = random.Random(seed)

    def pick(self, alphabet, n):
        return "".join(self.r.choice(alphabet) for _ in range(n))

    # K1 ------------------------------------------------------------------
    def openai_legacy(self):
        return "s" + "k-" + self.pick(ALNUM, 48)

    def openai_old(self):
        return "s" + "k-" + self.pick(ALNUM, 20) + "T3Bl" + "bkFJ" + self.pick(ALNUM, 20)

    def openai_proj(self):
        return "s" + "k-" + "pro" + "j-" + self.pick(URLSAFE, 120)

    def anthropic(self):
        return "s" + "k-" + "ant-" + "api03-" + self.pick(URLSAFE, 93) + "AA"

    def github_classic(self):
        return "gh" + "p_" + self.pick(ALNUM, 36)

    def github_fine(self):
        return "github" + "_pat_" + self.pick(ALNUM, 22) + "_" + self.pick(ALNUM, 59)

    def aws(self):
        return "AK" + "IA" + self.pick(string.ascii_uppercase + "234567", 16)

    def google(self):
        return "AI" + "za" + self.pick(URLSAFE, 35)

    def slack_bot(self):
        return "xo" + "xb-" + self.pick(string.digits, 12) + "-" + self.pick(string.digits, 13) + "-" + self.pick(ALNUM, 24)

    def slack_user(self):
        return "xo" + "xp-" + self.pick(string.digits, 12) + "-" + self.pick(string.digits, 12) + "-" + \
            self.pick(string.digits, 13) + "-" + self.pick(LOWHEX, 32)

    def stripe_live(self):
        return "s" + "k_" + "live_" + self.pick(ALNUM, 24)

    def stripe_test(self):
        return "s" + "k_" + "test_" + self.pick(ALNUM, 24)

    def hf(self):
        return "h" + "f_" + self.pick(ALNUM, 34)

    # K3 ------------------------------------------------------------------
    def discord_webhook(self):
        return "https://discord.com/api/" + "web" + "hooks/" + self.pick(string.digits, 18) + "/" + self.pick(URLSAFE, 68)

    def slack_webhook(self):
        return ("https://hooks.slack" + ".com/services/T" + self.pick(UPDIG, 10) + "/B" + self.pick(UPDIG, 10) +
                "/" + self.pick(ALNUM, 24))

    # K2 (deliberately not vendor-shaped) -----------------------------------
    def secret_value(self, n=24):
        return self.pick(ALNUM + "!#%+=", n - 2) + "9Z"

    def uuid(self):
        h = self.pick(LOWHEX, 32)
        return "-".join([h[:8], h[8:12], "4" + h[13:16], "a" + h[17:20], h[20:32]])


PERSONAS = {
    "win_user": "tester_one", "mac_user": "qa_mac_two", "posix_user": "qa-bot",
    "email": "qa.person" + "@" + "zzfixture-mail.dev", "ip_a": "192.168.50.7", "ip_b": "10.20.30.40",
    "ip_c": "172.20.1.9", "host": "render-box-7.local",
}


# --------------------------------------------------------------------------
# ComfyUI-shaped JSON
# --------------------------------------------------------------------------
def api_prompt(extra=None, text="a lighthouse on a cliff at dawn, oil painting"):
    p = {
        "3": {"class_type": "KSampler", "inputs": {"seed": 1234567, "steps": 20, "cfg": 7.0, "sampler_name": "euler",
                                                   "model": ["4", 0], "positive": ["6", 0], "latent_image": ["5", 0]},
              "_meta": {"title": "KSampler"}},
        "4": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "base_model.safetensors"},
              "_meta": {"title": "Load Checkpoint"}},
        "5": {"class_type": "EmptyLatentImage", "inputs": {"width": 512, "height": 512, "batch_size": 1},
              "_meta": {"title": "Empty Latent"}},
        "6": {"class_type": "CLIPTextEncode", "inputs": {"text": text, "clip": ["4", 1]},
              "_meta": {"title": "Positive"}},
    }
    for k, v in (extra or {}).items():
        p[k] = v
    return p


def api_node(cls, inputs, title=None):
    return {"class_type": cls, "inputs": inputs, "_meta": {"title": title or cls}}


def ui_node(nid, ntype, widgets, names=None, mode=0, title=None):
    n = {"id": nid, "type": ntype, "pos": [10, 10], "size": [200, 80], "flags": {}, "order": nid, "mode": mode,
         "inputs": [{"name": nm, "type": "STRING", "widget": {"name": nm}, "link": None} for nm in (names or [])],
         "outputs": [], "properties": {"Node name for S&R": ntype}, "widgets_values": widgets}
    if title is not None:
        n["title"] = title
    return n


def ui_workflow(nodes):
    return {"id": "00000000-0000-4000-8000-000000000000", "revision": 0, "last_node_id": 99, "last_link_id": 0,
            "nodes": nodes, "links": [], "groups": [], "config": {}, "extra": {"ds": {"scale": 1.0}}, "version": 0.4}


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------
PNG_SIG = b"\x89PNG\r\n\x1a\n"


def chunk(ctype, data, crc=None, length=None):
    if isinstance(ctype, str):
        ctype = ctype.encode("ascii")
    c = (zlib.crc32(ctype + data) & 0xFFFFFFFF) if crc is None else crc
    return struct.pack(">I", len(data) if length is None else length) + ctype + data + struct.pack(">I", c)


def _kw(kw):
    return kw if isinstance(kw, bytes) else kw.encode("latin-1")


def t_text(kw, text, **k):
    return chunk("tEXt", _kw(kw) + b"\x00" + (text if isinstance(text, bytes) else text.encode("utf-8")), **k)


def z_text(kw, text, raw_stream=None, **k):
    body = raw_stream if raw_stream is not None else zlib.compress(text if isinstance(text, bytes) else text.encode("utf-8"), 9)
    return chunk("zTXt", _kw(kw) + b"\x00\x00" + body, **k)


def i_text(kw, text, compressed=False, raw_stream=None, **k):
    raw = text if isinstance(text, bytes) else text.encode("utf-8")
    body = raw_stream if raw_stream is not None else (zlib.compress(raw, 9) if compressed else raw)
    return chunk("iTXt", _kw(kw) + b"\x00" + bytes([1 if compressed else 0, 0]) + b"\x00" + b"\x00" + body, **k)


def ihdr():
    return chunk("IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))


def idat():
    return chunk("IDAT", zlib.compress((b"\x00" + b"\x10\x20\x30" * 2) * 2))


def make_png(*mid, **kw):
    out = [PNG_SIG, ihdr()] + list(mid) + [idat()]
    if kw.get("iend", True):
        out.append(chunk("IEND", b""))
    out.append(kw.get("tail", b""))
    return b"".join(out)


def bomb_stream(total_bytes, block=1 << 20):
    """A valid zlib stream that inflates to `total_bytes` zero bytes (built without big allocations)."""
    co = zlib.compressobj(9)
    zero = bytes(block)
    out = []
    left = total_bytes
    while left > 0:
        n = min(block, left)
        out.append(co.compress(zero[:n]))
        left -= n
    out.append(co.flush())
    return b"".join(out)


def prefix_then_bomb(prefix_text, total_bytes):
    co = zlib.compressobj(9)
    out = [co.compress(prefix_text.encode("utf-8"))]
    zero = bytes(1 << 20)
    left = total_bytes
    while left > 0:
        n = min(1 << 20, left)
        out.append(co.compress(zero[:n]))
        left -= n
    out.append(co.flush())
    return b"".join(out)


# --------------------------------------------------------------------------
# JPEG / EXIF
# --------------------------------------------------------------------------
def rationals(e, vals):
    return b"".join(struct.pack(e + "II", n, d) for n, d in vals)


def exif_gps_tiff(order="II", lat=((12, 1), (34, 1), (5600, 100)), lon=((156, 1), (47, 1), (2400, 100)),
                  lat_ref=b"N\x00", lon_ref=b"W\x00", forged_count=None, dup_exif_pointer=False):
    e = "<" if order == "II" else ">"
    head = (b"II" if order == "II" else b"MM") + struct.pack(e + "HI", 42, 8)
    n0 = 2 if dup_exif_pointer else 1
    gps_off = 8 + 2 + 12 * n0 + 4
    ifd0 = struct.pack(e + "H", n0)
    if dup_exif_pointer:                       # the Exif-IFD pointer and the GPS pointer name the same offset
        ifd0 += struct.pack(e + "HHII", 0x8769, 4, 1, gps_off)
    ifd0 += struct.pack(e + "HHII", 0x8825, 4, 1, gps_off) + struct.pack(e + "I", 0)
    n = 4
    data_off = gps_off + 2 + 12 * n + 4
    lat_b, lon_b = rationals(e, lat), rationals(e, lon)
    cnt = 3 if forged_count is None else forged_count
    gps = struct.pack(e + "H", n)
    gps += struct.pack(e + "HHI", 1, 2, 2) + lat_ref + b"\x00\x00"
    gps += struct.pack(e + "HHII", 2, 5, cnt, data_off)
    gps += struct.pack(e + "HHI", 3, 2, 2) + lon_ref + b"\x00\x00"
    gps += struct.pack(e + "HHII", 4, 5, cnt, data_off + len(lat_b))
    gps += struct.pack(e + "I", 0)
    return head + ifd0 + gps + lat_b + lon_b


def exif_text_tiff(text, order="II"):
    """TIFF with one ASCII ImageDescription tag (0x010E)."""
    e = "<" if order == "II" else ">"
    head = (b"II" if order == "II" else b"MM") + struct.pack(e + "HI", 42, 8)
    raw = text.encode("utf-8") + b"\x00"
    off = 8 + 2 + 12 + 4
    return head + struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x010E, 2, len(raw), off) + \
        struct.pack(e + "I", 0) + raw


def seg(marker, payload):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def make_jpeg(app1=(), com=(), tail=b"", eoi=True, extra_segments=()):
    out = [b"\xff\xd8", seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")]
    for p in app1:
        out.append(seg(0xE1, p))
    for c in com:
        out.append(seg(0xFE, c if isinstance(c, bytes) else c.encode("utf-8")))
    out.extend(extra_segments)
    out.append(seg(0xDA, b"\x01\x01\x00\x00\x3f\x00"))
    out.append(b"\x12\x34\xff\x00\x56\xff\xd0\x78")
    if eoi:
        out.append(b"\xff\xd9")
    out.append(tail)
    return b"".join(out)


def xmp_packet(lat_text, lon_text):
    xml = ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           '<rdf:Description xmlns:exif="http://ns.adobe.com/exif/1.0/" exif:GPSLatitude="%s" exif:GPSLongitude="%s"/>'
           '</rdf:RDF></x:xmpmeta>' % (lat_text, lon_text))
    return b"http://ns.adobe.com/xap/1.0/\x00" + xml.encode("utf-8")


# --------------------------------------------------------------------------
# MP4 / MOV
# --------------------------------------------------------------------------
def box(typ, payload=b""):
    if isinstance(typ, str):
        typ = typ.encode("latin-1")
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def ftyp():
    return box("ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2mp41")


def ilst_item(atom, text):
    raw = text if isinstance(text, bytes) else text.encode("utf-8")
    return box(atom, box("data", struct.pack(">II", 1, 0) + raw))


def meta_ilst(items, hdlr_type=b"mdir"):
    hdlr = box("hdlr", struct.pack(">I", 0) + b"\x00\x00\x00\x00" + hdlr_type + b"\x00" * 12 + b"\x00")
    return box("meta", struct.pack(">I", 0) + hdlr + box("ilst", b"".join(items)))


def meta_mdta(pairs):
    """QuickTime/ffmpeg 'mdta' keys + ilst: pairs = [(key, text)]"""
    keys = struct.pack(">II", 0, len(pairs)) + b"".join(
        struct.pack(">I4s", 8 + len(k), b"mdta") + k.encode("ascii") for k, _ in pairs)
    items = b"".join(box(struct.pack(">I", i + 1), box("data", struct.pack(">II", 1, 0) + v.encode("utf-8")))
                     for i, (_, v) in enumerate(pairs))
    hdlr = box("hdlr", struct.pack(">I", 0) + b"\x00\x00\x00\x00" + b"mdta" + b"\x00" * 12 + b"\x00")
    return box("meta", hdlr + box("keys", keys) + box("ilst", items))


def qt_text_atom(atom, text):
    raw = text.encode("utf-8")
    return box(atom, struct.pack(">HH", len(raw), 0x55C4) + raw)


def make_mp4(udta_children=(), meta=None, appended=(), mdat=b"\x00" * 32, ffmpeg_like_free=False):
    moov_kids = [box("mvhd", b"\x00" * 100)]
    if udta_children or meta is not None:
        kids = list(udta_children)
        if meta is not None:
            kids.append(meta)
        moov_kids.append(box("udta", b"".join(kids)))
    parts = [ftyp(), box("moov", b"".join(moov_kids)), box("mdat", mdat)]
    if ffmpeg_like_free:
        parts.insert(1, box("free"))
    parts.extend(appended)
    return b"".join(parts)


def jdump(obj):
    return json.dumps(obj, separators=(",", ":"))


def mail(local, domain):
    """local@domain assembled at run time, so that no e-mail address exists as a literal in a test source file."""
    return local + "@" + domain
