# -*- coding: utf-8 -*-
"""Hostile and degenerate inputs: bombs, truncation, bad CRCs, bad boxes, deep JSON, obfuscation, ReDoS."""
import os
import struct
import threading
import time
import unittest

from _base import ScanCase, B, scan


def codes(rp):
    return [e["code"] for e in rp.errors]


class TestBombs(ScanCase):
    def patch(self, name, value):
        old = getattr(scan, name)
        setattr(scan, name, value)
        self.addCleanup(setattr, scan, name, old)

    def test_ztxt_zero_bomb_is_stopped_early(self):
        png = B.make_png(B.z_text("prompt", "", raw_stream=B.bomb_stream(300 << 20)))
        t = time.perf_counter()
        rp = self.inproc(self.write("bomb.png", png))
        self.assertLess(time.perf_counter() - t, 10)
        self.assertEqual(rp.findings, [])
        self.assertTrue(any(c in ("png_inflate_bomb_ratio", "png_inflate_bomb_size") for c in codes(rp)), codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_itxt_compressed_zero_bomb(self):
        png = B.make_png(B.i_text("Comment", "", compressed=True, raw_stream=B.bomb_stream(200 << 20)))
        rp = self.inproc(self.write("bomb2.png", png))
        self.assertIn("png_inflate_bomb_ratio", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_secret_before_the_bomb_is_still_reported(self):
        tok = self.fake.hf()
        stream = B.prefix_then_bomb(B.jdump(B.api_prompt({"9": B.api_node("Note", {"text": tok})})) + " ", 60 << 20)
        rp = self.inproc(self.write("b3.png", B.make_png(B.z_text("prompt", "", raw_stream=stream))))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(len(self.comp(rp, "H3")), 1)
        self.assertTrue(codes(rp))
        self.assertEqual(self.code_of(rp), 1)

    def test_stream_size_cap_on_incompressible_data(self):
        self.patch("INFLATE_CAP_STREAM", 1 << 20)
        png = B.make_png(B.z_text("prompt", os.urandom(3 << 20)))
        rp = self.inproc(self.write("big.png", png))
        self.assertIn("png_inflate_bomb_size", codes(rp))

    def test_file_wide_budget(self):
        self.patch("INFLATE_CAP_FILE", 1 << 20)
        text = os.urandom(350000).hex()
        rp = self.inproc(self.write("budget.png", B.make_png(B.z_text("a", text), B.z_text("b", text))))
        self.assertIn("png_inflate_budget", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_corrupt_zlib_is_reported(self):
        rp = self.inproc(self.write("cz.png", B.make_png(B.z_text("prompt", "", raw_stream=b"\x78\x9c\xff\xff\xff\xff"))))
        self.assertIn("png_zlib_corrupt", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_realistic_big_workflow_is_not_a_bomb(self):
        extra = {}
        for i in range(1000, 1600):
            extra[str(i)] = B.api_node("KSampler", {"seed": self.fake.r.randint(1, 2 ** 40), "steps": 20 + i % 7,
                                                    "cfg": 7.5, "sampler_name": "euler", "model": [str(i - 1), 0],
                                                    "text": "prompt number %d with %s" % (i, self.fake.pick(B.ALNUM, 30))})
        png = B.make_png(B.z_text("workflow", B.jdump(B.api_prompt(extra))))
        rp = self.inproc(self.write("w.png", png))
        self.assertEqual((rp.findings, rp.errors), ([], []))

    def test_deeply_double_encoded_json_is_bounded(self):
        s = B.jdump({"api_key": self.fake.secret_value()})
        for _ in range(scan.MAX_DOUBLE_ENCODE + 3):
            s = B.jdump({"x": s})
        rp = self.inproc(self.write("dd.png", B.make_png(B.t_text("prompt", s))))
        self.assertIn("json_depth_cap", codes(rp))


class TestTruncationAndCorruption(ScanCase):
    def test_png_cut_inside_text_chunk_keeps_what_was_there(self):
        tok = self.fake.hf()
        body = B.jdump(B.api_prompt({"9": B.api_node("Note", {"text": tok + " " + "pad " * 80})}))
        data = B.PNG_SIG + B.ihdr() + B.t_text("prompt", body)[:-25]
        rp = self.inproc(self.write("t.png", data))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertIn("png_truncated", codes(rp))
        self.assertEqual(self.code_of(rp), 1)

    def test_png_cut_elsewhere_is_unscanned_not_clean(self):
        for name, data in (("idat", B.PNG_SIG + B.ihdr() + B.idat()[:20]), ("noiend", B.make_png(iend=False)),
                           ("sigonly", B.PNG_SIG), ("hdrcut", B.PNG_SIG + B.ihdr()[:10])):
            rp = self.inproc(self.write(name + ".png", data))
            self.assertEqual(self.code_of(rp), 3, name)

    def test_png_bad_crc(self):
        tok = self.fake.hf()
        bad = B.t_text("prompt", "k " + tok, crc=0x12345678)
        rp = self.inproc(self.write("c.png", B.make_png(bad)))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertIn("png_crc_mismatch", codes(rp))
        self.assertEqual(self.code_of(rp), 1)
        rp = self.inproc(self.write("c2.png", B.make_png(B.t_text("prompt", "fine", crc=0x1))))
        self.assertEqual((rp.findings, self.code_of(rp)), ([], 3))
        idat_bad = B.PNG_SIG + B.ihdr() + B.chunk("IDAT", b"\x78\x9c\x01\x00", crc=5) + B.chunk("IEND", b"")
        rp = self.inproc(self.write("c3.png", idat_bad))
        self.assertEqual(self.code_of(rp), 3)

    def test_png_lost_sync_recovers_text_chunks(self):
        tok = self.fake.github_classic()
        data = B.PNG_SIG + B.ihdr() + struct.pack(">I", 0xF0000000) + b"junk" + B.t_text("prompt", "k " + tok)
        rp = self.inproc(self.write("s.png", data))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertIn("png_bad_chunk", codes(rp))
        self.assertEqual(len(rp.findings), 1)              # carved once, not twice

    def test_png_trailing_data_and_appended_png(self):
        a, b = self.fake.hf(), self.fake.github_classic()
        inner = B.make_png(B.t_text("prompt", "k " + b))
        rp = self.inproc(self.write("t.png", B.make_png(tail=b"\x00\x00 note " + a.encode() + b"\x00" + inner)))
        self.assertEqual(len(self.prim(rp, "K1")), 2)       # tail starts with junk -> raw runs see both
        rp = self.inproc(self.write("t2.png", B.make_png(tail=inner)))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(self.prim(rp, "K1")[0]["carrier"], "png:tEXt")

    def test_png_unknown_private_chunk_is_scanned(self):
        tok = self.fake.hf()
        rp = self.inproc(self.write("p.png", B.make_png(B.chunk("prVt", b"\x01\x02 token: " + tok.encode()))))
        # a private chunk type is not echoed (four free characters per finding would let a file spell a message)
        self.assertRegex(self.prim(rp, "K1")[0]["carrier"], r"^png:chunk~[0-9a-f]{8}$")

    def test_png_text_chunk_without_separator(self):
        rp = self.inproc(self.write("n.png", B.make_png(B.chunk("tEXt", b"nokeywordhere " + self.fake.hf().encode()))))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertIn("png_bad_text_chunk", codes(rp))

    def test_png_unknown_compression_method(self):
        rp = self.inproc(self.write("m.png", B.make_png(B.chunk("zTXt", b"prompt\x00\x07" + b"abc"))))
        self.assertIn("png_unknown_compression", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_jpeg_truncated(self):
        tok = self.fake.hf()
        rp = self.inproc(self.write("t.jpg", B.make_jpeg(com=["x " + tok], eoi=False)))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        rp = self.inproc(self.write("t2.jpg", B.make_jpeg(eoi=False)))
        self.assertEqual((rp.findings, self.code_of(rp)), ([], 3))
        rp = self.inproc(self.write("t3.jpg", B.make_jpeg()[:30]))
        self.assertEqual(self.code_of(rp), 3)
        rp = self.inproc(self.write("t4.jpg", b"\xff\xd8\xff\xe1\x00\x02" + b"\x00\x05garbage" + b"\xff"))
        self.assertEqual(self.code_of(rp), 3)

    def test_jpeg_forged_segment_length(self):
        rp = self.inproc(self.write("f.jpg", b"\xff\xd8\xff\xe1\xff\xff" + b"Exif\x00\x00II*\x00"))
        self.assertEqual(self.code_of(rp), 3)

    def test_jpeg_circular_ifd_and_huge_counts(self):
        e = "<"
        tiff = b"II*\x00" + struct.pack(e + "I", 8) + struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x010E, 2, 99999999, 100) \
            + struct.pack(e + "I", 8)                      # next IFD points back at itself
        rp = self.inproc(self.write("c.jpg", B.make_jpeg(app1=[b"Exif\x00\x00" + tiff])))
        self.assertIn(self.code_of(rp), (0, 3))

    def test_mp4_truncated_media(self):
        rp = self.inproc(self.write("t.mp4", B.make_mp4()[:-10]))
        self.assertIn("mp4_truncated", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_mp4_garbage_json_appended_after_last_box(self):
        val = self.fake.secret_value()
        data = B.make_mp4() + ('{"api_key": "%s", "x": [' % val).encode()
        rp = self.inproc(self.write("g.mp4", data))
        self.assertEqual(len(self.prim(rp, "K2")), 1)
        self.assertEqual(len(self.prim(rp, "M1")), 1)
        self.assertEqual(self.code_of(rp), 1)

    def test_mp4_tiny_trailing_bytes(self):
        rp = self.inproc(self.write("g.mp4", B.make_mp4() + b"HIDDEN"))
        self.assertEqual(len(self.prim(rp, "M1")), 1)
        rp = self.inproc(self.write("g2.mp4", B.make_mp4() + b"\x00\x00\x00"))
        self.assertEqual(rp.findings, [])

    def test_mp4_bad_box_sizes(self):
        rp = self.inproc(self.write("b.mp4", B.make_mp4() + struct.pack(">I4s", 4, b"free") + b"xxxxxxxx"))
        self.assertIn("mp4_bad_box", codes(rp))
        self.assertEqual(self.code_of(rp), 1)
        rp = self.inproc(self.write("b2.mp4", B.ftyp() + struct.pack(">I4sQ", 1, b"mdat", 1 << 60) + b"\x00" * 8))
        self.assertIn("mp4_truncated", codes(rp))
        rp = self.inproc(self.write("b3.mp4", B.ftyp() + struct.pack(">I4sQ", 1, b"free", 3)))
        self.assertIn("mp4_bad_box", codes(rp))                 # unexplained bytes: reported, never clean
        self.assertIn(self.code_of(rp), (1, 3))

    def test_mp4_nesting_bomb(self):
        inner = B.box(b"free", b"")
        for _ in range(60):
            inner = B.box(b"moov", inner)
        rp = self.inproc(self.write("n.mp4", B.ftyp() + inner))
        self.assertIn("mp4_depth", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    def test_mp4_many_boxes(self):
        data = B.ftyp() + B.box(b"moov", B.box(b"mvhd", b"\x00" * 100)) + b"".join(B.box(b"skip") for _ in range(30000))
        t = time.perf_counter()
        rp = self.inproc(self.write("many.mp4", data))
        self.assertLess(time.perf_counter() - t, 15)
        self.assertEqual(rp.findings, [])

    def test_mp4_ilst_with_lying_item_sizes(self):
        bad = B.box(b"meta", struct.pack(">I", 0) + B.box(b"ilst", struct.pack(">I4s", 4, b"\xa9cmt") + b"junk"))
        rp = self.inproc(self.write("l.mp4", B.make_mp4(udta_children=[bad])))
        self.assertIn(self.code_of(rp), (1, 3))


class TestHostileJson(ScanCase):
    def one(self, text, name="h.png"):
        return self.inproc(self.write(name, B.make_png(B.t_text("prompt", text))))

    def test_very_deep_nesting_does_not_crash(self):
        for n in (5000, 100000):
            for o, c in (("[", "]"), ('{"a":', "}")):
                rp = self.one(o * n + "1" + c * n)
                self.assertIn(self.code_of(rp), (0, 3))
                self.assertNotIn("internal_error", " ".join(codes(rp)))

    def test_secret_inside_very_deep_nesting_is_found_by_the_text_pass(self):
        tok = self.fake.hf()
        rp = self.one("[" * 6000 + '"' + tok + '"' + "]" * 6000)
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(self.code_of(rp), 1)

    def test_huge_integer_literal(self):
        tok = self.fake.hf()
        rp = self.one('{"a": %s, "n": {"text": "%s"}}' % ("9" * 6000, tok))
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        self.assertEqual(codes(rp), [])

    def test_unicode_escaped_secret(self):
        tok = self.fake.openai_legacy()
        esc = "".join("\\u%04x" % ord(c) for c in tok)
        rp = self.one('{"text": "%s"}' % esc)
        self.assertEqual([x["sha256_prefix"] for x in self.prim(rp, "K1")], [scan.sha8(tok)])

    def test_text_encodings(self):
        tok = self.fake.hf()
        doc = '{"a": {"text": "%s"}}' % tok
        for name, raw in (("utf16", doc.encode("utf-16")), ("utf16le_nobom", doc.encode("utf-16-le")),
                          ("utf16be_nobom", doc.encode("utf-16-be")), ("bom8", b"\xef\xbb\xbf" + doc.encode()),
                          ("latin1", ('{"\xe4": {"text": "%s"}}' % tok).encode("latin-1"))):
            rp = self.inproc(self.write(name + ".png", B.make_png(B.t_text("prompt", raw))))
            self.assertEqual(len(self.prim(rp, "K1")), 1, name)

    def test_padding_and_garbage_around_json(self):
        tok = self.fake.hf()
        rp = self.one('{"a": 1}' + "\x00" * 10 + "tail " + tok)
        self.assertEqual(len(self.prim(rp, "K1")), 1)
        rp = self.one("\x00\x01junk" + '{"a": {"text": "%s"}}' % tok)
        self.assertEqual(len(self.prim(rp, "K1")), 1)

    def test_zero_width_characters_inside_a_token(self):
        tok = self.fake.openai_legacy()
        sneaky = tok[:10] + "​" + tok[10:30] + "­" + tok[30:]
        rp = self.one(B.jdump({"text": "key " + sneaky}))
        self.assertEqual(len(self.prim(rp, "K1")), 1)

    def test_chunk_and_segment_caps_are_reported(self):
        old = (scan.MAX_PNG_CHUNKS, scan.MAX_JPEG_SEGMENTS)
        scan.MAX_PNG_CHUNKS, scan.MAX_JPEG_SEGMENTS = 50, 20
        self.addCleanup(lambda: setattr(scan, "MAX_PNG_CHUNKS", old[0]) or setattr(scan, "MAX_JPEG_SEGMENTS", old[1]))
        rp = self.inproc(self.write("c.png", B.make_png(*[B.t_text("k%d" % i, "v") for i in range(200)])))
        self.assertIn("png_chunk_cap", codes(rp))
        self.assertEqual(self.code_of(rp), 3)
        segs = [B.seg(0xE5, b"x" * 8) for _ in range(100)]
        rp = self.inproc(self.write("c.jpg", B.make_jpeg(extra_segments=segs)))
        self.assertIn("jpeg_segment_cap", codes(rp))
        self.assertEqual(self.code_of(rp), 3)

    @unittest.skipIf(os.name == "nt", "fifo needs POSIX")
    def test_open_regular_refuses_a_fifo_without_blocking(self):
        # open_regular runs in a thread with a time limit: if a regression makes it block on a pipe that nobody writes to, the
        # test FAILS after 10 s instead of hanging the whole suite for ever.
        p = os.path.join(self.dir, "pipe")
        os.mkfifo(p)
        outcome = []

        def attempt():
            try:
                scan.open_regular(p).close()
                outcome.append("opened it")
            except OSError:
                outcome.append("refused it")

        t = threading.Thread(target=attempt, daemon=True)
        t.start()
        t.join(10)
        if t.is_alive():
            os.close(os.open(p, os.O_RDWR))                  # gives the stuck open a writer, so the thread ends and the folder can be removed
            t.join(10)
            self.fail("open_regular was still blocked after 10 s on a named pipe that nobody writes to")
        self.assertEqual(outcome, ["refused it"])

    def test_lone_surrogates_and_control_chars(self):
        tok = self.fake.hf()
        rp = self.one('{"a": "\\ud800 \\udfff \\u0000 \\u001f %s"}' % tok)
        self.assertEqual(len(self.prim(rp, "K1")), 1)

    def test_findings_are_capped_and_the_cap_is_reported(self):
        emails = " ".join(B.mail("u%d" % i, "zzfixture-mail.dev") for i in range(3000))
        rp = self.one(B.jdump({"text": emails}))
        self.assertEqual(len(self.prim(rp, "P2")), scan.MAX_FINDINGS_PER_FILE)
        self.assertIn("findings_capped_%d" % scan.MAX_FINDINGS_PER_FILE, [n["code"] for n in rp.info])

    def test_same_value_repeated_is_one_finding(self):
        rp = self.one(B.jdump({"text": (self.fake.hf() + " ") * 5000}))
        self.assertEqual(len(self.prim(rp, "K1")), 1)

    def test_twenty_thousand_nodes(self):
        extra = {str(i): B.api_node("Note", {"text": "node %d note" % i, "n": i}) for i in range(1000, 21000)}
        t = time.perf_counter()
        rp = self.one(B.jdump(B.api_prompt(extra)))
        self.assertLess(time.perf_counter() - t, 10)
        self.assertEqual(rp.findings, [])

    def test_thousands_of_tiny_chunks(self):
        chunks = [B.t_text("k%d" % i, "v") for i in range(5000)]
        t = time.perf_counter()
        rp = self.inproc(self.write("many.png", B.make_png(*chunks)))
        self.assertLess(time.perf_counter() - t, 10)
        self.assertEqual(rp.findings, [])


ADVERSARIAL = {
    "plain_a": "a" * 80000, "sk_dash": "sk-" * 26666, "sk_prefix_long": "sk-" + "a" * 79997, "at": "@" * 80000,
    "a_at": "a@" * 40000, "a_long_at": ("a" * 63 + "@") * 1250, "dots": "." * 80000, "akia": "AKIA" * 20000,
    "ip_frag": "192.168." * 10000, "ip_long": "1." * 40000, "token_eq": "token=" * 13000,
    "users": "C:\\Users\\" * 8000, "home": "/home/" * 13000, "escapes": "\\u00" * 16000, "backslash": "\\" * 80000,
    "brace": "{" * 80000, "quote": '"' * 80000, "quote_colon": '":' * 40000, "dot_local": ".local" * 13000,
    "host_dots": "a." * 40000 + "local", "hf": "hf_" * 26000, "xox": ("xox" + "b-") * 16000, "bearer": "bearer " * 11000,
    "discord": "discord/webhooks/" * 4700, "slack_hook": "hooks.slack.com/services/" * 3200,
    "pem": "-----BEGIN " * 7000, "gps": "gpslatitude=" * 6600, "mixed": ("sk-a@b.c 192.168.1.1 token=abc12345 "
                                                                       "C:\\Users\\x\\ /home/y/ .local " * 1300)[:80000],
    "digits": "1" * 80000, "unicode": "\u00e9\ud800\U0001f600" * 20000, "nulls": "\x00" * 80000,
    "email_tail": "a" * 40000 + "@" + "b" * 40000, "authorization": "authorization:" * 6000,
    "privkey": ("-----BEGIN " + "PRIVATE KEY-----") * 2900, "json_like": '{"password":"' * 6000,
}


class TestAdversarialTiming(ScanCase):
    def test_each_80k_string_is_fast(self):
        slow = []
        for name, s in ADVERSARIAL.items():
            t = time.perf_counter()
            scan.scan_text(s, unescape=True)
            dt = time.perf_counter() - t
            if dt > 0.5:
                slow.append((name, round(dt, 2)))
        self.assertEqual(slow, [])

    def test_whole_pipeline_on_adversarial_strings(self):
        t = time.perf_counter()
        for name in ("mixed", "token_eq", "json_like", "quote_colon", "users"):
            rp = self.inproc(self.write(name + ".png", B.make_png(B.t_text("prompt", ADVERSARIAL[name]))))
            self.assertNotIn("internal_error", " ".join(codes(rp)))
        self.assertLess(time.perf_counter() - t, 5)

    def test_80k_string_as_a_json_value_and_as_a_key(self):
        s = ADVERSARIAL["mixed"]
        for doc in (B.jdump({"text": s}), B.jdump({s: "value"}), B.jdump([s] * 3)):
            t = time.perf_counter()
            self.inproc(self.write("x.png", B.make_png(B.t_text("prompt", doc))))
            self.assertLess(time.perf_counter() - t, 1.5)

    def test_one_megabyte_of_base64_is_quiet_and_quick(self):
        blob = self.fake.pick(B.ALNUM + "+/", 1 << 20) + "=="
        t = time.perf_counter()
        rp = self.inproc(self.write("b64.png", B.make_png(B.t_text("prompt", B.jdump({"latent": blob})))))
        self.assertLess(time.perf_counter() - t, 3)
        self.assertEqual(rp.findings, [])


if __name__ == "__main__":
    unittest.main()
