# -*- coding: utf-8 -*-
"""A bug found while building the package, with the test that pins it.

HEIC / HEIF / AVIF files (the iPhone default) start with an `ftyp` box, exactly like an MP4. The prototype therefore walked
them as MP4 and reported "nothing found" (exit 0) for a photo whose GPS sits in an Exif item inside `mdat`, which the scanner
does not read. That broke the contract "a file that could not be scanned is never reported as clean". They are now
`unsupported_media` (exit 3), like WebP and GIF.
"""
import os
import struct

from _base import ScanCase, B, scan


def ftyp(major, compat):
    body = major + struct.pack(">I", 0) + b"".join(compat)
    return struct.pack(">I", 8 + len(body)) + b"ftyp" + body


def heif_like(major, compat):
    """An ISO-BMFF image file: ftyp, a meta box, and an mdat that holds an Exif item with GPS."""
    exif = b"Exif\x00\x00" + B.exif_gps_tiff()
    meta = B.box("meta", struct.pack(">I", 0) + B.box("hdlr", struct.pack(">I", 0) + b"\x00" * 4 + b"pict" + b"\x00" * 13))
    return ftyp(major, compat) + meta + B.box("mdat", exif)


class TestHeifIsNeverReportedClean(ScanCase):
    def test_heic_avif_and_mif1_are_exit_3_unsupported(self):
        for major, compat in ((b"heic", [b"mif1", b"heic"]), (b"avif", [b"mif1", b"avif"]), (b"mif1", [b"heic"]),
                              (b"heix", [b"mif1"]), (b"avis", [b"avif"])):
            p = self.write(major.decode() + ".bin", heif_like(major, compat))
            r = self.cli(p)
            self.assertEqual(r.code, 3, major)
            self.assertEqual([e["code"] for e in r.doc["errors"]], ["unsupported_media"], major)
            self.assertEqual(r.doc["summary"]["files_scanned"], 0)
            self.assertNotIn("NOTHING FOUND", r.out)
            self.assertIn("COULD NOT SCAN", r.out)

    def test_the_old_behaviour_would_have_said_nothing_found(self):
        # negative control: the same bytes under an MP4 brand, with nothing else that says "image", are walked and, since the GPS
        # is in the first mdat, come out clean. This is the documented miss for MP4 sample data; it is why the HEIF marks must
        # not take this path. (With a `pict` handler in a top-level meta box the same bytes are refused: see below.)
        data = ftyp(b"isom", [b"mp41"]) + B.box("mdat", b"Exif\x00\x00" + B.exif_gps_tiff())
        r = self.cli(self.write("looks_like_mp4.bin", data))
        self.assertEqual(r.code, 0)
        self.assertEqual(r.doc["summary"]["files_scanned"], 1)

    def test_an_avif_with_an_encoder_major_brand_is_found_by_its_compatible_brands(self):
        # review finding S3: only the major brand was checked, and an AVIF can have any major brand (MA1B here)
        p = self.write("avif_major_ma1b.bin", heif_like(b"MA1B", [b"avif", b"mif1", b"miaf"]))
        r = self.cli(p)
        self.assertEqual(r.code, 3)
        self.assertEqual([e["code"] for e in r.doc["errors"]], ["unsupported_media"])
        self.assertEqual(r.doc["summary"]["files_scanned"], 0)
        # one compatible brand in the middle of a long list is enough
        p = self.write("long_list.bin", heif_like(b"isom", [b"iso2", b"mp41", b"mp42", b"heic", b"dash"]))
        self.assertEqual(self.cli(p).code, 3)

    def test_the_extension_wins_over_an_mp4_looking_start(self):
        for ext in ("avif", "heic", "heif", "hif"):
            data = ftyp(b"isom", [b"mp41"]) + B.box("mdat", b"Exif\x00\x00" + B.exif_gps_tiff())
            r = self.cli(self.write("renamed." + ext, data))
            self.assertEqual((r.code, [e["code"] for e in r.doc["errors"]]), (3, ["unsupported_media"]), ext)
        # control: the same bytes under an MP4 extension are walked
        r = self.cli(self.write("renamed.mp4", ftyp(b"isom", [b"mp41"]) + B.box("mdat", b"\x00" * 16)))
        self.assertEqual((r.code, r.doc["summary"]["files_scanned"]), (0, 1))

    def test_a_top_level_meta_box_with_the_pict_handler_marks_an_image(self):
        r = self.cli(self.write("pict_handler.bin", heif_like(b"isom", [b"mp41"])))
        self.assertEqual((r.code, [e["code"] for e in r.doc["errors"]]), (3, ["unsupported_media"]))
        # the QuickTime form of the meta box has no version and flags field
        meta = B.box("meta", B.box("hdlr", struct.pack(">I", 0) + b"\x00" * 4 + b"pict" + b"\x00" * 13))
        data = ftyp(b"isom", [b"mp41"]) + meta + B.box("mdat", b"\x00" * 16)
        self.assertEqual(self.cli(self.write("pict_qt_form.bin", data)).code, 3)
        # controls: a meta box whose handler is `mdir` (iTunes style tags) or `mdta` is an ordinary video's
        for handler in (b"mdir", b"mdta"):
            meta = B.box("meta", struct.pack(">I", 0) + B.box("hdlr", struct.pack(">I", 0) + b"\x00" * 4 + handler + b"\x00" * 13))
            data = ftyp(b"isom", [b"mp41"]) + B.box("moov", B.box("mvhd", b"\x00" * 100)) + meta + B.box("mdat", b"\x00" * 16)
            r = self.cli(self.write("tags_%s.mp4" % handler.decode(), data))
            self.assertEqual((r.code, r.doc["summary"]["files_scanned"]), (0, 1), handler)
        # control: a pict handler that is not at the top level (inside moov) is not an image container
        inner = B.box("moov", B.box("mvhd", b"\x00" * 100) + B.box("meta", struct.pack(">I", 0) + B.box(
            "hdlr", struct.pack(">I", 0) + b"\x00" * 4 + b"pict" + b"\x00" * 13)))
        r = self.cli(self.write("nested_pict.mp4", ftyp(b"isom", [b"mp41"]) + inner + B.box("mdat", b"\x00" * 16)))
        self.assertEqual((r.code, r.doc["summary"]["files_scanned"]), (0, 1))

    def test_an_mp4_with_many_ordinary_brands_is_still_scanned(self):
        data = ftyp(b"isom", [b"isom", b"iso2", b"avc1", b"mp41", b"mp42", b"dash", b"cmfc"]) + B.box("moov", B.box("mvhd", b"\x00" * 100)) \
            + B.box("mdat", b"\x00" * 16)
        r = self.cli(self.write("ordinary.mp4", data))
        self.assertEqual((r.code, r.doc["summary"]["files_scanned"]), (0, 1))

    def test_an_ordinary_mp4_mov_and_m4a_are_still_scanned(self):
        j = B.jdump(B.api_prompt({"9": B.api_node("Note", {"text": self.fake.hf()})}))
        for brand in (b"isom", b"mp42", b"qt  ", b"M4A ", b"3gp4"):
            data = ftyp(brand, [b"isom"]) + B.box("moov", B.box("mvhd", b"\x00" * 100) + B.box("udta", B.qt_text_atom(b"\xa9cmt", j))) \
                + B.box("mdat", b"\x00" * 16)
            p = self.write(brand.decode().strip() + ".mov", data)
            r = self.cli(p)
            self.assertEqual(r.code, 1, brand)
            self.assertGreaterEqual(len([f for f in r.doc["findings"] if f["class"] == "K1"]), 1, brand)

    def test_in_a_folder_a_heic_file_makes_the_run_exit_3_not_0(self):
        self.write("a/clean.png", B.make_png())
        self.write("a/photo.heic", heif_like(b"heic", [b"mif1"]))
        r = self.cli(os.path.join(self.dir, "a"))
        self.assertEqual(r.code, 3)
        self.assertEqual(r.doc["summary"]["files_scanned"], 1)
        self.assertEqual([e["code"] for e in r.doc["errors"]], ["unsupported_media"])

    def test_extensions_that_are_known_unsupported_are_errors_even_without_a_signature(self):
        for ext in ("heic", "heif", "avif", "jxl", "jp2"):
            self.write("b/x." + ext, b"not a recognised signature at all, just some bytes " * 3)
        r = self.cli(os.path.join(self.dir, "b"))
        self.assertEqual(r.code, 3)
        self.assertEqual(sorted(e["code"] for e in r.doc["errors"]), ["unsupported_media"] * 5)

    def test_the_printed_known_misses_no_longer_list_heic_as_merely_missed(self):
        joined = "\n".join(scan.KNOWN_MISSES)
        self.assertIn("HEIC, AVIF ... are reported as not scanned", joined)
        self.assertNotIn("HEIC/AVIF item data", joined)


if __name__ == "__main__":
    import unittest
    unittest.main()
