# -*- coding: utf-8 -*-
"""scripts/make_demo.py: the six synthetic demo files, DEMO_EXPECTED.md, and the rules the script keeps."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from _base import ScanCase, SCAN, MAKE_DEMO, have_ffmpeg, read_bytes, read_text, scan  # noqa: F401  (puts scripts/ on sys.path)
import make_demo as MD  # noqa: E402

NAMES = [d["name"] for d in MD.DEMO_FILES]
MP4 = "05_mp4_prompt_tag_and_free_box.mp4"
NEEDLES = [b"DEMOFAKE", b"demo_user_42", b"zzdemo", b"192.168.77.20", b"discord.com/api"]   # invented values in the demo files


def run_demo(outdir, *flags, env=None, cwd=None):
    e = dict(os.environ)
    if env is not None:
        e = env
    p = subprocess.run([sys.executable, "-I", "-B", MAKE_DEMO, outdir] + list(flags), stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=e, cwd=cwd, timeout=300)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def scan_cli(*args):
    p = subprocess.run([sys.executable, "-I", "-B", SCAN] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=300)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


class DemoCase(ScanCase):
    def make(self, name="demo", *flags, env=None):
        out = os.path.join(self.dir, name)
        code, so, se = run_demo(out, *flags, env=env, cwd=self.dir)
        return out, code, so, se

    def present(self, out):
        return [n for n in NAMES if os.path.exists(os.path.join(out, n))]


class TestDemoFiles(DemoCase):
    def test_writes_everything_it_can_and_reports_it(self):
        out, code, so, se = self.make()
        self.assertEqual(code, 0, so + se)
        want = NAMES if have_ffmpeg() else [n for n in NAMES if n != MP4]
        self.assertEqual(self.present(out), want)
        self.assertTrue(os.path.exists(os.path.join(out, "DEMO_EXPECTED.md")))
        self.assertIn("%d of %d demo files written" % (len(want), len(NAMES)), so)
        self.assertIn("none of them has been scanned yet", so)

    def test_each_file_reports_exactly_what_the_table_says(self):
        out, code, so, se = self.make()
        for d in MD.DEMO_FILES:
            path = os.path.join(out, d["name"])
            if not os.path.exists(path):
                continue
            report = os.path.join(self.dir, "r_%s.json" % d["name"])
            c, o, e = scan_cli(path, "--json", report)
            doc = json.loads(read_text(report))
            self.assertEqual(c, d["exit"], d["name"] + o)
            self.assertEqual(sorted(set(f["class"] for f in doc["findings"])), sorted(d["classes"]), d["name"])

    def test_folder_scan_is_exit_1_and_counts_the_expected_page_as_skipped(self):
        out, code, so, se = self.make()
        report = os.path.join(self.dir, "folder.json")
        c, o, e = scan_cli(out, "--json", report)
        doc = json.loads(read_text(report))
        n_render = len(self.present(out))
        self.assertEqual(c, 1)
        self.assertEqual(doc["summary"]["files_scanned"], n_render)
        self.assertEqual(doc["summary"]["skipped_unrecognized"], 1)       # DEMO_EXPECTED.md
        self.assertEqual(doc["summary"]["files_with_findings"], n_render - 1)
        self.assertEqual(doc["errors"], [])

    def test_the_clean_control_is_clean_and_says_a_workflow_is_embedded(self):
        out, code, so, se = self.make()
        report = os.path.join(self.dir, "clean.json")
        c, o, e = scan_cli(os.path.join(out, "04_clean.png"), "--json", report)
        doc = json.loads(read_text(report))
        self.assertEqual(c, 0)
        self.assertEqual(doc["findings"], [])
        self.assertEqual([i["code"] for i in doc["info"]], ["embedded_comfyui_api_json"])

    def test_scanner_output_never_contains_a_demo_value(self):
        out, code, so, se = self.make()
        report = os.path.join(self.dir, "all.json")
        c, o, e = scan_cli(out, "--json", report)
        blob = o.encode() + e.encode() + read_bytes(report)
        for needle in NEEDLES:
            self.assertNotIn(needle, blob, needle)
        # ... while the files really do contain the values (otherwise the line above proves nothing)
        raw = b"".join(read_bytes(os.path.join(out, n)) for n in self.present(out) if n.endswith((".png", ".mp4")))
        self.assertIn(b"DEMOFAKE", raw)
        self.assertIn(b"demo_user_42", raw)

    def test_compressed_chunk_hides_its_webhook_from_a_plain_text_search(self):
        out, code, so, se = self.make()
        raw = read_bytes(os.path.join(out, "02_png_ztxt_webhook.png"))
        self.assertNotIn(b"discord.com", raw)
        self.assertNotIn(b"webhooks", raw)

    def test_same_input_gives_the_same_bytes(self):
        a, _, _, _ = self.make("a")
        b, _, _, _ = self.make("b")
        for n in NAMES:
            if n == MP4:
                continue
            self.assertEqual(read_bytes(os.path.join(a, n)), read_bytes(os.path.join(b, n)), n)

    def test_bypassed_node_is_in_the_workflow_chunk_only(self):
        out, code, so, se = self.make()
        p = os.path.join(out, "03_png_bypassed_node_secret.png")
        c, o, e = scan_cli(p, "--json", os.path.join(self.dir, "b.json"))
        doc = json.loads(read_text(os.path.join(self.dir, "b.json")))
        locs = [f["location"] for f in doc["findings"] if "companion_of" not in f]
        self.assertTrue(locs and all(l.startswith("tEXt[workflow]") for l in locs), locs)
        self.assertTrue(all(f["bypassed"] and f["node_id"] == "12" for f in doc["findings"] if "companion_of" not in f))


class TestDemoExpectedPage(DemoCase):
    def test_every_written_file_has_a_row_with_its_classes_and_exit(self):
        out, code, so, se = self.make()
        page = read_text(os.path.join(out, "DEMO_EXPECTED.md"))
        for d in MD.DEMO_FILES:
            if not os.path.exists(os.path.join(out, d["name"])):
                self.assertNotIn("`%s`" % d["name"], page)
                continue
            row = [ln for ln in page.splitlines() if ln.startswith("| `%s`" % d["name"])]
            self.assertEqual(len(row), 1, d["name"])
            cells = [c.strip() for c in row[0].strip("|").split("|")]
            self.assertEqual(cells[2], ", ".join(d["classes"]) if d["classes"] else "none")
            self.assertEqual(cells[4], str(d["exit"]))

    def test_the_page_names_no_value(self):
        out, code, so, se = self.make()
        page = read_bytes(os.path.join(out, "DEMO_EXPECTED.md"))
        for needle in NEEDLES:
            self.assertNotIn(needle, page, needle)

    def test_missing_ffmpeg_skips_the_mp4_with_a_message_and_the_page_says_so(self):
        env = dict(os.environ)
        env["PATH"] = os.path.join(self.dir, "no-such-folder")
        out, code, so, se = self.make("nof", env=env)
        self.assertEqual(code, 0, so + se)
        self.assertNotIn(MP4, self.present(out))
        self.assertIn("SKIPPED", so)
        self.assertIn("ffmpeg is not on PATH", so)
        self.assertIn("5 of 6 demo files written", so)
        page = read_text(os.path.join(out, "DEMO_EXPECTED.md"))
        self.assertIn("Not written in this run", page)
        self.assertIn("4 of the files leak on purpose", page)

    def test_no_mp4_flag_skips_it_too(self):
        out, code, so, se = self.make("nm", "--no-mp4")
        self.assertEqual(code, 0, so + se)
        self.assertNotIn(MP4, self.present(out))
        self.assertIn("--no-mp4 was given", so)


class TestDemoSafety(DemoCase):
    def test_refuses_to_overwrite_and_leaves_files_alone(self):
        out, code, so, se = self.make()
        before = {n: read_bytes(os.path.join(out, n)) for n in self.present(out)}
        code2, so2, se2 = run_demo(out, cwd=self.dir)
        self.assertEqual(code2, 2)
        self.assertIn("refusing to overwrite", se2)
        self.assertEqual(before, {n: read_bytes(os.path.join(out, n)) for n in self.present(out)})

    def test_overwrite_flag_replaces_the_demo_files(self):
        out, code, so, se = self.make()
        victim = os.path.join(out, "04_clean.png")
        with open(victim, "wb") as fh:
            fh.write(b"changed")
        code2, so2, se2 = run_demo(out, "--overwrite", cwd=self.dir)
        self.assertEqual(code2, 0, so2 + se2)
        self.assertNotEqual(read_bytes(victim), b"changed")

    def test_other_files_in_the_folder_are_left_alone(self):
        out = os.path.join(self.dir, "mine")
        os.makedirs(out)
        keep = os.path.join(out, "my_own_file.txt")
        with open(keep, "wb") as fh:
            fh.write(b"mine")
        code, so, se = run_demo(out, "--no-mp4", cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertEqual(read_bytes(keep), b"mine")

    def test_outdir_that_is_a_file_is_refused(self):
        f = self.write("afile", b"x")
        code, so, se = run_demo(f, cwd=self.dir)
        self.assertEqual(code, 2)
        self.assertEqual(read_bytes(f), b"x")

    def test_writes_nothing_outside_its_folder_and_leaves_no_temp_file(self):
        parent = os.path.join(self.dir, "parent")
        os.makedirs(parent)
        with open(os.path.join(parent, "sentinel.txt"), "wb") as fh:
            fh.write(b"s")
        cwd = os.path.join(self.dir, "cwd")
        os.makedirs(cwd)
        out = os.path.join(parent, "demo")
        code, so, se = run_demo(out, cwd=cwd)
        self.assertEqual(code, 0, so + se)
        self.assertEqual(sorted(os.listdir(parent)), ["demo", "sentinel.txt"])
        self.assertEqual(os.listdir(cwd), [])
        want = set(self.present(out)) | {"DEMO_EXPECTED.md"}
        self.assertEqual(set(os.listdir(out)), want)        # no *.part, no stray file

    def test_leftover_part_file_is_reported_not_deleted(self):
        if not have_ffmpeg():
            self.skipTest("ffmpeg not on PATH: the .part file only exists on the MP4 path")
        out = os.path.join(self.dir, "p")
        os.makedirs(out)
        part = os.path.join(out, MP4 + ".part")
        with open(part, "wb") as fh:
            fh.write(b"old")
        code, so, se = run_demo(out, cwd=self.dir)
        self.assertEqual(code, 0)
        self.assertIn("remove it and try again", so)
        self.assertEqual(read_bytes(part), b"old")

    def test_runs_from_any_folder_with_a_path_that_has_spaces(self):
        out = os.path.join(self.dir, "my renders", "demo out")
        code, so, se = run_demo(out, "--no-mp4", cwd=tempfile.gettempdir())
        self.assertEqual(code, 0, so + se)
        self.assertIn('"%s"' % out, so)                      # the "Next:" line quotes the path
        self.assertTrue(os.path.isdir(out))


@unittest.skipUnless(have_ffmpeg(), "ffmpeg/ffprobe not on PATH")
class TestDemoFilesAreRealMedia(DemoCase):
    def decode(self, path):
        p = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "null", "-"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=120)
        return p.returncode, p.stderr.decode("utf-8", "replace")

    def test_pngs_and_jpeg_decode_without_a_complaint(self):
        out, code, so, se = self.make()
        for n in NAMES:
            if n.endswith((".png", ".jpg")):
                rc, err = self.decode(os.path.join(out, n))
                self.assertEqual((rc, err), (0, ""), n)

    def test_mp4_opens_in_ffprobe_and_ffprobe_does_not_show_the_hidden_box(self):
        out, code, so, se = self.make()
        p = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams",
                            os.path.join(out, MP4)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(b"DEMOFAKE", p.stdout)
        self.assertNotIn(b"hidden", p.stdout)
        doc = json.loads(p.stdout)
        self.assertEqual(doc["streams"][0]["codec_type"], "video")
        raw = read_bytes(os.path.join(out, MP4))
        self.assertIn(b"hidden: ", raw)                      # the box is really in the file


if __name__ == "__main__":
    unittest.main()
