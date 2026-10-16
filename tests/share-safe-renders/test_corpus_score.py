# -*- coding: utf-8 -*-
"""The package scanner against the synthetic corpus (tests/share-safe-renders/corpus) with the scorer
(tests/share-safe-renders/eval/score.py). Everything is generated at run time into a temp folder.

Default: the corpus without the heavy resource probes (about 15 MB, under a minute).
SSR_FULL_CORPUS=1 builds the full corpus (about 60 MB, includes the 1 GiB decompression bombs) and scores that.
SSR_SKIP_SLOW=1 skips this test file's work.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from _base import HERE, SCAN

CORPUS = os.path.join(HERE, "corpus", "make_corpus.py")
SCORE = os.path.join(HERE, "eval", "score.py")
FULL = os.environ.get("SSR_FULL_CORPUS") == "1"


@unittest.skipIf(os.environ.get("SSR_SKIP_SLOW") == "1", "SSR_SKIP_SLOW=1")
@unittest.skipUnless(os.path.exists(CORPUS) and os.path.exists(SCORE), "the corpus builder and scorer are not in this checkout")
class TestCorpusScore(unittest.TestCase):
    def test_the_package_scanner_matches_the_answer_key(self):
        with tempfile.TemporaryDirectory(prefix="ssrtest_corpus_") as td:
            corpus = os.path.join(td, "corpus")
            flags = [] if FULL else ["--no-heavy", "--many", "50"]
            b = subprocess.run([sys.executable, "-I", "-B", CORPUS, corpus] + flags, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=900)
            built = b.stdout.decode("utf-8", "replace")
            self.assertEqual(b.returncode, 0, built[-1500:])
            self.assertIn("selfcheck: OK", built)
            s = subprocess.run([sys.executable, "-I", "-B", SCORE, "--corpus", corpus, "--scanner", SCAN, "--out",
                                os.path.join(td, "out"), "--phases", "file,dirs,cli", "--quiet"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=1800)
            out = s.stdout.decode("utf-8", "replace")
            self.assertIn("MISSES (strict): 0", out)
            self.assertIn("MISSES (lenient): 0", out)
            m = re.search(r"CLEAN CONTROLS: (\d+) files, (\d+) with findings", out)
            self.assertTrue(m, out[-1500:])
            self.assertGreaterEqual(int(m.group(1)), 40)
            self.assertEqual(m.group(2), "0", "a clean control produced a finding")
            self.assertIn("clean-file records 0", out)
            bad = [ln for ln in out.splitlines() if re.search(r"\s(FAIL|CRASH|TIMEOUT)\b", ln)]
            self.assertEqual(bad, [])
            planted = re.search(r"^ALL\s+(\d+)\s+(\d+)\s+100\.0%", out, re.M)
            self.assertTrue(planted, "every required planted entry must be found")
            self.assertEqual(planted.group(1), planted.group(2))


# The two M1 fixtures that hide their text behind about 3 MB of media share one noise clip.  About one 3 MB draw in ten
# holds an e-mail-shaped run (local part, at sign, dotted domain), which the builder's self-check then reports as an
# unplanted P2 value in both files ("selfcheck: 2 PROBLEM(S)").  Reproduced with the old lavfi noise source on ubuntu:24.04
# (ffmpeg 6.1.1) at 32 and at 15 CPUs, and on debian:12 (ffmpeg 5.1.9) pinned to 15 CPUs.  These tests pin the two
# properties that make the build independent of the machine: a matching draw is thrown away, and the clips do not
# depend on the CPU count.  All of the builder's MP4/MOV files are made from three base clips (the 3 MB noise clip and
# the small mp4 and mov clips) by stream copy, and libx264 at its default thread count writes the thread count of the
# machine into the bytes of a clip, so each base clip is encoded with -threads 1 and is checked here.
_CLIP_CODE = (
    "import hashlib, importlib.util, os, sys\n"
    "from pathlib import Path\n"
    "if sys.argv[3] == 'one_cpu':\n"
    "    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})\n"
    "spec = importlib.util.spec_from_file_location('ssr_make_corpus_child', sys.argv[1])\n"
    "mc = importlib.util.module_from_spec(spec)\n"
    "sys.modules[spec.name] = mc\n"
    "spec.loader.exec_module(mc)\n"
    "c = mc.Corpus(Path(sys.argv[2]), 42, {})\n"
    "for container, big in (('mp4', True), ('mp4', False), ('mov', False)):\n"
    "    base = c._base_video(container, big)\n"
    "    print('clip', container, 'big' if big else 'small',\n"
    "          hashlib.sha256(Path(base).read_bytes()).hexdigest() if base else 'none')\n"
)


def _digest(text):
    """A short stand-in for a text of about 3 MB, so that a failing assertion does not print the text."""
    return "%d chars, sha256 %s" % (len(text), hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest())


def _load_builder():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ssr_make_corpus_under_test", CORPUS)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@unittest.skipIf(os.environ.get("SSR_SKIP_SLOW") == "1", "SSR_SKIP_SLOW=1")
@unittest.skipUnless(os.path.exists(CORPUS), "the corpus builder is not in this checkout")
@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg is not on PATH")
class TestBigMp4Filler(unittest.TestCase):
    def setUp(self):
        self.mc = _load_builder()
        self.addCleanup(sys.modules.pop, self.mc.__name__, None)

    def test_the_guard_flags_the_accident_seen_on_ubuntu_2404(self):
        # a 7-character run (digit, at sign, two letters + digit, dot, two letters) sat 1.7 MB into the old clip
        # (ffmpeg 6.1.1, 15 or more CPUs).  Built from parts: the hygiene test bans e-mail-shaped literals.
        accident = "9" + "@" + "X4" + "." + "hn"
        self.assertEqual([c for c, _ in self.mc.guard_hits("ab " + accident + " cd")], ["P2"])

    def test_a_draw_that_matches_a_contract_pattern_is_thrown_away(self):
        mc = self.mc
        real = mc.guard_hits
        seen = []

        def fake(text):
            seen.append(text)
            return [("P2", "fx" + "@" + "host.example")] if len(seen) == 1 else real(text)

        with tempfile.TemporaryDirectory(prefix="ssrtest_big_") as td:
            c = mc.Corpus(td, 42, {})
            c.work.mkdir(parents=True)
            out = c.work / "big.mp4"
            mc.guard_hits = fake
            try:
                self.assertTrue(c._big_base("mp4", out))
            finally:
                mc.guard_hits = real
            self.assertGreaterEqual(len(seen), 2, "the first draw matched; a second one must be made")
            self.assertTrue(seen[0] != seen[1], "the second draw must be different noise")
            self.assertEqual(real(seen[-1]), [], "the clip that is kept must not match any contract pattern")
            self.assertEqual(_digest(seen[-1]), _digest("\n".join(mc.texts_of(out.read_bytes()))),
                             "the guard must read the whole encoded clip that is kept")
            self.assertGreater(out.stat().st_size, 2500000, "the clip must still put the moov box megabytes in")

    def test_the_base_clips_do_not_depend_on_the_cpu_count(self):
        if not (hasattr(os, "sched_setaffinity") and len(os.sched_getaffinity(0)) >= 2):
            self.skipTest("needs Linux with at least two CPUs to pin one")
        clips = []
        for mode in ("all_cpus", "one_cpu"):
            with tempfile.TemporaryDirectory(prefix="ssrtest_big_") as td:
                r = subprocess.run([sys.executable, "-I", "-B", "-c", _CLIP_CODE, CORPUS, td, mode],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
                out = r.stdout.decode("utf-8", "replace")
                self.assertEqual(r.returncode, 0, out[-1500:])
                clips.append([ln for ln in out.splitlines() if ln.startswith("clip ")])
        self.assertEqual(len(clips[0]), 3, clips[0])
        if any(ln.endswith(" none") for ln in clips[0] + clips[1]):
            self.skipTest("ffmpeg could not create a base clip")
        self.assertEqual(clips[0], clips[1], "a base clip changed with the number of CPUs")


if __name__ == "__main__":
    unittest.main()
