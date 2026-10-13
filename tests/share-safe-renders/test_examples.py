# -*- coding: utf-8 -*-
"""examples/: real runs, reproducible, and consistent with SKILL.md.

* structure tests read the committed files (always run),
* the reproducibility test regenerates all three files from real runs of the scripts in a temp folder and compares them with
  the committed ones, ignoring the fields that legitimately differ between machines: path separators, the Python version,
  whether ffprobe is on PATH, and the MP4 box path of the prompt tag (it depends on how the installed ffmpeg writes tags).
  The hash prefixes (`sha256=...`, `sha256_prefix`, and the `~xxxxxxxx` labels) are keyed with a random key made for each run (S4), so
  they differ on every run: each distinct prefix is renamed H1, H2 ... in the order it first appears, which keeps the structure
  (which findings share a value) and ignores the digits.
"""
import json
import os
import re
import tempfile
import unittest

from _base import PKG, LISTING, scan, read_text, have_ffmpeg
import make_demo as MD
import make_examples as ME

EXAMPLES = os.path.join(PKG, "examples")
SKILL = read_text(os.path.join(PKG, "SKILL.md"))
REPORT_JSON = json.loads(read_text(os.path.join(EXAMPLES, "sample_report.json")))
REPORT_MD = read_text(os.path.join(EXAMPLES, "sample_report.md"))
SESSION = read_text(os.path.join(EXAMPLES, "example_session.md"))


_HASH = re.compile(r'(sha256=|~|"sha256_prefix": ")([0-9a-f]{8})(?![0-9a-f])')


def canon_hashes(text):
    """Rename every distinct 8-hex hash prefix H1, H2 ... in order of first appearance."""
    seen = {}

    def sub(m):
        return m.group(1) + "H%d" % seen.setdefault(m.group(2), len(seen) + 1)
    return _HASH.sub(sub, text)


def norm_text(t):
    t = t.replace("\r\n", "\n").replace("\\", "/")
    t = re.sub(r"Python \d+\.\d+\.\d+", "Python X", t)
    t = re.sub(r"ffprobe: (used|absent|disabled|not needed)", "ffprobe: S", t)
    t = re.sub(r"moov/[A-Za-z0-9_/()~.]*?prompt", "MP4PROMPTPATH", t)
    return canon_hashes(t)


def norm_json(text):
    doc = json.loads(text)
    doc["summary"]["ffprobe"] = "S"
    for key in ("findings", "errors", "info"):
        for item in doc[key]:
            item["file"] = item["file"].replace("\\", "/")
            if "location" in item:
                item["location"] = re.sub(r"moov/[A-Za-z0-9_/()~.]*?prompt", "MP4PROMPTPATH", item["location"])
    return canon_hashes(json.dumps(doc, indent=1, sort_keys=True))


class TestSampleReport(unittest.TestCase):
    def test_json_is_a_real_scan_of_the_demo_files(self):
        d = REPORT_JSON
        self.assertEqual(d["tool"], "share-safe-renders/scan.py")
        self.assertEqual(d["version"], scan.VERSION)
        self.assertEqual(d["exit_code"], 1)
        self.assertEqual(d["summary"]["files_scanned"], 6)
        self.assertEqual(d["summary"]["skipped_unrecognized"], 1)
        self.assertEqual(d["errors"], [])
        by_file = {}
        for f in d["findings"]:
            by_file.setdefault(os.path.basename(f["file"].replace("\\", "/")), set()).add(f["class"])
        for item in MD.DEMO_FILES:
            self.assertEqual(by_file.get(item["name"], set()), set(item["classes"]), item["name"])

    def test_no_machine_specific_path_or_demo_value_in_any_example(self):
        for name, text in (("json", read_text(os.path.join(EXAMPLES, "sample_report.json"))), ("md", REPORT_MD), ("session", SESSION)):
            bs = chr(92)
            body = text.replace("C:" + bs + "Users" + bs + "<name>" + bs, "")        # the class table names the pattern, not a path
            self.assertIsNone(re.search("[A-Za-z]:[" + bs + bs + "/]", body), name + ": a drive letter path")
            for needle in ("Users", "AppData", "Temp", "DEMOFAKE", "demo_user_42", "zzdemo", "192.168.77.20", "discord.com/api"):
                self.assertNotIn(needle, body.replace("<name>", ""), "%s: %s" % (name, needle))

    def test_markdown_holds_the_three_runs_with_their_exit_codes(self):
        self.assertIn("### 1. The demo folder (exit 1)", REPORT_MD)
        self.assertIn("### 2. The one PNG with only an ordinary prompt, scanned alone (exit 0)", REPORT_MD)
        self.assertIn("### 3. The re-scan loop: export a copy without the metadata, scan the copy (exit 0)", REPORT_MD)
        # the verdict line is printed twice in every report: under the summary line and last
        self.assertEqual(REPORT_MD.count("RESULT: FINDINGS - do not share these files as they are (exit 1)"), 2)
        self.assertEqual(REPORT_MD.count("RESULT: NOTHING FOUND in what was scanned"), 4)


class TestSessionFollowsSkillMd(unittest.TestCase):
    ACTS = None

    @classmethod
    def setUpClass(cls):
        cls.ACTS = [a for a in SESSION.split("\n---\n") if "**User:**" in a]

    def assistant_prose(self, act):
        """The assistant's own words: everything outside fenced blocks."""
        return re.sub(r"```.*?```", "", act, flags=re.S)

    def test_three_requests_and_the_claim_about_what_is_real(self):
        self.assertEqual(len(self.ACTS), 3)
        self.assertIn("not a recording of a model", SESSION)
        self.assertIn("real runs of the scripts", SESSION)

    def test_every_final_report_has_the_four_parts_in_the_order_skill_md_requires(self):
        for act in self.ACTS:
            order = [act.find(h) for h in ("**Verdict.**", "**Findings", "**How to fix", "**What this scan cannot see**")]
            self.assertTrue(all(i >= 0 for i in order), order)
            self.assertEqual(order, sorted(order), order)

    def test_verdicts_are_the_ones_skill_md_prescribes(self):
        v = [re.search(r"\*\*Verdict\.\*\* (.+)", a).group(1) for a in self.ACTS]
        self.assertRegex(v[0], r"^Do not share these files as they are: \d+ finding\(s\) in \d+ of \d+ file\(s\) \(\d+ high, \d+ medium, \d+ low\)\.$")
        self.assertRegex(v[1], r"^Nothing found in \d+ file\(s\) scanned\. That is not a guarantee\.$")
        self.assertEqual(v[2], "Could not scan everything, and found nothing in what could be read. Treat these files as NOT checked.")
        table = {r[0]: r[2] for r in ME_rows()}
        self.assertIn("Do not share these files as they are", table["1"])
        self.assertIn("Nothing found in N file(s) scanned. That is not a guarantee.", table["0"])
        self.assertIn("Treat these files as NOT checked.", table["3"])

    def test_the_numbers_in_the_verdict_are_the_numbers_in_the_scan_it_follows(self):
        act = self.ACTS[0]
        summary = re.search(r"Scanned (\d+) file\(s\): (\d+) with findings, (\d+) finding\(s\)", act)
        n, f, k = summary.groups()
        self.assertIn("%s finding(s) in %s of %s file(s)" % (k, f, n), act)
        h, m, l = (len(re.findall(r"^  \[%s\]" % s, act, re.M)) for s in ("HIGH", "MEDIUM", "LOW"))
        self.assertIn("(%d high, %d medium, %d low)" % (h, m, l), act)
        self.assertEqual(h + m + l, int(k))

    def test_exit_codes_are_reported_and_match_the_result_lines(self):
        want = [("1", "(exit 1)"), ("0", "(exit 0)"), ("3", "(exit 3)")]
        for act, (code, tail) in zip(self.ACTS, want):
            self.assertIn("Exit code: **%s**" % code, act)
            self.assertIn(tail, act)

    def test_commands_are_the_skill_md_commands(self):
        self.assertIn('python "<SKILL_DIR>/scripts/scan.py" "renders" --json "share-safe-report.json"', SESSION)
        self.assertIn('python "<SKILL_DIR>/scripts/scan.py" "reexported" --json "share-safe-report-2.json"', SESSION)
        self.assertIn('python "<SKILL_DIR>/scripts/scan.py" "extras" --strict --json "share-safe-report-3.json"', SESSION)
        for line in re.findall(r"^ffmpeg .+$", SESSION, re.M):
            self.assertRegex(line, r'^ffmpeg -loglevel error -n -i "[^"]+" -map_metadata -1 .*"[^"]+"$')
        self.assertIn("mkdir reexported", SESSION)

    def test_the_assistant_never_calls_anything_clean_or_safe_and_prints_no_value(self):
        for act in self.ACTS:
            prose = self.assistant_prose(act)
            prose = prose.replace("04_clean.png", "<a file name>").replace("NOT clean", "<a negation>")
            self.assertIsNone(re.search(r"(?<![-\w])(clean|safe|secure)(?![-\w])", prose, re.I), act[:80])
            # and no go-ahead to share: whether to share is the user's decision
            self.assertNotRegex(prose, r"(?i)\bshare the copies\b|nothing is left to fix|it is (fine|ok|okay) to share|you can share")
        for needle in ("DEMOFAKE", "demo_user_42", "zzdemo"):
            self.assertNotIn(needle, SESSION)

    def test_the_copies_are_counted_before_the_assistant_says_they_were_checked(self):
        act = self.ACTS[1]
        made = len(re.findall(r"^ffmpeg ", act, re.M))
        scanned = int(re.search(r"Scanned (\d+) file\(s\)", act).group(1))
        self.assertEqual(made, scanned)
        self.assertIn("%d copies were made and %d were scanned" % (made, scanned), act)
        self.assertIn("new report name", act)

    def test_the_workflow_note_and_the_skipped_files_are_reported_when_the_scan_lists_them(self):
        for act in (self.ACTS[0], self.ACTS[2]):
            self.assertIn("carry an embedded ComfyUI workflow", act)
        self.assertIn("`renders/DEMO_EXPECTED.md`", self.ACTS[0])
        self.assertIn("`extras/notes.txt`", self.ACTS[2])
        self.assertNotIn("(all paths)` (`strict", self.ACTS[2])

    def test_exports_are_run_only_after_the_user_asks_and_write_to_new_names(self):
        a1, a2 = self.ACTS[0], self.ACTS[1]
        self.assertNotIn("\nffmpeg ", re.sub(r"\*\*How to fix\*\*.*", "", a1, flags=re.S).replace("**Assistant:**", ""))
        self.assertIn("**User:** Please run those exports", a2)
        self.assertIn("writing only to new names in `reexported/`", a2)

    def test_the_exit_3_act_lists_every_unscanned_file_with_its_code(self):
        act = self.ACTS[2]
        for code in ("unsupported_media", "png_truncated", "strict_skipped_entries"):
            self.assertIn("(`%s`)" % code, act)
            self.assertIn("ERROR %s" % code, act)
        self.assertIn("Do not describe `extras/` as checked until that run exits 0.", act)

    def test_the_cannot_see_block_is_skill_mds_five_lines(self):
        m = re.search(r"Always these five lines: (.+?)\.\n", SKILL)
        items = [s.strip() for s in m.group(1).split(";")]
        for act in self.ACTS:
            block = act.split("**What this scan cannot see**")[1]
            lines = [ln[2:] for ln in block.splitlines() if ln.startswith("- ")]
            self.assertEqual([l[0].lower() + l[1:] for l in lines], items)


def ME_rows():
    from test_skill_docs import table_rows
    return table_rows(SKILL, "| Exit | Meaning |")


class TestTheComparisonCanFail(unittest.TestCase):
    def test_a_changed_example_is_not_equal_after_normalising(self):
        self.assertNotEqual(norm_text(REPORT_MD), norm_text(REPORT_MD.replace("12 finding(s)", "13 finding(s)")))
        self.assertNotEqual(norm_text(SESSION), norm_text(SESSION.replace("(exit 3)", "(exit 0)")))
        doc = json.loads(json.dumps(REPORT_JSON))
        doc["findings"][0]["length"] += 1
        self.assertNotEqual(norm_json(json.dumps(REPORT_JSON)), norm_json(json.dumps(doc)))

    def test_hash_prefixes_are_ignored_but_which_findings_share_one_is_not(self):
        a = "x sha256=aaaaaaaa y sha256=bbbbbbbb z sha256=aaaaaaaa loc=~0123abcd"
        b = "x sha256=11111111 y sha256=22222222 z sha256=11111111 loc=~99999999"
        self.assertEqual(norm_text(a), norm_text(b))
        self.assertNotEqual(norm_text(a), norm_text("x sha256=11111111 y sha256=11111111 z sha256=11111111 loc=~99999999"))
        self.assertNotEqual(norm_text(a), norm_text("x sha256=11111111 y sha256=22222222 z sha256=33333333 loc=~99999999"))

    def test_the_things_that_may_differ_between_machines_are_ignored(self):
        t = "Python 3.9.1\ndemo\\a.png ffprobe: absent moov/meta/ilst/prompt:node:1"
        u = "Python 3.14.6\ndemo/a.png ffprobe: used moov/udta/meta/ilst/prompt:node:1"
        self.assertEqual(norm_text(t), norm_text(u))


class TestReproducible(unittest.TestCase):
    def test_regenerating_from_real_runs_gives_the_committed_files(self):
        if not have_ffmpeg():
            self.skipTest("ffmpeg/ffprobe not on PATH: the demo MP4 and the exports cannot be rebuilt")
        with tempfile.TemporaryDirectory(prefix="ssr_regen_") as td:
            fresh = ME.build(td)
        self.assertEqual(sorted(fresh), ["example_session.md", "listing/demo_request.md", "listing/demo_result.md",
                                         "sample_report.json", "sample_report.md"])
        self.assertEqual(norm_json(fresh["sample_report.json"]), norm_json(read_text(os.path.join(EXAMPLES, "sample_report.json"))))
        for name in ("sample_report.md", "example_session.md", "listing/demo_request.md", "listing/demo_result.md"):
            where = os.path.join(LISTING, name.split("/", 1)[1]) if name.startswith("listing/") else os.path.join(EXAMPLES, name)
            if not os.path.exists(where):
                continue                          # the listing folder lives outside packages/ and tests/; absent here
            a, b = norm_text(fresh[name]), norm_text(read_text(where))
            self.assertEqual(a, b, name + " differs from a fresh run; regenerate with tests/share-safe-renders/make_examples.py")


if __name__ == "__main__":
    unittest.main()
