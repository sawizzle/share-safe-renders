# -*- coding: utf-8 -*-
"""listing/share-safe-renders: the Agensi form text is complete, honest, consistent with the package and with this suite."""
import os
import re
import unittest

from _base import HERE, PKG, LISTING, scan, read_text

NEEDED = ("listing_fields.md", "demo_result.md", "demo_request.md")
HAVE_LISTING = all(os.path.exists(os.path.join(LISTING, n)) for n in NEEDED)
SKIP_REASON = "listing/share-safe-renders is not in this checkout (the listing text lives outside packages/ and tests/)"


def _read(name):
    return read_text(os.path.join(LISTING, name)) if HAVE_LISTING else ""


FIELDS, RESULT, REQUEST = _read("listing_fields.md"), _read("demo_result.md"), _read("demo_request.md")
README = read_text(os.path.join(PKG, "README.md"))
KNOWN = read_text(os.path.join(PKG, "references", "known-misses.md"))


def section(name):
    m = re.search(r"^## %s.*?\n(.*?)(?=^## |\Z)" % re.escape(name), FIELDS, re.S | re.M)
    assert m, name
    return m.group(1).strip()


def total_tests():
    return unittest.TestLoader().discover(HERE).countTestCases()


@unittest.skipUnless(HAVE_LISTING, SKIP_REASON)
class TestFields(unittest.TestCase):
    def test_every_form_field_is_there_in_order(self):
        heads = re.findall(r"^## (.+)$", FIELDS, re.M)
        want = ["Name (max 60)", "Summary (one line)", "Pricing", "Categories (up to 3, first = primary)", "Tags", "Use cases",
                "Description (markdown, for the long description field)", "See it in action", "Compatibility note", "Permissions",
                "Known limitations", "FAQ", "Precheck gate notes (local copy of the Agensi checks: tools/agensi_precheck_v3.py on the package folder and on the zip)",
                "Changelog", "Release checklist (do these before pressing Submit; each one makes a sentence in the package or this listing true)"]
        self.assertEqual(heads, want)

    def test_name_summary_pricing_categories_tags(self):
        self.assertLessEqual(len(section("Name")), 60)
        self.assertEqual(section("Name"), "Share-Safe Renders")
        summary = section("Summary")
        self.assertEqual(len(summary.splitlines()), 1)
        self.assertLessEqual(len(summary), 200)
        self.assertEqual(section("Pricing"), "Free")
        cats = re.findall(r"^\d\. (.+)$", section("Categories"), re.M)
        self.assertEqual(cats, ["Image & Video", "Testing & Debugging", "Workflow Automation"])
        tags = [t.strip() for t in section("Tags").split(",")]
        self.assertLessEqual(len(tags), 12)
        for t in tags:
            self.assertRegex(t, r"^[a-z0-9-]+$")
        self.assertGreaterEqual(len(re.findall(r"^- ", section("Use cases"), re.M)), 4)

    def test_the_test_count_is_the_real_count(self):
        n = total_tests()
        found = [int(x) for x in re.findall(r"\b(\d{3,4})(?:[- ]tests?\b| automated tests)", FIELDS)]
        self.assertGreaterEqual(len(found), 3)
        self.assertEqual(set(found), {n}, "the listing quotes %s tests; the suite has %d" % (sorted(set(found)), n))

    def test_the_tested_versions_are_the_ones_the_readme_gives(self):
        for text in (FIELDS, README):
            for v in ("Windows 11", "3.14.6", "3.9.25", "8.1.1", "5.1", "7.1", "9.0.1",
                      "Ubuntu 22.04", "Debian 12", "Ubuntu 24.04", "Ubuntu 26.04", "4.4.2", "5.1.9", "6.1.1", "8.0.1",
                      "3.10.12", "3.11.2", "3.12.3", "3.14.4", "normal user"):
                self.assertIn(v, text)
        for v in ("macOS", "Linux"):
            self.assertIn(v, section("Compatibility note"))
        self.assertIn("Not tested", section("Compatibility note"))

    def test_the_vendor_count_is_right(self):
        vendors = {r[0] for r in scan._K1_RULES}
        self.assertEqual(len(vendors), 8)
        self.assertIn("eight vendors", FIELDS)
        self.assertIn("eight vendors", README)
        self.assertNotRegex(FIELDS + README, r"\bnine\b")
        for name in ("OpenAI", "Anthropic", "GitHub", "AWS", "Google", "Slack", "Stripe", "Hugging Face"):
            self.assertIn(name, KNOWN)

    def test_description_has_the_honest_parts(self):
        d = section("Description (markdown, for the long description field)")
        for needle in ("scan-first", "never edits", "never prints", "is not reported as clean", "not a guarantee", "known misses",
                       "does not replace exiftool or trufflehog", "194 of 194", "built against that corpus", "not an estimate of real-world recall",
                       "27 of 68", "none of the real PNG, JPEG or MP4 files", "far more vendor detectors", "can check whether a key is live",
                       "Not tested", "Source and licence"):
            self.assertIn(needle, d, needle)
        self.assertIn("https://github.com/sawizzle/share-safe-renders", d)

    def test_the_comparison_is_like_for_like_and_the_exit_3_claim_is_qualified(self):
        d = section("Description (markdown, for the long description field)")
        flat = " ".join(d.split())
        for needle in ("(the scanner: 68 of 68)", "91 of those 194 are classes trufflehog has no detector for", "189 of the 194 entries in clear text",
                       "exits 3 when nothing else was found (1 if another file has a finding)", "named under NOTES",
                       "No verdict line the skill gives the agent says \"clean\" or \"safe\"", "never to say a file is fine to share",
                       "check the copy by scanning it again", "the check is not circular"):
            self.assertIn(needle, flat, needle)
        self.assertNotIn("the skill never tells an agent", flat)
        self.assertNotRegex(FIELDS, r"(?i)\bproof\b|\bprove\b")
        self.assertNotIn("2 of 240", FIELDS)
        self.assertNotIn("showed all 194 entries", FIELDS)
        lim = " ".join(section("Known limitations").split())
        for needle in ("exit 3 when nothing else was found", "Teams, Zapier, n8n, Make, Telegram", "example.org, example.net and example.edu",
                       "other .org, .net and .edu addresses are reported", "keeps a PNG's EXIF", "one-frame file",
                       "one video and one audio stream", "unless you add --strict"):
            self.assertIn(needle, lim, needle)
        scopes = [ln for ln in section("Permissions").splitlines() if ln.startswith("File scopes:")][0]
        self.assertIn("reads its first bytes to tell what it is, whatever the extension", scopes)
        self.assertNotIn("*.png", scopes)

    def test_permissions_and_limitations_match_what_the_scripts_do(self):
        p = section("Permissions")
        for needle in ("Terminal / Shell", "Read Files", "Write Files", "NOT used: Browser, Network Access, Environment Variables",
                       "never deletes a file", "opens no network connection", "reads no environment variable", "ffprobe", "ffmpeg",
                       "argument list", "refuses to replace", "--no-mp4", "--overwrite"):
            self.assertIn(needle, p, needle)
        self.assertNotIn("relaxed by make_demo.py", p)           # an internal gate note, not form text
        lim = section("Known limitations")
        for needle in ("pixels", "C2PA", "WebP", "split", "placeholder", "cookie", "IPv6", "prompt text", "in-sample", "Linux x86-64", "not on macOS",
                       "-c copy", "-n option"):
            self.assertIn(needle, lim, needle)

    def test_every_gate_warn_is_explained(self):
        g = section("Precheck gate notes (local copy of the Agensi checks: tools/agensi_precheck_v3.py on the package folder and on the zip)")
        self.assertIn("0 FAIL, 2 WARN", g)
        self.assertRegex(g, r"process spawn, scripts/scan\.py: the optional ffprobe")
        self.assertRegex(g, r"process spawn, scripts/make_demo\.py: the ffmpeg call")
        self.assertIn("URL literals", g)
        self.assertIn("relaxed by make_demo.py for ffmpeg", g)
        self.assertIn("deny-list scan", g)

    def test_the_checklist_makes_the_package_sentences_true(self):
        c = section("Release checklist (do these before pressing Submit; each one makes a sentence in the package or this listing true)")
        items = re.findall(r"^\d\. (.+)$", c, re.M)
        self.assertEqual(len(items), 7)
        self.assertIn("https://github.com/sawizzle/share-safe-renders", items[0])
        self.assertIn("published with the release", items[0])
        self.assertIn("published with the release", README)
        self.assertIn("licence", items[1].lower())
        self.assertIn("MIT OR Apache-2.0", README)
        self.assertIn("trigger test", items[2].lower())
        self.assertIn("Sonnet 5 of 5 and 5 of 5", items[2])
        self.assertIn("Haiku 3 of 5 and 5 of 5", items[2])
        note = " ".join(section("Compatibility note").split())
        self.assertIn("Sonnet 10 of 10 right; Haiku 8 of 10", note)
        self.assertIn("use the share-safe-renders skill", note)
        self.assertIn("deny-list", items[3])
        self.assertIn("zip", items[4])
        self.assertIn("knowledge base", items[5])
        self.assertIn("clear yes", items[6])

    def test_changelog_matches_the_package(self):
        ch = section("Changelog")
        self.assertIn("scan.py 1.2.0", ch)
        self.assertEqual(scan.VERSION, "1.2.0")
        for needle in ("194 of 194", "46 clean controls", "adversarial review", "tempfile.mkstemp", "keyed with a random per-run key",
                       "an empty folder exits 3", "23 Pillow releases", "empty exif, comment and xmp values"):
            self.assertIn(needle, ch, needle)
        self.assertEqual(len(re.findall(r"^- ", ch, re.M)), 1, "a first release has one changelog entry")
        self.assertLess(len(ch), 2600, "the changelog is for buyers: no internal process narration")

    def test_the_listing_agrees_with_the_skill_description(self):
        desc = re.search(r"^description: (.*)$", read_text(os.path.join(PKG, "SKILL.md")), re.M).group(1)
        self.assertLessEqual(len(desc), 300)
        for needle in ("Discord/Slack webhooks", "scanning source code"):
            self.assertIn(needle, desc, needle)
        # the form's summary names the same two webhook services the scanner knows, and the longer text says what it cannot do
        self.assertIn("Discord and Slack webhooks", section("Summary"))
        self.assertNotIn("Fixed after the first Linux run", FIELDS)

    def test_faq_covers_the_questions_a_buyer_asks(self):
        faq = section("FAQ")
        qs = re.findall(r"^Q: (.+)$", faq, re.M)
        self.assertGreaterEqual(len(qs), 7)
        self.assertEqual(len(qs), len(re.findall(r"^A: ", faq, re.M)))

    def test_no_overclaim_and_no_private_name_in_the_listing_text(self):
        for name, text in (("fields", FIELDS), ("result", RESULT), ("request", REQUEST)):
            for m in re.finditer(r"guarantee", text, re.I):
                before = text[max(0, m.start() - 16): m.start()].lower()
                self.assertTrue("not a " in before or "no " in before or "not " in before, name)
            for pat in (r"100%", r"bullet-?proof", r"foolproof", r"\bTODO\b", r"\bTBD\b", r"finds? (all|every) ", r"guaranteed? (safe|clean)"):
                self.assertIsNone(re.search(pat, text, re.I), (name, pat))
            self.assertTrue(all(ord(c) < 128 for c in text), name)


@unittest.skipUnless(HAVE_LISTING, SKIP_REASON)
class TestDemo(unittest.TestCase):
    def test_the_demo_is_long_enough_real_and_complete(self):
        self.assertGreaterEqual(len(RESULT), 700)
        self.assertLess(len(RESULT), 8000)
        self.assertGreaterEqual(len(REQUEST), 40)
        for needle in ("**Verdict.**", "**Findings**", "**How to fix**", "**What this scan cannot see**",
                       "Do not share these files as they are", "12 finding(s) in 5 of 6 file(s)", "K3 + H3", "bypassed", "revoke it at the provider"):
            self.assertIn(needle, RESULT, needle)
        order = [RESULT.index(h) for h in ("**Verdict.**", "**Findings**", "**How to fix**", "**What this scan cannot see**")]
        self.assertEqual(order, sorted(order))
        for needle in ("DEMOFAKE", "demo_user_42", "zzdemo", "192.168.77.20", "discord.com"):
            self.assertNotIn(needle, RESULT)

    def test_the_demo_result_is_the_first_report_of_the_example_session(self):
        session = read_text(os.path.join(PKG, "examples", "example_session.md"))
        body = RESULT.split("\n\n", 1)[1].strip()
        self.assertIn(body, session)


if __name__ == "__main__":
    unittest.main()
