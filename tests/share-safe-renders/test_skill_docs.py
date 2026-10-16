# -*- coding: utf-8 -*-
"""SKILL.md, README.md and references/: the rules a peer tester checks, as tests.

* the frontmatter rules (name and description only, short, trigger style),
* the workflow and output format exist in the promised order,
* the verdict wording matches the exit codes and never calls anything clean or safe,
* every class, error code, note code, exit code and JSON field the scanner can produce is documented, and nothing is documented that the scanner cannot produce,
* the claims in known-misses.md that say "confirmed" are re-run here,
* the numbers copied from the head-to-head report are copied exactly,
* no sentence promises more than the scripts do (a short overclaim list).
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

from _base import PKG, SCAN, MAKE_DEMO, HERE, ScanCase, B, scan, read_text, read_bytes

SKILL = read_text(os.path.join(PKG, "SKILL.md"))
README = read_text(os.path.join(PKG, "README.md"))
REF = {n: read_text(os.path.join(PKG, "references", n)) for n in os.listdir(os.path.join(PKG, "references"))}
ALL_DOCS = dict(REF, **{"SKILL.md": SKILL, "README.md": README})


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "no frontmatter"
    return m.group(1).split("\n"), text[m.end():]


def table_rows(text, header_start):
    """Cells of every row of the markdown table whose header row starts with `header_start`."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith(header_start):
            rows = []
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                cells = re.split(r"(?<!\\)\|", row.strip())[1:-1]
                rows.append([c.strip() for c in cells])
            return rows
    raise AssertionError("table %r not found" % header_start)


def frontmatter_problems(lines):
    """Everything wrong with a frontmatter block (a list of its lines); empty means fine."""
    bad = []
    keys = [ln.split(":", 1)[0] for ln in lines]
    if keys != ["name", "description"]:
        bad.append("fields are %r, expected name and description only, one line each" % keys)
    desc = next((ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("description:")), "")
    if len(desc) > 300:
        bad.append("description is %d characters, over 300" % len(desc))
    if len(desc) < 120:
        bad.append("description is too short to say what it does and when to use it")
    if not re.match(r"^[A-Z][a-z]+s ", desc):
        bad.append("description does not start with what the skill does")
    if ". Use when " not in desc:
        bad.append("no 'Use when' clause")
    if ". Do not use for " not in desc:
        bad.append("no 'Do not use for' clause")
    if not desc.endswith("."):
        bad.append("description does not end with a full stop")
    if re.search(r": ", desc) or re.search(r" #", desc) or re.match(r"^[\"'>|]", desc):
        bad.append("description is not safe as an unquoted YAML scalar")
    if not all(ord(c) < 128 for c in desc):
        bad.append("non-ASCII character in the description")
    return bad


OVERCLAIMS = [r"finds? (all|every|any) (secret|leak|key)", r"catch(es)? everything", r"100%", r"bullet-?proof", r"fool-?proof",
              r"fully protects", r"replaces? (exiftool|trufflehog)", r"better than (exiftool|trufflehog)",
              r"guaranteed? (safe|clean|secure)", r"completely (safe|clean|secure)", r"\bTODO\b", r"\bTBD\b", r"\bFIXME\b",
              r"lorem ipsum", r"\bXXX\b", r"world-class", r"best-in-class", r"state of the art"]


def overclaim_hits(text):
    """Overclaims, or an unnegated 'guarantee', in a text; empty means fine."""
    hits = []
    for pat in OVERCLAIMS:
        for m in re.finditer(pat, text, re.I):
            if re.search(r"(not|n't|never|no|cannot) +\w* *$", text[max(0, m.start() - 14): m.start()], re.I):
                continue
            hits.append(text[max(0, m.start() - 25): m.end() + 5])
    for m in re.finditer(r"guarantee", text, re.I):
        before = text[max(0, m.start() - 16): m.start()].lower()
        if not ("not a " in before or "no " in before or "not " in before):
            hits.append(text[max(0, m.start() - 40): m.end() + 20])
    return hits


def verdict_problems(cell):
    """A verdict line must not call anything clean, safe, secure or ok."""
    return re.findall(r"\b(clean|safe|secure|ok)\b", cell.split("**Never say")[0].lower())


class TestFrontmatter(unittest.TestCase):
    def setUp(self):
        self.lines, self.body = frontmatter(SKILL)

    def test_frontmatter_rules(self):
        self.assertEqual(frontmatter_problems(self.lines), [])

    def test_name_is_the_folder_name(self):
        self.assertEqual(self.lines[0], "name: share-safe-renders")
        self.assertEqual(os.path.basename(PKG), "share-safe-renders")

    def test_the_checker_can_fail(self):
        good = list(self.lines)
        bad_cases = {
            "extra field": good + ["license: MIT"],
            "wrong order": [good[1], good[0]],
            "too long": [good[0], good[1] + " " + "More words here. " * 20],
            "too short": ["name: x", "description: Does a thing."],
            "no use-when": [good[0], good[1].replace(". Use when ", ". Run ")],
            "no do-not": [good[0], good[1].replace(". Do not use for ", ". Skip for ")],
            "colon": [good[0], good[1].replace("Scans", "Scans: and")],
            "quoted": [good[0], 'description: "' + good[1].split(": ", 1)[1] + '"'],
            "non-ascii": [good[0], good[1].replace("renders", "rendérs")],
        }
        for label, lines in bad_cases.items():
            self.assertTrue(frontmatter_problems(lines), label)

    def test_the_do_not_use_clause_keeps_source_code_scanning_out(self):
        # The old description did not rule out "scan my Python repository for hardcoded API keys", which is not a render: the
        # clause names source code, so an agent that reads only the description can exclude it. (This test pins the wording; it
        # does not measure what any model does with it.)
        desc = self.lines[1].split(":", 1)[1].strip()
        clause = desc.split(". Do not use for ", 1)[1]
        for needle in ("scrubbing files", "judging picture content", "scanning source code"):
            self.assertIn(needle, clause)
        self.assertNotIn("source code", desc.split(". Do not use for ", 1)[0])

    def test_description_is_valid_yaml_when_a_parser_is_available(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        doc = yaml.safe_load("\n".join(self.lines))
        self.assertEqual(sorted(doc), ["description", "name"])
        self.assertIsInstance(doc["description"], str)

    def test_body_is_real(self):
        self.assertGreater(len(self.body.strip()), 3000)
        self.assertLessEqual(len(self.body.splitlines()), 150, "SKILL.md must stay tight")


class TestStructure(unittest.TestCase):
    def test_headings_in_order(self):
        heads = re.findall(r"^## (.+)$", SKILL, re.M)
        want = ["If there is no skill folder", "When to use", "Rules that always apply", "Names in commands", "Workflow",
                "Output format (always this order)",
                "Exit codes: what to say", "Classes",
                "Export commands (copy without the metadata; run on the demo files with ffmpeg 5.1, 7.1, 8.1.1 and 9.0.1 on Windows)",
                "If Python is missing, or the path has spaces", "Files in this skill"]
        self.assertEqual(heads, want)

    def test_the_six_workflow_steps_in_order(self):
        steps = re.findall(r"^\*\*(\d)\. ([A-Za-z -]+)\.\*\*", SKILL, re.M)
        self.assertEqual(steps, [("1", "Locate"), ("2", "Run"), ("3", "Read"), ("4", "Report"), ("5", "Fix and re-scan"),
                                 ("6", "Limits")])

    def test_output_format_order_is_verdict_findings_fix_limits(self):
        items = re.findall(r"^(\d)\. \*\*([^*]+)\.\*\*", SKILL.split("## Output format")[1].split("## Exit codes")[0], re.M)
        self.assertEqual(items, [("1", "Verdict"), ("2", "Findings"), ("3", "How to fix"), ("4", "What this scan cannot see")])

    def test_the_four_rules_that_protect_the_user(self):
        rules = SKILL.split("## Rules that always apply")[1].split("## Workflow")[0]
        for needle in ("Read only the scanner's report", "untrusted", "Never print a leaked value",
                       "Never change the user's files", "Never tell the user a file or a copy is"):
            self.assertIn(needle, rules)

    def test_statements_added_after_the_first_buyer_read_stay_in_skill_md(self):
        # a first-time buyer ran the package and found these gaps; each statement is measured (see reading-the-report.md and the changelog)
        flat = " ".join(SKILL.split())
        for needle in ("Pass each copy once: `N` counts every path you pass, so a path given twice is counted twice (measured)",
                       "carrier (the container that held the value, such as a PNG text chunk or an MP4 tag)",
                       "bypassed (the ComfyUI node was bypassed or muted: it did not run, but its values are still saved)",
                       "`COULD NOT FULLY SCAN` (the printed section that lists files it could not read, or read only in part)",
                       "do not cut the output with `| Select-Object -First N`: that leaves `$LASTEXITCODE` at -1",
                       # the last read of 1.0.2 and its re-read (run in test_v102_no_skill_folder.py, ShellTests, on Windows: the
                       # usage error --nope prints no RESULT line)
                       "In PowerShell read `$LASTEXITCODE` in the same command, or the `(exit n)` at the end of the `RESULT:` line (a "
                       "usage error, exit 2, prints no `RESULT:` line: read `$LASTEXITCODE` there): a tool that starts a new `powershell.exe` for each command can report 1 for exits 2 and 3 (measured in Windows "
                       "PowerShell 5.1).",
                       "Scanning the containing folder instead puts no file name into the command",
                       "Say them in plain words when the user is not a specialist"):
            self.assertIn(needle, flat, needle)
        report = " ".join(REF["reading-the-report.md"].split())
        self.assertIn("in Windows PowerShell 5.1, cutting the scanner's output with `Select-Object -First 2` left `$LASTEXITCODE` at -1 (measured)", report)

    def test_locate_step_does_not_send_the_agent_searching_the_disk(self):
        self.assertIn("Do not search the disk", SKILL)

    def test_references_named_in_skill_md_exist_and_none_is_orphaned(self):
        for ref in re.findall(r"references/([\w.-]+\.md)", SKILL):
            self.assertIn(ref, REF, ref)
        for ref in REF:
            self.assertTrue(ref in SKILL or ref in README, "%s is not mentioned in SKILL.md or README.md" % ref)
        for ex in os.listdir(os.path.join(PKG, "examples")):
            self.assertTrue(ex in SKILL or ex in README, ex)

    def test_the_package_holds_exactly_these_files(self):
        found = []
        for dp, dns, fns in os.walk(PKG):
            dns[:] = [d for d in dns if d != "__pycache__"]
            found += [os.path.relpath(os.path.join(dp, f), PKG).replace(os.sep, "/") for f in fns]
        want = ["README.md", "SKILL.md", "scripts/scan.py", "scripts/make_demo.py", "examples/sample_report.md",
                "examples/sample_report.json", "examples/example_session.md"] + ["references/" + r for r in (
                    "what-leaks-and-where.md", "how-to-export-clean.md", "reading-the-report.md", "known-misses.md",
                    "vs-exiftool-and-trufflehog.md", "no-skill-folder.md")]
        self.assertEqual(sorted(found), sorted(want))


class TestVerdicts(unittest.TestCase):
    def rows(self):
        return {r[0]: r for r in table_rows(SKILL, "| Exit | Meaning |")}

    def test_every_exit_code_has_a_row(self):
        self.assertEqual(list(self.rows()), ["0", "1", "2", "3", "any other code, or 0, 1 or 3 without a `RESULT:` line"])

    def test_exit_codes_in_the_scanner_are_the_documented_ones(self):
        self.assertEqual((scan.EXIT_CLEAN, scan.EXIT_FINDINGS, scan.EXIT_USAGE, scan.EXIT_UNSCANNED), (0, 1, 2, 3))

    def test_no_verdict_line_calls_anything_clean_or_safe(self):
        for code, row in self.rows().items():
            self.assertEqual(verdict_problems(row[2]), [], code)

    def test_the_verdict_checker_can_fail(self):
        for bad in ("These files are clean.", "Safe to share.", "All OK", "The copy is secure."):
            self.assertTrue(verdict_problems(bad), bad)
        self.assertEqual(verdict_problems("Treat these files as NOT checked. **Never say clean or safe.**"), [])

    def test_exit_0_verdict_says_it_is_not_a_guarantee_and_exit_3_says_not_checked(self):
        r = self.rows()
        self.assertIn("Nothing found in N file(s) scanned. That is not a guarantee.", r["0"][2])
        self.assertIn("Treat these files as NOT checked.", r["3"][2])
        self.assertIn("Never say clean or safe", r["3"][2])
        self.assertIn("Do not share these files as they are", r["1"][2])

    def test_the_scanners_own_result_words_agree_with_the_skill(self):
        # the RESULT line texts the skill tells the agent to look for
        rp = scan.Report()
        self.assertIn("FINDINGS - do not share", scan.render_human(rp, 1))
        self.assertIn("NOTHING FOUND in what was scanned", scan.render_human(rp, 0))
        self.assertIn("treat as NOT clean", scan.render_human(rp, 3))

    def test_class_table_matches_the_scanner(self):
        rows = table_rows(SKILL, "| Id | Severity | Meaning |")
        got = {}
        for r in rows:
            for cid in r[0].split(", "):
                got[cid] = r[1]
        self.assertEqual(got, scan.SEVERITY)
        self.assertEqual(sorted(got), sorted(scan.SEVERITY))

    def test_the_five_cannot_see_items_are_exactly_five(self):
        m = re.search(r"Always these five lines: (.+?)\.\n", SKILL)
        self.assertEqual(len(m.group(1).split(";")), 5)
        for needle in ("pixel", "IDAT", "mdat", "C2PA", "split", "glued", "placeholder", "WebP"):
            self.assertIn(needle, m.group(1))


class TestReportReferenceMatchesTheScanner(unittest.TestCase):
    REPORT = REF["reading-the-report.md"]

    def codes_in_scanner(self):
        tree = ast.parse(read_text(SCAN))
        errors, notes = set(), set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("error", "note") \
                    and len(n.args) >= 2:
                tgt = errors if n.func.attr == "error" else notes
                for c in ast.walk(n.args[1]):
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        tgt.add(c.value)
        errors -= {"png_", "internal_error_"}
        errors |= set("png_" + v for v in scan._INFLATE_ERR.values())      # the code adds the png_ prefix
        errors.add("internal_error_<Name>")
        notes -= {"embedded_comfyui_%s_json", "findings_capped_%d"}
        notes |= {"embedded_comfyui_api_json", "embedded_comfyui_ui_json",
                  "findings_capped_%d" % scan.MAX_FINDINGS_PER_FILE}
        return errors, notes

    def documented(self, heading):
        sect = self.REPORT.split(heading)[1].split("\n## ")[0]
        codes = set()
        for row in table_rows(sect, "| Code |"):
            codes.update(re.findall(r"`([a-z_0-9<>A-Z]+)`", row[0]))
        return codes

    def test_every_error_code_is_documented_and_none_is_invented(self):
        errors, _ = self.codes_in_scanner()
        doc = self.documented("## `COULD NOT FULLY SCAN`: every code")
        self.assertEqual(sorted(errors - doc), [], "codes the scanner can emit but the page does not explain")
        self.assertEqual(sorted(doc - errors), [], "codes the page explains that the scanner never emits")

    def test_every_note_code_is_documented_and_none_is_invented(self):
        _, notes = self.codes_in_scanner()
        doc = self.documented("## `NOTES`: every code")
        self.assertEqual(sorted(notes - doc), [])
        self.assertEqual(sorted(doc - notes), [])

    def test_version_in_the_documented_examples_is_the_scanner_version(self):
        self.assertIn("scan.py %s" % scan.VERSION, self.REPORT)
        self.assertIn('"version": "%s"' % scan.VERSION, self.REPORT)

    def test_class_table_matches(self):
        rows = table_rows(self.REPORT, "| Id | Severity | What it is |")
        got = {r[0]: r[1] for r in rows}
        self.assertEqual(got, scan.SEVERITY)

    def test_documented_caps_are_the_scanners_caps(self):
        for fact in ("1,000,000 chunks", "64 MiB", "200,000 boxes", "4,000,000", "5000 text tags", "1000 lines",
                     "50,000", "20,000", "20000", "(12)", "256 MiB", "120", "over 1 MiB (only its first 1 MiB is read)",
                     "first 100"):
            self.assertIn(fact, self.REPORT, fact)
        self.assertEqual((scan.MAX_PNG_CHUNKS, scan.PAYLOAD_CAP, scan.MAX_BOXES, scan.MAX_TEXT_RUNS, scan.MAX_EXIF_TEXTS,
                          scan.MAX_PRINT_FINDINGS, scan.MAX_REPORT_HIGH, scan.MAX_REPORT_LOW, scan.DEFAULT_MAX_FILES,
                          scan.DEFAULT_MAX_DEPTH, scan.JSON_FILE_CAP, scan.DEFAULT_TIME_LIMIT, scan.NESTED_BOX_CAP,
                          scan.MAX_SKIP_NAMES),
                         (1000000, 64 << 20, 200000, 4000000, 5000, 1000, 50000, 20000, 20000, 12, 256 << 20, 120.0, 1 << 20, 100))

    def test_every_detail_value_the_scanner_writes_is_documented(self):
        src = read_text(SCAN)
        values = set(re.findall(r'"(kind=[a-z0-9_]+)', src)) | set(re.findall(r'detail="(kind=[a-z0-9_]+)', src))
        values |= {"kind=exif_gps", "kind=xmp_gps", "kind=iso6709_location", "kind=loci_location"}
        for v in sorted(values):
            self.assertIn(v, self.REPORT, v)

    def test_json_fields_documented_are_the_fields_produced(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "demo")
            subprocess.run([sys.executable, "-I", "-B", MAKE_DEMO, out, "--no-mp4"], check=True, stdout=subprocess.PIPE)
            rep = os.path.join(td, "r.json")
            subprocess.run([sys.executable, "-I", "-B", SCAN, out, "--json", rep], stdout=subprocess.PIPE)
            doc = json.loads(read_text(rep))
        for key in list(doc) + list(doc["summary"]):
            self.assertIn('"%s"' % key, self.REPORT, key)
        field_rows = {r[0].strip("`") for r in table_rows(self.REPORT, "| Field | Type | Meaning |")}
        produced = set()
        for f in doc["findings"]:
            produced.update(f)
        self.assertLessEqual(produced, field_rows, "fields the scanner writes but the page does not document")
        self.assertLessEqual(field_rows - produced, {"count"}, "fields documented but never written")

    def test_the_example_finding_line_has_the_shape_the_scanner_prints(self):
        shape = re.compile(r"^\[(HIGH|MEDIUM|LOW)\] \S+  file=.*  carrier=\S+  location=\S+  node=\S+  bypassed=(yes|no)  "
                           r"length=\d+  sha256=[0-9a-f]{8}(  \(.*\))?$")
        doc_line = re.search(r"^\[HIGH\] K1  file=.*$", self.REPORT, re.M).group(0)
        self.assertRegex(doc_line, shape)
        rp = scan.Report()
        sink = scan.Sink(rp, "f.png")
        sink.add("png:tEXt", "K1", "tEXt[prompt]:x", "somevalue", node_id="11", detail="vendor=openai")
        line = [ln.strip() for ln in scan.render_human(rp, 1).splitlines() if ln.strip().startswith("[HIGH]")][0]
        self.assertRegex(line, shape)


class TestKnownMissesAreTrue(ScanCase):
    """known-misses.md says 'confirmed' next to several items. Re-run each one."""

    def classes(self, text):
        return sorted(set(c for c, v, d in scan.scan_text(text, unescape=True)))

    def jclasses(self, obj):
        sink = scan.Sink(scan.Report(), "x")
        scan.process_blob(sink, "json:file", "file", json.dumps(obj))
        return sorted(set(f["class"] for f in sink.rp.findings if "companion_of" not in f))

    def setUp(self):
        ScanCase.setUp(self)
        self.key = self.fake.openai_legacy()
        self.ghp = self.fake.github_classic()

    def test_the_control_is_found(self):
        self.assertEqual(self.classes("here " + self.key), ["K1"])

    def test_base64_hex_and_lookalike_keys_are_silent(self):
        import base64
        self.assertEqual(self.classes(base64.b64encode(self.key.encode()).decode()), [])
        self.assertEqual(self.classes(self.key.encode().hex()), [])
        self.assertEqual(self.classes("s" + "k-" + "а" + self.key[4:]), [])

    def test_a_key_glued_to_a_letter_is_silent_but_env_prefix_is_not(self):
        self.assertEqual(self.classes("abc" + self.key), [])
        self.assertEqual(self.classes("ENV_" + self.key), ["K1"])
        self.assertEqual(self.classes("abc" + self.ghp), ["K1"])      # distinctive prefixes are found even when glued

    def test_a_key_split_into_short_pieces_is_silent(self):
        self.assertEqual(self.jclasses({"a": self.key[:10], "b": self.key[10:]}), [])

    def test_unrecognised_field_names_are_silent_and_recognised_ones_are_not(self):
        v = self.fake.secret_value(30)
        for name in ("cookie", "credentials", "session_id", "auth", "key"):
            self.assertEqual(self.jclasses({name: v}), [], name)
        self.assertEqual(self.jclasses({"api_key": v}), ["K2"])
        self.assertEqual(self.jclasses({"password": "hunter22"}), ["K2"])

    def test_placeholders_are_silent_even_under_a_secret_name(self):
        self.assertEqual(self.jclasses({"password": "changeme"}), [])
        self.assertEqual(self.jclasses({"api_key": "your_api_key"}), [])
        self.assertEqual(self.jclasses({"max_tokens": "123456789"}), [])

    def test_addresses_outside_the_three_private_ranges_are_silent(self):
        for text in ("addr fd12:3456:789a::1 here", "addr 127.0.0.1 here", "addr 8.8.8.8 here", "addr 100.64.1.1 here",
                     "addr 169.254.10.10 here", "version 1.2.3.4 here", "path /root/secret/file.png"):
            self.assertEqual(self.classes(text), [], text)
        self.assertEqual(self.classes("addr 192.168.1.1 here"), ["P3"])

    def test_documentation_addresses_stripe_test_keys_and_the_aws_example_are_silent(self):
        self.assertEqual(self.classes("a" + "@" + "example.com"), [])
        self.assertEqual(self.classes("s" + "k_" + "test_" + self.key[3:27]), [])
        self.assertEqual(self.classes("AKIA" + "IOSFODNN7" + "EXAMPLE"), [])

    def test_a_jwt_is_found_under_a_token_field_but_not_in_free_text(self):
        jwt = "eyJ" + self.key[3:23] + "." + self.key[3:33] + "." + self.key[10:40]
        self.assertEqual(self.classes(jwt), [])
        self.assertEqual(self.jclasses({"token": jwt}), ["K2"])

    def test_lowercase_passphrase_under_an_ordinary_name_is_silent(self):
        self.assertEqual(self.jclasses({"note": "correct horse battery staple"}), [])

    def test_unsupported_container_is_exit_3_not_clean(self):
        p = self.write("loop.webp", b"RIFF" + b"\x1a\x00\x00\x00" + b"WEBPVP8L" + bytes(18))
        r = self.cli(p)
        self.assertEqual(r.code, 3)
        self.assertEqual([e["code"] for e in r.doc["errors"]], ["unsupported_media"])

    def test_large_file_over_max_bytes_is_unscanned_not_skipped(self):
        p = self.write("big.png", B.make_png(B.t_text("Comment", "x" * 500)))
        r = self.cli(p, "--max-bytes", "100")
        self.assertEqual(r.code, 3)
        self.assertEqual([e["code"] for e in r.doc["errors"]], ["too_big"])

    def test_truncated_png_is_exit_3(self):
        p = self.write("cut.png", B.make_png(B.t_text("Comment", "plain words only"))[:-30])
        r = self.cli(p)
        self.assertEqual(r.code, 3)

    def test_heic_is_documented_as_not_opened_and_really_is_exit_3(self):
        import struct
        for name in ("known-misses.md", "reading-the-report.md", "what-leaks-and-where.md"):
            self.assertIn("HEIC", REF[name], name)
        self.assertIn("HEIC", SKILL)
        self.assertIn("HEIC", README)
        body = b"heic" + struct.pack(">I", 0) + b"mif1heic"
        data = struct.pack(">I", 8 + len(body)) + b"ftyp" + body + B.box("mdat", b"x" * 40)
        r = self.cli(self.write("photo.bin", data))
        self.assertEqual((r.code, [e["code"] for e in r.doc["errors"]]), (3, ["unsupported_media"]))

    def test_trailing_backslash_inside_quotes_is_exit_3_not_clean(self):
        # the effect described in SKILL.md: the closing quote is eaten, the path no longer exists
        r = self.cli(os.path.join(self.dir, "no such folder") + '"')
        self.assertEqual((r.code, [e["code"] for e in r.doc["errors"]]), (3, ["not_found"]))


class TestHeadToHeadNumbersAreCopiedExactly(unittest.TestCase):
    def test_every_table_block_is_a_verbatim_copy(self):
        report = read_text(os.path.join(HERE, "eval", "H2H_REPORT.md"))
        vs = REF["vs-exiftool-and-trufflehog.md"]
        blocks = re.findall(r"```\n(class  planted.*?)\n```", vs, re.S)
        self.assertEqual(len(blocks), 2)
        for b in blocks:
            self.assertIn(b, report)

    def test_the_sentences_that_quote_the_report(self):
        report = read_text(os.path.join(HERE, "eval", "H2H_REPORT.md"))
        vs = REF["vs-exiftool-and-trufflehog.md"]
        pairs = [("240 registered files, 194 required planted entries", "240 registered files, 194 required planted entries"),
                 ("exiftool 13.59, trufflehog 3.99.2, Python 3.14.6", "exiftool 13.59, trufflehog 3.99.2, Python 3.14.6"),
                 ("154 of 194", "154/194"), ("238 had `chunks: 0`", "238 of 240 files produced `chunks: 0`"),
                 ("27.2 s", "27.2"), ("159.5 s", "159.5"), ("212.8 s", "212.8"), ("0.68 s against 1.96 s", "0.68 s"),
                 ("33 of the 40 remaining effective K1 entries (82%)", "33 of 40 remaining effective K1 entries (82%)"),
                 ("excluding OpenAI-legacy values and lone AWS key ids", "Excluding openai-legacy and lone AWS ids"), ("169 of 176", "169 of 176"), ("43 OpenAI-legacy values, 1 with the marker", "(43 OpenAI-legacy values, 1")]
        for in_vs, in_report in pairs:
            self.assertIn(in_vs, vs, in_vs)
            self.assertIn(in_report, report, in_report)
        for fact in ("A 0; B1w 119; B2p 118; B2b 120; B2u 117; Bx 114 (B1: 147)",):
            self.assertIn(fact, vs)
        for row in ("| 0 | 147 | 119 | 118 | 120 | 117 | 114 |", "**0** | 147 | 119 | 118 | 120 | 117 | 114"):
            if row in report:
                break
        else:
            self.fail("false-clean row not found in the report")


class TestNoOverclaims(unittest.TestCase):
    def test_no_overclaim_in_any_doc(self):
        # The one ```python block of the package is the extractor program of references/no-skill-folder.md (code, not a claim:
        # its variable `todo` would read as TODO). test_v102_no_skill_folder.py pins that block byte for byte to the program
        # generated from the package scripts, so it is left out here and nothing else is.
        for name, text in ALL_DOCS.items():
            prose = re.sub(r"^```python\n.*?^```$", "", text, flags=re.S | re.M)
            self.assertEqual(prose.count("```python"), 0, name)
            self.assertEqual(overclaim_hits(prose), [], name)
        self.assertEqual(sum(t.count("```python\n") for t in ALL_DOCS.values()), 1, "only the extractor program is a python block")
        self.assertTrue(overclaim_hits(re.sub(r"^```python\n.*?^```$", "", "TODO\n```python\nx\n```\n", flags=re.S | re.M)),
                        "negative control: prose outside the block is still checked")

    def test_the_overclaim_checker_can_fail(self):
        for bad in ("It finds every secret.", "A 100% reliable check.", "This replaces exiftool.", "It is guaranteed safe.",
                    "We guarantee nothing leaks.", "TODO fill in", "bulletproof"):
            self.assertTrue(overclaim_hits(bad), bad)
        for good in ("This does not replace exiftool.", "That is not a guarantee.", "There is no guarantee."):
            self.assertEqual(overclaim_hits(good), [], good)

    def test_the_words_clean_and_safe_only_appear_in_allowed_ways(self):
        # allowed: "Never ... clean/safe" (the rule that forbids them), "safe to share" in a user phrase or a negation, "not clean/not safe".
        # (test_audit_docs.py also forbids "clean copy" and the like everywhere: a copy is a "re-exported copy")
        text = frontmatter(SKILL)[1]
        for m in re.finditer(r"(?<![-\w])(clean|safe)(?![-\w])", text, re.I):
            ctx = text[max(0, m.start() - 45): m.end() + 25].replace("\n", " ")
            ok = re.search(r"clean (copy|copies|export)", ctx, re.I) or re.search(r"(never|not|Never say|\"clean\" or \"safe\")", ctx, re.I) \
                or "safe to share" in ctx or "clean-copy" in ctx.lower() or "Clean copy" in ctx
            self.assertTrue(ok, ctx)

    def test_docs_are_ascii(self):
        for name, text in ALL_DOCS.items():
            bad = sorted(set(ch for ch in text if ord(ch) > 127))
            self.assertEqual(bad, [], name)

    def test_the_repository_sentence_is_the_agreed_one(self):
        self.assertIn("https://github.com/sawizzle/share-safe-renders", README)
        self.assertIn("published with the release", README)


class TestReadme(unittest.TestCase):
    def test_sections(self):
        heads = re.findall(r"^## (.+)$", README, re.M)
        self.assertEqual(heads, ["Quick start", "What it can tell you", "What it cannot tell you", "Install", "Requirements", "Try it",
                                 "How it compares", "What is in the folder", "Permissions", "Source and tests", "Licence"])
        flat = " ".join(README.split())
        quick = flat.split("## Quick start")[1].split("## What it can tell you")[0]
        for needle in ("check these renders before I post them", "0 nothing found, 1 something found, 2 the command was wrong, 3 something could not be scanned",
                       "is not a guarantee"):
            self.assertIn(needle, quick, needle)
        self.assertIn("Agensi's buyer terms (a personal, non-transferable licence)", flat)
        self.assertIn("if you want to use it on a team or at work, use that copy", flat)
        self.assertNotIn("private deny-list", flat)
        self.assertIn("`DEMO_EXPECTED.md` is created by this script: it is not in the zip", flat)

    def test_three_try_it_commands(self):
        block = re.search(r"## Try it.*?```sh\n(.*?)```", README, re.S).group(1).strip().splitlines()
        self.assertEqual(block, ['python -I -B "<SKILL_DIR>/scripts/make_demo.py" "<WORK>/demo"',
                                 'python -I -B "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo" --json "<WORK>/demo_report.json"',
                                 'python -I -B "<SKILL_DIR>/scripts/scan.py" "<WORK>/demo/04_clean.png"'])

    def test_permissions_paragraph_matches_the_static_checks(self):
        p = " ".join(README.split("## Permissions")[1].split("## Source and tests")[0].split())
        for needle in ("read no environment variable of their own", "delete nothing", "never through a shell", "--no-mp4",
                       "start no program except `ffprobe`", "refuses to replace an existing file given to `--json`"):
            self.assertIn(needle, p)


if __name__ == "__main__":
    unittest.main()
