# -*- coding: utf-8 -*-
"""Nothing private and nothing credential-shaped in any package, test or listing file; the package is text only and zips
the way Agensi wants; the local copy of Agensi's precheck passes with zero FAIL.

Files scanned: everything under packages/share-safe-renders, tests/share-safe-renders and listing/share-safe-renders
(not __pycache__, and not the private deny-list file described next).

Two kinds of check live here.

* Structural checks that need no private knowledge and run in every checkout: credential-shaped literals, e-mail addresses on
  real-looking domains, home-folder paths with a real-looking name, only the publisher handle in the repository address,
  a text-only package, the zip layout and the Agensi precheck.
* Checks against a list of private terms (a person's name, studio and project names, names of other products). That list is
  not in this repository, in clear or as hashes. It is read from one local file, tests/share-safe-renders/_private_denylist.json,
  which exists only in the maintainer's checkout and must be listed in .gitignore. In any other checkout the tests that need it
  skip with a stated reason. The mechanism itself is proven in every checkout, against a synthetic list built inside these
  tests: a text that holds a listed word, phrase or name is caught, and a text that does not is passed."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

from _base import HERE, PKG, LISTING, PRECHECK, REPO, scan, read_bytes, read_text

REPO_URL = "https://github.com/sawizzle/share-safe-renders"
HANDLE = REPO_URL.split("/")[3]                      # the publisher handle: public by design, allowed only inside the repository address
ROOTS = [PKG, HERE, LISTING]
TEXT_EXT = (".md", ".py", ".json", ".txt", ".gitignore")
PRIVATE_FILE = os.path.join(HERE, "_private_denylist.json")
PRIVATE_PRESENT = os.path.isfile(PRIVATE_FILE)
PRIVATE_SKIP = "the maintainer-only private deny-list file is not in this checkout"


def all_files(roots=None, skip=None):
    """Every file under the roots, sorted, except __pycache__ and .git folders and the private deny-list file (which holds
    the private terms in clear text, so it is the one file that must not be scanned for them)."""
    skip = os.path.normcase(os.path.abspath(PRIVATE_FILE if skip is None else skip))
    out = []
    for root in (ROOTS if roots is None else roots):
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in ("__pycache__", ".git")]
            for fn in fns:
                full = os.path.join(dp, fn)
                if os.path.normcase(os.path.abspath(full)) != skip:
                    out.append(full)
    return sorted(out)


def text_of(path):
    return read_bytes(path).decode("utf-8")


def rel(path):
    return os.path.relpath(path, REPO).replace(os.sep, "/")


# ---------------------------------------------------------------------------------------------------------------
# credential-shaped literals: the precheck's own patterns, plus a few of ours
# ---------------------------------------------------------------------------------------------------------------
CRED_PATTERNS = [
    r"AKIA[0-9A-Z]{16}", r"ASIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{20,}",
    r"sk-[A-Za-z0-9]{20,}", r"sk-ant-[A-Za-z0-9_-]{20,}", r"xox[abprsoe]-", r"xapp-[0-9]", r"AIza[0-9A-Za-z_-]{30,}",
    r"hf_[A-Za-z0-9]{30,}", r"(?<![A-Za-z])sk_live_[A-Za-z0-9]{10,}", r"(?<![A-Za-z])rk_live_[A-Za-z0-9]{10,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY", r"[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}", r"[A-Za-z0-9+/]{300,}={0,2}",
    r"https://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services)/\S{10,}",
]
# files that are allowed to hold a 64-hex string: none. (The precheck warns about a 64-hex literal.)


class TestNoCredentialShapedLiterals(unittest.TestCase):
    def test_precheck_style_patterns_find_nothing(self):
        for path in all_files():
            if not path.endswith(TEXT_EXT):
                continue
            text = text_of(path)
            for pat in CRED_PATTERNS:
                m = re.search(pat, text)
                self.assertIsNone(m, "%s: %s matches %s" % (rel(path), pat, m and m.group(0)[:12] + "..."))
            self.assertIsNone(re.search(r"\b[0-9a-fA-F]{64}\b", text), rel(path) + ": a 64-digit hex literal")

    def test_the_scanner_itself_finds_no_key_or_webhook_in_any_file(self):
        for path in all_files():
            if not path.endswith(TEXT_EXT):
                continue
            bad = [(c, d) for c, v, d in scan.scan_text(text_of(path)) if c in ("K1", "K3")]
            self.assertEqual(bad, [], rel(path))

    def test_the_credential_patterns_can_fail(self):
        # negative controls: strings that ARE credential-shaped, built from pieces here, must be caught by the patterns and by the scanner
        samples = {
            "openai": "s" + "k-" + "A" * 30, "github": "gh" + "p_" + "A" * 36, "aws": "AK" + "IA" + "A" * 16,
            "slack": "xo" + "xb-1", "google": "AI" + "za" + "A" * 35, "hf": "h" + "f_" + "A" * 34,
            "pem": "-----BEGIN " + "RSA PRIVATE KEY-----", "discord": "https://discord.com/api/web" + "hooks/123456789012345678/" + "A" * 30,
            "bearer": "Bearer " + "A" * 30, "blob": "A" * 320,
        }
        for label, text in samples.items():
            self.assertTrue(any(re.search(p, text) for p in CRED_PATTERNS), label)
        for label in ("openai", "github", "aws", "discord"):
            self.assertTrue([1 for c, v, d in scan.scan_text(samples[label]) if c in ("K1", "K3")], label)

    def test_text_files_are_text(self):
        for path in all_files():
            if os.path.relpath(path, PKG).startswith(".."):
                continue                                           # the package only: no binary, ever
            raw = read_bytes(path)
            self.assertNotIn(b"\x00", raw, rel(path))
            raw.decode("utf-8")
            self.assertTrue(path.endswith((".md", ".py", ".json")), rel(path))
            self.assertLess(len(raw), 1 << 20, rel(path))


# ---------------------------------------------------------------------------------------------------------------
# private terms: the mechanism (runs everywhere, on a synthetic list) and the real list (maintainer's checkout only)
# ---------------------------------------------------------------------------------------------------------------
WORDS = re.compile(r"[a-z0-9]+")
HASH16 = re.compile(r"[0-9a-f]{16}")
PRIVATE_KEYS = ("unigram_hashes", "bigram_hashes", "unigram_control_words", "bigram_control_words", "forbidden_products")


def sha16(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def private_term_hits(text, unigram_hashes=(), bigram_hashes=(), names=()):
    """What in one text is on a private list, as short labels that never repeat the text that matched.

    A word is a run of letters and digits, compared in lower case by the first 16 hex digits of its SHA-256; a phrase is two
    neighbouring words (punctuation between them does not hide it) joined by one space; a name is a plain substring,
    compared in lower case."""
    hits = []
    words = WORDS.findall(text.lower())
    if any(sha16(w) in unigram_hashes for w in set(words)):
        hits.append("a word on the private list")
    if any(sha16(a + " " + b) in bigram_hashes for a, b in set(zip(words, words[1:]))):
        hits.append("a phrase on the private list")
    low = text.lower()
    for i, name in enumerate(names):
        if name.lower() in low:
            hits.append("a forbidden name (entry %d of the private list)" % i)
    return hits


def private_term_problems(paths, unigram_hashes=(), bigram_hashes=(), names=(), base=REPO):
    """One line per (text file, kind of hit); the paths are shown relative to `base`."""
    problems = []
    for path in paths:
        if not path.endswith(TEXT_EXT):
            continue
        for hit in private_term_hits(text_of(path), unigram_hashes, bigram_hashes, names):
            problems.append("%s holds %s" % (os.path.relpath(path, base).replace(os.sep, "/"), hit))
    return problems


def load_private_denylist(path):
    """The private deny-list as a dict of lists. Raises ValueError, naming the key and the position but never a term, when the
    file is not usable: a list that is missing or empty would make the checks pass without checking anything."""
    try:
        doc = json.loads(read_text(path))
    except ValueError as exc:
        raise ValueError("the private deny-list is not valid UTF-8 JSON (%s)" % exc.__class__.__name__)
    if not isinstance(doc, dict):
        raise ValueError("the private deny-list is not a JSON object")
    extra = sorted(set(doc) - set(PRIVATE_KEYS) - {"note"})
    if extra:
        raise ValueError("the private deny-list has unknown keys: %s" % ", ".join(extra))
    for key in PRIVATE_KEYS:
        items = doc.get(key)
        if not isinstance(items, list) or not items:
            raise ValueError("%s is missing or empty" % key)
        for i, item in enumerate(items):
            if not isinstance(item, str):
                raise ValueError("%s[%d] is not a string" % (key, i))
            if key.endswith("_hashes") and not HASH16.fullmatch(item):
                raise ValueError("%s[%d] is not 16 lower-case hex digits" % (key, i))
            if key == "unigram_control_words" and not re.fullmatch(r"[a-z0-9]+", item):
                raise ValueError("%s[%d] is not one lower-case word" % (key, i))
            if key == "bigram_control_words" and not re.fullmatch(r"[a-z0-9]+ [a-z0-9]+", item):
                raise ValueError("%s[%d] is not two lower-case words" % (key, i))
            if key == "forbidden_products" and len(item.strip()) < 4:
                raise ValueError("%s[%d] is shorter than 4 characters" % (key, i))
    return {key: doc[key] for key in PRIVATE_KEYS}


def handle_outside_the_repository_address(text):
    return HANDLE in text.replace(REPO_URL, "").lower()


class TestPrivateTermMechanism(unittest.TestCase):
    """The checks that read the private list, proven on a synthetic list. The terms below are invented stand-ins (stock
    adventure-game words that belong to nobody), not anything private."""

    UNI = {sha16("zork1")}
    BI = {sha16("xyzzy plugh")}
    NAMES = ["Frobozz"]

    def hits(self, text):
        return private_term_hits(text, self.UNI, self.BI, self.NAMES)

    def test_a_listed_word_phrase_or_name_is_caught(self):
        self.assertEqual(self.hits("Say Zork1 aloud."), ["a word on the private list"])                        # case does not hide it
        self.assertEqual(self.hits("then XYZZY, Plugh!"), ["a phrase on the private list"])                    # neither do capitals or punctuation
        self.assertEqual(self.hits("see the frobozz papers"), ["a forbidden name (entry 0 of the private list)"])
        self.assertEqual(len(self.hits("Zork1 xyzzy plugh Frobozz")), 3)                                       # all three kinds in one text

    def test_text_that_holds_no_listed_term_passes(self):
        for text in ("", "nothing to see here", "xyzzy and plugh", "plugh xyzzy", "xyzzy, then much later, plugh",
                     "zork 1 and zork10 and azork1", "frob ozz", "a render of 10.0.0.1 with GPS"):
            self.assertEqual(self.hits(text), [], text)

    def test_an_empty_list_finds_nothing(self):
        self.assertEqual(private_term_hits("xyzzy plugh zork1 frobozz"), [])

    def test_a_hit_never_repeats_the_text_it_matched(self):
        shown = " ".join(self.hits("zork1 xyzzy plugh frobozz")).lower()
        for term in ("zork1", "xyzzy", "plugh", "frobozz"):
            self.assertNotIn(term, shown)

    def test_the_file_check_reads_every_text_file_and_names_the_file_that_holds_a_term(self):
        with tempfile.TemporaryDirectory() as td:
            files = {"clean.md": "nothing here", "word.md": "play zork1", "phrase.json": '{"a": "xyzzy plugh"}',
                     "name.py": "# frobozz", "binary.png": "xyzzy plugh frobozz zork1"}
            for name, text in files.items():
                with open(os.path.join(td, name), "w") as fh:
                    fh.write(text)
            got = private_term_problems(all_files([td], skip=os.path.join(td, "no-such-file")), self.UNI, self.BI, self.NAMES, base=td)
            self.assertEqual(got, ["name.py holds a forbidden name (entry 0 of the private list)",
                                   "phrase.json holds a phrase on the private list", "word.md holds a word on the private list"])

    def test_the_deny_list_file_itself_is_the_one_file_that_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ("_private_denylist.json", "other.json", os.path.join("sub", "_private_denylist.json")):
                os.makedirs(os.path.dirname(os.path.join(td, name)), exist_ok=True)
                with open(os.path.join(td, name), "w") as fh:
                    fh.write("{}")
            got = [os.path.relpath(p, td).replace(os.sep, "/") for p in all_files([td], skip=os.path.join(td, "_private_denylist.json"))]
            self.assertEqual(got, ["other.json", "sub/_private_denylist.json"])
        self.assertEqual(os.path.dirname(PRIVATE_FILE), HERE)                         # the real one sits beside these tests
        self.assertEqual(os.path.basename(PRIVATE_FILE), "_private_denylist.json")

    def test_a_deny_list_file_that_cannot_make_the_checks_pass_vacuously_is_refused(self):
        good = {"unigram_hashes": ["0123456789abcdef"], "bigram_hashes": ["fedcba9876543210"], "unigram_control_words": ["zork1"],
                "bigram_control_words": ["xyzzy plugh"], "forbidden_products": ["Frobozz"]}
        bad = {"empty list": dict(good, bigram_hashes=[]), "missing list": {k: v for k, v in good.items() if k != "forbidden_products"},
               "short hash": dict(good, unigram_hashes=["0123456789abcde"]), "upper-case hash": dict(good, unigram_hashes=["0123456789ABCDEF"]),
               "capital control word": dict(good, unigram_control_words=["Zork1"]), "one-word phrase": dict(good, bigram_control_words=["xyzzy"]),
               "tiny product name": dict(good, forbidden_products=["ab"]), "not a string": dict(good, forbidden_products=[7]),
               "unknown key": dict(good, extra=["x"]), "not an object": ["x"]}
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "d.json")

            def write(doc):
                with open(path, "w") as fh:
                    json.dump(doc, fh)

            write(dict(good, note="free text is allowed"))
            self.assertEqual(sorted(load_private_denylist(path)), sorted(PRIVATE_KEYS))
            for label, doc in bad.items():
                write(doc)
                with self.assertRaises(ValueError, msg=label):
                    load_private_denylist(path)
            with open(path, "w") as fh:
                fh.write("{not json")
            with self.assertRaises(ValueError):
                load_private_denylist(path)

    def test_the_publisher_handle_is_allowed_only_inside_the_repository_address(self):
        self.assertFalse(handle_outside_the_repository_address("see " + REPO_URL + " for the tests"))
        self.assertTrue(handle_outside_the_repository_address("by " + HANDLE))
        self.assertTrue(handle_outside_the_repository_address(REPO_URL + " and " + HANDLE.upper()))
        self.assertTrue(handle_outside_the_repository_address("https://github.com/" + HANDLE))
        self.assertEqual(HANDLE, REPO_URL.split("github.com/")[1].split("/")[0])    # the handle is the first folder of the address

    def test_the_tests_readme_describes_the_private_file_and_the_reason_for_the_skip(self):
        flat = " ".join(read_text(os.path.join(HERE, "README.md")).split())
        self.assertIn(os.path.basename(PRIVATE_FILE), flat)
        self.assertIn(PRIVATE_SKIP, flat)
        for key in PRIVATE_KEYS:
            self.assertIn("`%s`" % key, flat, key)


@unittest.skipUnless(PRIVATE_PRESENT, PRIVATE_SKIP)
class TestPrivateDenyList(unittest.TestCase):
    """The real private list, read from tests/share-safe-renders/_private_denylist.json (maintainer's checkout only). A file
    that is there but unusable is an error, not a skip."""

    @classmethod
    def setUpClass(cls):
        cls.deny = load_private_denylist(PRIVATE_FILE)

    def test_no_private_name_in_any_file(self):
        d = self.deny
        self.assertEqual(private_term_problems(all_files(), set(d["unigram_hashes"]), set(d["bigram_hashes"])), [])

    def test_the_private_name_list_catches_what_it_is_for(self):
        # negative control: the hash of every listed control word is on the list, and a text made of them is caught
        d = self.deny
        for w in d["unigram_control_words"]:
            self.assertIn(sha16(w), d["unigram_hashes"])
            self.assertIn("a word on the private list", private_term_hits("x " + w + " y", set(d["unigram_hashes"]), set(d["bigram_hashes"])))
        for w in d["bigram_control_words"]:
            self.assertIn(sha16(w), d["bigram_hashes"])
            self.assertIn("a phrase on the private list", private_term_hits("x " + w + " y", set(d["unigram_hashes"]), set(d["bigram_hashes"])))

    def test_no_forbidden_product_names(self):
        names = self.deny["forbidden_products"]
        self.assertEqual(private_term_problems(all_files(), names=names), [])
        for i, name in enumerate(names):                        # negative control: every listed name is caught, in any case
            self.assertEqual(private_term_hits("a " + name.upper() + " b", names=names).count("a forbidden name (entry %d of the private list)" % i), 1)


# ---------------------------------------------------------------------------------------------------------------
# e-mail addresses, home paths, the publisher handle
# ---------------------------------------------------------------------------------------------------------------
EMAIL = re.compile(r"(?<![\w.])[\w.%+-]+@(?:[\w-]+\.)+[\w-]{2,}")
RESERVED_DOMAINS = ("example.com", "example.org", "example.net", "example.edu")
RESERVED_TLDS = {"example", "test", "invalid", "localhost"}
FILE_LOOKALIKES = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "safetensors", "ckpt", "js", "json", "txt", "yaml"}
HOME = re.compile(r"(?:[A-Za-z]:[\\/]+|(?<![\w:])/)(?:Users|home|Documents and Settings)[\\/]+([^\\/\s\"'<>|*?:`]+)", re.I)
ALLOWED_HOME_NAMES = {"public", "default", "all", "shared", "user", "username", "name", "page", "you", "yourname", "x", "y",
                      "z", "someone", "me", "profile", "default user"}
ALLOWED_HOME_PREFIXES = ("fx", "demo", "tester", "test", "qa", "your")


class TestNoPrivateData(unittest.TestCase):
    def test_the_only_mention_of_the_publisher_handle_is_the_repository_address(self):
        for path in all_files():
            if not path.endswith(TEXT_EXT):
                continue
            self.assertFalse(handle_outside_the_repository_address(text_of(path)), rel(path))

    def test_no_email_address_except_reserved_example_domains(self):
        for path in all_files():
            if not path.endswith(TEXT_EXT):
                continue
            for m in EMAIL.finditer(text_of(path)):
                addr = m.group(0).lower().rstrip(".")
                dom = addr.split("@")[1]
                tld = dom.split(".")[-1]
                ok = dom.endswith(RESERVED_DOMAINS) or tld in RESERVED_TLDS or tld in FILE_LOOKALIKES or tld.isdigit()
                self.assertTrue(ok, "%s: an e-mail address on a real-looking domain: %s" % (rel(path), addr))

    def test_no_home_folder_path_with_a_real_looking_name(self):
        for path in all_files():
            if not path.endswith(TEXT_EXT):
                continue
            for m in HOME.finditer(text_of(path)):
                name = m.group(1).strip().lower().rstrip(".,;)")
                ok = (name in ALLOWED_HOME_NAMES or name.startswith(ALLOWED_HOME_PREFIXES) or not re.match(r"[a-z]", name)
                      or name.isdigit() or len(name) == 1)
                self.assertTrue(ok, "%s: a home path with a name: %r" % (rel(path), name))

    def test_deny_patterns_do_catch_what_they_are_for(self):
        # negative controls: the same patterns, on strings built here, must fire
        bs = chr(92)
        win = "C:" + bs + "Users" + bs + "pat" + bs + "Desktop"
        posix = "/home/" + "pat" + "/x"
        mail = "pat" + "@" + "mail.com"
        self.assertTrue(HOME.search(win) and HOME.search(win).group(1) == "pat")
        self.assertTrue(HOME.search(posix))
        self.assertTrue(EMAIL.search(mail))
        self.assertFalse(EMAIL.search("@staticmethod and @unittest.skipIf(x)"))

    def test_no_absolute_machine_path_of_the_author_in_the_package(self):
        for path in all_files():
            if os.path.relpath(path, PKG).startswith(".."):
                continue
            low = text_of(path).lower()
            for needle in ("appdata", "onedrive", "downloads" + chr(92), "documents" + chr(92) + "github"):
                self.assertNotIn(needle, low, (needle, rel(path)))


# ---------------------------------------------------------------------------------------------------------------
# the zip and the precheck
# ---------------------------------------------------------------------------------------------------------------
def build_zip(dest):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for dp, dns, fns in os.walk(PKG):
            dns[:] = sorted(d for d in dns if d != "__pycache__")
            for fn in sorted(fns):
                full = os.path.join(dp, fn)
                arc = "share-safe-renders/" + os.path.relpath(full, PKG).replace(os.sep, "/")
                info = zipfile.ZipInfo(arc, date_time=(2026, 10, 12, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                zf.writestr(info, read_bytes(full))


class TestZipAndPrecheck(unittest.TestCase):
    def test_zip_has_one_top_level_folder_with_skill_md_at_its_root(self):
        with tempfile.TemporaryDirectory() as td:
            z = os.path.join(td, "share-safe-renders.zip")
            build_zip(z)
            with zipfile.ZipFile(z) as zf:
                names = zf.namelist()
                self.assertEqual({n.split("/")[0] for n in names}, {"share-safe-renders"})
                self.assertIn("share-safe-renders/SKILL.md", names)
                self.assertFalse([n for n in names if n.endswith((".pyc", ".DS_Store")) or "__pycache__" in n])
                self.assertFalse([i for i in zf.infolist() if (i.external_attr >> 16) & 0o170000 == 0o120000])
                self.assertLess(sum(i.file_size for i in zf.infolist()), 5 << 20)
            self.assertLess(os.path.getsize(z), 1 << 20)

    @unittest.skipUnless(os.path.exists(PRECHECK), "tools/agensi_precheck_v3.py is not in this checkout (it lives outside packages/ and tests/)")
    def test_precheck_gate_zero_fail_and_the_only_warns_are_the_explained_ones(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "p.json")
            p = subprocess.run([sys.executable, "-I", PRECHECK, PKG, "--json", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            doc = json.loads(read_text(out))
            self.assertEqual(p.returncode, 0, p.stdout.decode())
            self.assertEqual([f for f in doc["findings"] if f["severity"] == "FAIL"], [])
            warns = sorted((f["file"], f["label"].split(" x")[0]) for f in doc["findings"] if f["severity"] == "WARN")
            self.assertEqual(warns, [("scripts/make_demo.py", "process spawn"), ("scripts/scan.py", "process spawn")])
            z = os.path.join(td, "share-safe-renders.zip")
            build_zip(z)
            p2 = subprocess.run([sys.executable, "-I", PRECHECK, z], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p2.returncode, 0, p2.stdout.decode())
            self.assertIn("RELEASE GATE: OK - 0 FAIL, 2 WARN", p2.stdout.decode())

    def test_the_precheck_would_catch_a_planted_credential_pattern(self):
        if not os.path.exists(PRECHECK):
            self.skipTest("tools/agensi_precheck_v3.py is not in this checkout")
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "x-skill")
            os.makedirs(d)
            body = "---\nname: x-skill\ndescription: Does a thing. Use when asked. Do not use for other things.\n---\n" + "text " * 100 + "\n"
            with open(os.path.join(d, "SKILL.md"), "w") as fh:
                fh.write(body + "xo" + "xb-1\n")
            p = subprocess.run([sys.executable, "-I", PRECHECK, d], stdout=subprocess.PIPE)
            self.assertEqual(p.returncode, 1)
            self.assertIn("credential pattern", p.stdout.decode())


if __name__ == "__main__":
    unittest.main()
