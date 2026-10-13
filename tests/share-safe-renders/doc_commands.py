# -*- coding: utf-8 -*-
"""Extract the command lines written in the package docs and run them for real, in a throw-away workspace.

A command in a doc is a line of a fenced ```sh / ```powershell / ```cmd block, or an inline `code span` that starts with
python, python3, py, ffmpeg or ffprobe. Placeholders in angle brackets are replaced by real paths:

    <SKILL_DIR>   a COPY of the package (so the tests prove it works without the tests next to it)
    <WORK>        a fresh folder that is not the skill folder (the README's "Try it" writes its files there)
    <PATH>        the demo folder          <REPORT>  a fresh report path       <COPY>  a demo file without findings
    <IN.png> <IN.jpg> <IN.mp4>  a demo file of that type        <OUT.png> <OUT.jpg> <OUT.mp4>  a new path in the workspace

An interpreter word (python, python3, py -3) is replaced by sys.executable, so the suite exercises the interpreter it runs
on; test_doc_commands separately runs the alias forms as written when they exist on the machine.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from _base import PKG, MAKE_DEMO, have_ffmpeg

COMMAND_WORDS = ("python", "python3", "py", "ffmpeg", "ffprobe")
SHELL_FENCES = ("sh", "bash", "powershell", "pwsh", "cmd", "bat")
WINDOWS_FENCES = ("powershell", "pwsh", "cmd", "bat")
PLACEHOLDER = re.compile(r"<(SKILL_DIR|WORK|PATH|REPORT|COPY|IN\.(?:png|jpg|mp4)|OUT\.(?:png|jpg|mp4))>")


class Command(object):
    def __init__(self, text, doc, kind, fence=""):
        self.text, self.doc, self.kind, self.fence = text, doc, kind, fence

    def __repr__(self):
        return "<%s %s %r>" % (self.doc, self.kind, self.text)

    @property
    def windows_form(self):
        return self.fence in WINDOWS_FENCES or "\\" in self.text or self.text.startswith("py -3")

    def argv_template(self):
        """Split into tokens without touching placeholders. Backslashes (Windows forms) survive."""
        if "\\" in self.text:
            toks = shlex.split(self.text, posix=False)
            return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t for t in toks]
        return shlex.split(self.text)


def extract(doc_name, text):
    out = []
    for m in re.finditer(r"```(\w*)\n(.*?)```", text, re.S):
        lang, body = m.group(1), m.group(2)
        if lang not in SHELL_FENCES:
            continue
        for line in body.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(Command(line, doc_name, "fenced", lang))
    stripped = re.sub(r"```\w*\n.*?```", "", text, flags=re.S)
    for m in re.finditer(r"`([^`\n]+)`", stripped):
        span = m.group(1).strip()
        words = span.split(" ")
        if words[0] in COMMAND_WORDS and set(words) - {"python", "python3", "py", "-3", "ffmpeg", "ffprobe"}:
            out.append(Command(span, doc_name, "inline"))     # a bare program name is a mention, not a command
    return out


def unknown_placeholders(cmd):
    """Angle-bracket words in a command that the workspace cannot fill."""
    out = []
    for tok in cmd.argv_template():
        for ph in re.findall(r"<[^<>\s]+>", tok):
            if not PLACEHOLDER.fullmatch(ph):
                out.append(ph)
    return out


def alias_works(alias):
    """True if `alias --version` (for example 'python3' or 'py -3') prints Python 3.9 or newer."""
    try:
        p = subprocess.run(alias.split() + ["--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    except OSError:
        return False
    m = re.match(rb"Python (\d+)\.(\d+)", p.stdout)
    return bool(p.returncode == 0 and m and (int(m.group(1)), int(m.group(2))) >= (3, 9))


class Workspace(object):
    """A temporary folder with a copy of the package, a demo folder, and an out/ folder for new files."""

    def __init__(self):
        self._td = tempfile.TemporaryDirectory(prefix="ssr_docs_")
        self.root = self._td.name
        self.skill_dir = os.path.join(self.root, "skill", "share-safe-renders")
        shutil.copytree(PKG, self.skill_dir, ignore=shutil.ignore_patterns("__pycache__"))
        self.work = os.path.join(self.root, "work")         # a different folder from the skill folder
        self.try_it = os.path.join(self.root, "try it work")         # <WORK> of the README (a space in its name, on purpose)
        os.makedirs(self.try_it)
        self.out = os.path.join(self.root, "out")
        os.makedirs(self.work)
        os.makedirs(self.out)
        self.demo = os.path.join(self.root, "demo")
        subprocess.run([sys.executable, "-I", "-B", MAKE_DEMO, self.demo], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=300)
        self._n = 0

    def close(self):
        self._td.cleanup()

    def new_path(self, ext):
        self._n += 1
        return os.path.join(self.out, "new_%d.%s" % (self._n, ext))

    def demo_file(self, ext):
        names = {"png": "01_png_api_key_and_username.png", "jpg": "06_jpeg_exif_gps.jpg",
                 "mp4": "05_mp4_prompt_tag_and_free_box.mp4"}
        return os.path.join(self.demo, names[ext])

    def subst(self, token):
        def one(m):
            key = m.group(1)
            if key == "SKILL_DIR":
                return self.skill_dir
            if key == "WORK":
                return self.try_it
            if key == "PATH":
                return self.demo
            if key == "REPORT":
                return self.new_path("json")
            if key == "COPY":
                return os.path.join(self.demo, "04_clean.png")
            kind, ext = key.split(".")
            return self.demo_file(ext) if kind == "IN" else self.new_path(ext)
        return PLACEHOLDER.sub(one, token)

    def argv(self, cmd):
        toks = cmd.argv_template()
        if toks[:2] == ["py", "-3"]:
            toks = toks[2:]
            head = [sys.executable]
        elif toks[0] in ("python", "python3", "py"):
            toks = toks[1:]
            head = [sys.executable]
        else:
            head = [toks[0]]
            toks = toks[1:]
        return head + [self.subst(t) for t in toks]

    def run(self, cmd, cwd=None, argv=None):
        argv = argv or self.argv(cmd)
        p = subprocess.run(argv, cwd=cwd or self.work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=300)
        return p.returncode, p.stdout.decode("utf-8", "replace"), argv


def needs_ffmpeg(cmd):
    return cmd.text.split(" ")[0] in ("ffmpeg", "ffprobe") or "mp4" in cmd.text.lower() and "ffmpeg" in cmd.text


_PILLOW_VERSION = []


def pillow_version():
    """The version string of the Pillow a child interpreter finds (for example '9.0.1'), or None when there is none.
    A child process without -I: Pillow often sits in a user site-packages that the suite's own `python -I` hides."""
    if not _PILLOW_VERSION:
        p = subprocess.run([sys.executable, "-c", "import PIL; print(PIL.__version__)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _PILLOW_VERSION.append(p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else None)
    return _PILLOW_VERSION[0]


def pillow_available():
    return pillow_version() is not None
