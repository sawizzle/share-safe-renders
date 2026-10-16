#!/usr/bin/env python3
# get_skill_sim.py - simulate the answers that give an agent a skill as text, with nothing installed (no skill folder).
# Test helper: no network, no ffmpeg, standard library only. It copies no text of any real service: the shapes are the
# measured ones (2026-10-15), the words around them are neutral filler.
#
# Shapes it builds from a package folder (a folder that holds SKILL.md):
#   first answer   a short listing-like header (name, price, description, compatibility, limitations, a permissions JSON,
#                  tags, creator), the SKILL.md text inline, then an index of every other file, one line each:
#                  "- `<skill>/<path>` (<size> KB)" with the size in KiB and one decimal, and one closing sentence that
#                  names how to load one file
#   file answer    "## File: <skill>/<path> (from <Display Name>)", a blank line, then the exact text of the file
#   P1             a host-saved file answer: a plain-text file that holds exactly the file answer
#   P2             a host-saved file answer: a JSON file that holds a list with one {"type": "text", "text": <file answer>}
#   old shape      (the shape before 2026-10-15) one answer with SKILL.md inline and every other file as a block:
#                  "### File: <skill>/<path>", a blank line, a plain triple-backtick fence line, the file text, a line
#                  break and a closing fence line; blocks separated by a blank line, the last one with no final newline
# <skill> is the name of the package folder; <Display Name> is the first "# " heading of SKILL.md.
#
# Command line:
#   python -I get_skill_sim.py <package_dir> <out_dir>
#     writes into <out_dir> (it must not exist yet, and must not be inside the package folder):
#       fake_get_skill.py      a stand-in for the tool that gives a skill as text (the package is stored inside it):
#                                python fake_get_skill.py                       prints the first answer
#                                python fake_get_skill.py --file <skill>/<path> prints the file answer (<path> alone works too)
#                              A result longer than 30,000 characters is not printed. Like an agent's host, the stand-in
#                              writes it to a new file in <out_dir>/saved/ (P2 JSON when it is over 50,000 characters, P1 plain
#                              text otherwise) and prints only a short message with that file's path. This saves more results
#                              than a real host would, on purpose: a Bash tool cuts long output.
#       old_shape_answer.txt   the old-shape answer for the same package
# Exit codes: 0 written, 2 bad arguments, no SKILL.md, an output folder that exists, or one inside the package.
import base64
import json
import os
import re
import sys
import zlib

FENCE = "```"
INLINE_LIMIT = 30000          # longer results are saved to a file by the stand-in (and by real hosts, at a size of their own)
JSON_OVER = 50000             # saved results over this length are saved as P2 JSON, shorter ones as P1 plain text
OLD_HEADER = ("# {name}\n\nSimulated answer of a tool that returns a skill as text. Test helper, not a real service.\n\n---\n\n"
              "## SKILL.md\n\nThe SKILL.md text follows.\n\n")
OLD_MIDDLE = "\n\n---\n\n## Other files\n\nThe other files of the skill follow, one block per file.\n\n"
FIRST_TEMPLATE = ("# {display}\n\nSimulated first answer of a tool that gives a skill as text. Test helper, not a real service.\n\n"
                  "**Price:** Free\n\n## Description\n{description}\n\n## Compatibility\nSimulated: not stated.\n\n"
                  "## Known Limitations\n- Simulated: not stated.\n\n## Permissions\n{permissions}\n\n**Tags:** simulated\n\n"
                  "## Creator\n**Simulator** (test helper)\n\n---\n\n## SKILL.md\n\n{skill_md}\n\n---\n\n## Files in this skill\n\n"
                  "{index}\n\nLoad a file with fake_get_skill.py --file <path> when SKILL.md tells you to.")


def package_files(package_dir):
    """Relative posix paths of every file in the package except SKILL.md, in sorted order."""
    found = []
    for folder, names, files in os.walk(package_dir):
        names[:] = sorted(n for n in names if n != "__pycache__")
        for file in files:
            if file.endswith((".pyc", ".pyo")):
                continue
            rel = os.path.relpath(os.path.join(folder, file), package_dir).replace(os.sep, "/")
            if rel != "SKILL.md":
                found.append(rel)
    return sorted(found)


def read_text(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8")


def skill_name(package_dir):
    return os.path.basename(os.path.abspath(package_dir).rstrip("\\/"))


def display_name(package_dir):
    """The first '# ' heading of SKILL.md, or the folder name in title case."""
    text = read_text(os.path.join(package_dir, "SKILL.md"))
    m = re.search(r"^# (.+)$", text.split("\n---\n", 1)[-1], re.M)
    return m.group(1).strip() if m else skill_name(package_dir).replace("-", " ").title()


def description(package_dir):
    m = re.search(r"^description: (.*)$", read_text(os.path.join(package_dir, "SKILL.md")), re.M)
    return m.group(1).strip() if m else "Simulated: no description."


def index_line(package_dir, rel):
    size = os.path.getsize(os.path.join(package_dir, *rel.split("/")))
    return "- `%s/%s` (%.1f KB)" % (skill_name(package_dir), rel, size / 1024.0)


def first_answer(package_dir):
    """The first answer: listing-like header, SKILL.md inline, the file index and the closing sentence."""
    permissions = json.dumps({"hosts": [], "notes": "Simulated.", "tools": ["terminal", "file_read", "file_write"]}, indent=2)
    return FIRST_TEMPLATE.format(display=display_name(package_dir), description=description(package_dir), permissions=permissions,
                                 skill_md=read_text(os.path.join(package_dir, "SKILL.md")).rstrip("\n"),
                                 index="\n".join(index_line(package_dir, rel) for rel in package_files(package_dir)))


def header(package_dir, rel):
    return "## File: %s/%s (from %s)" % (skill_name(package_dir), rel, display_name(package_dir))


def file_answer(package_dir, rel):
    """The answer for one file: the header line, a blank line, then the exact text of the file."""
    return header(package_dir, rel) + "\n\n" + read_text(os.path.join(package_dir, *rel.split("/")))


def saved_p1(answer):
    """The plain-text form a host saves (P1): exactly the answer, as UTF-8 bytes."""
    return answer.encode("utf-8")


def saved_p2(answer, ensure_ascii=False):
    """The JSON form a host saves (P2): a list with one {"type": "text", "text": ...} object, as UTF-8 bytes."""
    return json.dumps([{"type": "text", "text": answer}], indent=2, ensure_ascii=ensure_ascii).encode("utf-8")


def old_block(name, rel, text, fence=FENCE):
    return "### File: %s/%s\n\n%s\n%s\n%s" % (name, rel, fence, text, fence)


def old_shape(package_dir):
    """The old-shape answer (before 2026-10-15): SKILL.md inline, then one block per other file."""
    package_dir = os.path.abspath(package_dir)
    name = skill_name(package_dir)
    skill = read_text(os.path.join(package_dir, "SKILL.md"))
    blocks = [old_block(name, rel, read_text(os.path.join(package_dir, *rel.split("/")))) for rel in package_files(package_dir)]
    return OLD_HEADER.format(name=name) + skill.rstrip("\n") + OLD_MIDDLE + "\n\n".join(blocks)


FAKE_TOOL = '''#!/usr/bin/env python3
# fake_get_skill.py - a stand-in, written by get_skill_sim.py, for a tool that gives a skill as text. No network.
#   python fake_get_skill.py                         the first answer: a listing-like header, SKILL.md and the file index
#   python fake_get_skill.py --file <skill>/<path>   the answer for one file: a header line, a blank line, the exact file
# A result longer than %(inline)d characters is not printed. Like an agent's host, the stand-in writes it to a new file in
# saved/ next to this script (JSON when it is over %(json_over)d characters, plain text otherwise) and prints a short message
# with that file's path instead.
import base64, json, os, sys, time, zlib
STORE = json.loads(zlib.decompress(base64.b64decode("".join("""
%(store)s
""".split()))).decode("utf-8"))
INLINE, JSON_OVER = %(inline)d, %(json_over)d


def emit(text):
    if len(text) <= INLINE:
        sys.stdout.buffer.write(text.encode("utf-8"))
        return
    saved = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved")
    os.makedirs(saved, exist_ok=True)
    big = len(text) > JSON_OVER
    path = os.path.join(saved, "result-%%d.%%s" %% (time.time_ns(), "json" if big else "txt"))
    data = json.dumps([{"type": "text", "text": text}], indent=2, ensure_ascii=False) if big else text
    with open(path, "xb") as handle:
        handle.write(data.encode("utf-8"))
    if big:
        message = "Output too large (%%.1fKB). Full output saved to: %%s\\n" %% (len(data.encode("utf-8")) / 1024.0, path)
    else:
        message = "Result (%%s characters across %%s lines) is too long to show; output saved to: %%s (plain text)\\n" %% (
            format(len(text), ","), format(text.count("\\n") + 1, ","), path)
    sys.stdout.buffer.write(message.encode("utf-8"))


def main(argv):
    if not argv:
        emit(STORE["first"])
        return 0
    if len(argv) != 2 or argv[0] != "--file":
        sys.stderr.write("usage: python fake_get_skill.py [--file <skill>/<path>]\\n")
        return 2
    rel = argv[1][len(STORE["skill"]) + 1:] if argv[1].startswith(STORE["skill"] + "/") else argv[1]
    if rel not in STORE["files"]:
        sys.stdout.buffer.write(("No file %%s in this skill. The file index in the first answer lists its files.\\n" %% argv[1]).encode("utf-8"))
        return 0
    emit("## File: %%s/%%s (from %%s)\\n\\n" %% (STORE["skill"], rel, STORE["display"]) + STORE["files"][rel])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def fake_tool_source(package_dir):
    """The source of fake_get_skill.py for a package: the first answer and every file, compressed inside it."""
    store = {"skill": skill_name(package_dir), "display": display_name(package_dir), "first": first_answer(package_dir),
             "files": {rel: read_text(os.path.join(package_dir, *rel.split("/"))) for rel in package_files(package_dir) + ["SKILL.md"]}}
    blob = base64.b64encode(zlib.compress(json.dumps(store, sort_keys=True).encode("utf-8"), 9)).decode("ascii")
    lines = "\n".join(blob[i:i + 100] for i in range(0, len(blob), 100))
    return FAKE_TOOL % {"store": lines, "inline": INLINE_LIMIT, "json_over": JSON_OVER}


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: python -I get_skill_sim.py <package_dir> <out_dir>\n")
        return 2
    package_dir, out_dir = argv
    if not os.path.isfile(os.path.join(package_dir, "SKILL.md")):
        sys.stderr.write("error: %s has no SKILL.md\n" % package_dir)
        return 2
    try:
        inside = os.path.commonpath([os.path.abspath(package_dir), os.path.abspath(out_dir)]) == os.path.abspath(package_dir)
    except ValueError:  # another drive on Windows
        inside = False
    if inside:
        sys.stderr.write("error: the output folder must not be inside the package folder\n")
        return 2
    if os.path.lexists(out_dir):
        sys.stderr.write("error: the output folder must not exist yet: %s\n" % out_dir)
        return 2
    os.makedirs(out_dir)
    tool = os.path.join(out_dir, "fake_get_skill.py")
    with open(tool, "xb") as handle:
        handle.write(fake_tool_source(package_dir).encode("utf-8"))
    old = old_shape(package_dir)
    with open(os.path.join(out_dir, "old_shape_answer.txt"), "xb") as handle:
        handle.write(old.encode("utf-8"))
    print("wrote %s: the stand-in tool for %s (%d files in its index) and old_shape_answer.txt (%d characters, %d file blocks)"
          % (out_dir, skill_name(package_dir), len(package_files(package_dir)), len(old), len(package_files(package_dir))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
