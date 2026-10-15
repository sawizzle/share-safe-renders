#!/usr/bin/env python3
# get_skill_sim.py - build a text file shaped like a saved answer that gives an agent a skill as text (nothing is
# installed, so there is no skill folder). Test helper; it needs no network and no ffmpeg.
# Purpose: try references/no-skill-folder.md and its snippet without any real service.
# Inputs:  a package folder (it holds SKILL.md) and the path of the file to write.
#            python -I get_skill_sim.py <package_dir> <out_file>
# Outputs: one UTF-8 text file with LF line ends: a short header, the SKILL.md text inline, then one block per other
#          file of the package, in sorted path order:  "### File: <package>/<path>", a blank line, a plain triple-
#          backtick fence line, the file text, a line break and a closing fence line. Blocks are separated by a blank
#          line and the LAST block has no line break after its closing fence. The fences are plain on purpose: the
#          markdown files of the package contain fenced code of their own. <package> is the name of the package folder.
# Exit codes: 0 written, 2 bad arguments, no SKILL.md, or an output path inside the package.
# The shape (SKILL.md inline, "### File: " blocks, plain fences, no newline after the last fence) is the shape of a real
# saved answer; the wording around the blocks is neutral filler and copies no text of any service.
import os
import sys

FENCE = "```"
HEADER = ("# {name}\n\nSimulated answer of a tool that returns a skill as text. Test helper, not a real service.\n\n---\n\n"
          "## SKILL.md\n\nThe SKILL.md text follows.\n\n")
MIDDLE = "\n\n---\n\n## Other files\n\nThe other files of the skill follow, one block per file.\n\n"


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


def block(name, rel, text, fence=FENCE):
    return "### File: %s/%s\n\n%s\n%s\n%s" % (name, rel, fence, text, fence)


def build(package_dir):
    """The simulated response for a package folder, as one string."""
    package_dir = os.path.abspath(package_dir)
    name = os.path.basename(package_dir.rstrip("\\/"))
    skill = read_text(os.path.join(package_dir, "SKILL.md"))
    blocks = [block(name, rel, read_text(os.path.join(package_dir, *rel.split("/")))) for rel in package_files(package_dir)]
    return HEADER.format(name=name) + skill.rstrip("\n") + MIDDLE + "\n\n".join(blocks)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: python -I get_skill_sim.py <package_dir> <out_file>\n")
        return 2
    package_dir, out_file = argv
    if not os.path.isfile(os.path.join(package_dir, "SKILL.md")):
        sys.stderr.write("error: %s has no SKILL.md\n" % package_dir)
        return 2
    try:
        inside = os.path.commonpath([os.path.abspath(package_dir), os.path.abspath(out_file)]) == os.path.abspath(package_dir)
    except ValueError:  # another drive on Windows
        inside = False
    if inside:
        sys.stderr.write("error: the output file must not be inside the package folder\n")
        return 2
    text = build(package_dir)
    with open(out_file, "wb") as handle:
        handle.write(text.encode("utf-8"))
    print("wrote %s: %d characters, %d file blocks" % (out_file, len(text), len(package_files(package_dir))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
