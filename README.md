# share-safe-renders

A free agent skill that finds what a render leaks before you share it. One standard-library Python scanner opens PNG, JPEG, MP4/MOV and ComfyUI workflow JSON files and reports API keys, secret-named fields, Discord and Slack webhook URLs, user names inside home-folder paths, e-mail addresses, LAN addresses, GPS coordinates, and secrets hidden where a text search does not look: bypassed ComfyUI nodes, JSON stored inside a string, compressed PNG chunks and hidden MP4 boxes.

It only reads the files you give it and writes one JSON report to a path you name. Its report never prints the text it found, only the class, the place, the length and a short keyed hash, so a file's metadata cannot put instructions into a report an agent reads. "Nothing found" is not a guarantee: the skill lists what it cannot see in `packages/share-safe-renders/references/known-misses.md`.

## Get it

- Copy `packages/share-safe-renders/` into your agent's skills folder (for Claude Code: `~/.claude/skills/`, or `.claude/skills/` inside one project), or run the scanner by hand without any agent, or
- get it from Agensi: https://agensi.io/skills/share-safe-renders

Needs Python 3.9 or newer. `ffprobe` on PATH is optional (a second witness for MP4/MOV tags); `ffmpeg` is needed only for the export commands in the skill's how-to page and for the MP4 in the demo. The skill's own [README](packages/share-safe-renders/README.md) and [SKILL.md](packages/share-safe-renders/SKILL.md) have the full instructions, the tested versions and the limits.

## Try it

From any empty working folder, with `<CHECKOUT>` standing for the path of this repository:

```
python -I -B "<CHECKOUT>/packages/share-safe-renders/scripts/make_demo.py" demo
python -I -B "<CHECKOUT>/packages/share-safe-renders/scripts/scan.py" demo --json demo_report.json
```

The first command writes six small synthetic files with invented secrets; the second scans them, prints the findings and exits 1.

## Tests

```
python -I -B -m unittest discover -s tests/share-safe-renders
```

The suite has 692 tests. Every test that cannot run on a given machine skips with a stated reason, and [tests/share-safe-renders/README.md](tests/share-safe-renders/README.md) says what skips where and on which operating systems, ffmpeg builds, Python and Pillow versions the suite was run. macOS was not tested.

## Licence

MIT OR Apache-2.0, at your option: see `LICENSE-MIT` and `LICENSE-APACHE`. No warranty.

The copy of the skill delivered through Agensi is under Agensi's buyer terms (a personal, non-transferable licence). The licence line inside `packages/share-safe-renders/README.md` describes that delivered copy, not this repository.
