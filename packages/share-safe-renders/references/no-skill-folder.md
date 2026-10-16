# No skill folder: load the scripts and run them from a checked temporary folder

Read this only when the skill reached you as text and nothing was installed: the answer that gave you `SKILL.md` lists the other files in an index (as `share-safe-renders/<path>`), each file is loaded on its own, and there is no `share-safe-renders` folder on disk. If the folder exists, ignore this file.

The route in short: make a fresh private folder in the system temp folder with the program of section 2, load only the files your task needs (section 1), let the program write each one into the folder (only with exactly the published length and SHA-256) and check the folder, run the scripts as `SKILL.md` says, and delete the folder at the end. A script goes into the folder only as the text that loading it gave you (through `put`, or written as shown and then accepted by `check`): never write one from memory, never change one, never cut one out of a text with other tools, and never run one before `check` has printed its `OK` lines.

## 1. The files each task needs

Neither script imports the other or any other file of the skill, and neither opens a file of the skill while it runs: `scan.py` reads only the paths you pass it and writes only the `--json` report you name, and `make_demo.py` writes only the folder you name. Each set below was written by the program in section 2 into an otherwise empty folder and run from there. Size is what you load and write, in KB of 1,000 bytes (the file index counts 1,024 bytes to a KB, so it shows `scripts/scan.py` as 141.3 KB).

| Task | Script to run | Files to load and write | Size |
| --- | --- | --- | --- |
| Check renders, workflow JSON or a folder for leaks, and re-scan the re-exported copies (steps 2 and 5 of `SKILL.md`) | `scan.py` | `scripts/scan.py` | 145 KB |
| Make the six demo files and scan them (Try it in `README.md`) | `make_demo.py`, `scan.py` | `scripts/make_demo.py`, `scripts/scan.py` | 171 KB |

The references, the examples and `README.md` are never needed on disk: when `SKILL.md` sends you to one of them, load it and read it as text. Run `make_demo.py` from its file in the folder, not from standard input: its last line names the `scan.py` next to it, without `-I -B` and with plain paths unquoted: add `-I -B` and double quotes around both paths, as in `SKILL.md`.

## 2. The program

The program is plain Python (3.9 or newer, standard library only). It reads no environment variable of its own, starts no other program, deletes nothing, and is given to Python on standard input, so it is never saved as a file. It has three modes:

- `new` makes a fresh folder named `ssr_` and 8 more characters directly in the system temp folder, with an empty `scripts` folder in it (on Linux and other POSIX systems both are open to your user only), checks what it made and prints `OK folder: <FOLDER>`. It takes no folder of yours: every run makes a new one, and it never writes into a folder that already existed. It uses the real path of the temp folder (with no link in it), and on Linux and other POSIX systems it refuses when the temp folder, or any folder above it, belongs to another user (root excepted) or is open to other users' writes without the sticky bit.
- `put <FOLDER> <SAVED> <NAME>...` reads one saved result of a file request, finds in it the exact copy of each NAME and writes that into the folder. It checks the folder first, writes nothing unless every NAME is found with exactly the published length and SHA-256, never replaces a file, and checks the whole folder again after writing.
- `check <FOLDER> <NAME>...` checks the folder the way `new` leaves it: a name of the form `new` uses, a place directly in the temp folder, a real folder and not a link (on POSIX systems also yours and open to you only, with the temp folder checked as `new` checks it), the `scripts` folder and nothing but files of the program's table, each with exactly the published length and SHA-256, and every NAME you give. It prints `OK <NAME> verified (<n> bytes)` for each file, then `OK <N> verified files and nothing else in <FOLDER>`. It checks what is there, not who made it: a folder of your own made by hand the same way passes too, so use only the folder that `new` printed.

NAME is a path inside the skill exactly as in the program's table (`scripts/scan.py`); the path as the file index shows it (`share-safe-renders/scripts/scan.py`) works too. Success is the `OK` line, not the exit code alone: a program that never ran also exits 0 and prints nothing. A refusal is one line on standard error that starts with `REFUSED: ` (exit 1); a wrong command line prints the usage line (exit 2).

```python
try:  # Skill file extractor. One try block: a copy cut short almost always ends in a SyntaxError or IndentationError; only the OK lines mean success.
 import hashlib, itertools, json, os, re, stat, sys, tempfile
 SKILL, PREFIX, TABLE = "share-safe-renders", "ssr_", {
  "scripts/make_demo.py": ("350340f308429156ea21622ed3c48a48" "d548653a32a3cc91a15eaf3cdf973726", 26418),
  "scripts/scan.py": ("da4e39b29fb3894dd040bb5939ea5f03" "ae72499041d6602e6768ebd941b6f2f2", 144720),
 }
 DIRS, POSIX, J = sorted({n.split("/")[0] for n in TABLE}), os.name != "nt", os.path.join
 HEAD = re.compile(r"^#{2,3} File: [^\r\n]*", re.M)
 def stop(why): sys.exit("REFUSED: " + why)
 def show(p): return str(p) if re.fullmatch(r"[\w .:/\x5c~+-]+", str(p), re.A) else ascii(str(p))
 def same(n, data): return (hashlib.sha256(data).hexdigest(), len(data)) == TABLE[n]
 def tempdir():  # the real path, no link in it; on POSIX it and every folder above it must be safe from other users
   t = p = os.path.realpath(tempfile.gettempdir())
   if os.path.samefile(t, os.getcwd()): stop("the working folder is the temp folder, or no temp folder is usable: change to another folder (such as your home folder) and run again")
   while POSIX:
     s = os.lstat(p)
     if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.geteuid()) or s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX: stop("other users can replace folders in " + show(p) + ", the temp folder or a folder above it")
     if p == os.path.dirname(p): break
     p = os.path.dirname(p)
   return t
 def entry(p, d):
   s = os.lstat(p)
   if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 1024: stop(show(p) + " is a link or junction")
   if not (stat.S_ISDIR if d else stat.S_ISREG)(s.st_mode): stop(show(p) + " is not a real " + ("folder" if d else "file"))
   if POSIX and s.st_uid != os.geteuid(): stop(show(p) + " belongs to another user")
   if POSIX and (s.st_mode & (0o077 if d else 0o002) or not d and s.st_nlink != 1): stop(show(p) + " is open to other users or has a hard link")
 def verify(arg, need=()):
   f = os.path.abspath(arg)
   if not re.fullmatch(re.escape(PREFIX) + "[a-z0-9_]{8}", os.path.basename(f)): stop(show(f) + " is not a folder that new makes")
   entry(f, True)
   if os.path.normcase(os.path.dirname(f)) != os.path.normcase(tempdir()): stop(show(f) + " is not directly in the temp folder")
   if sorted(os.listdir(f)) != DIRS: stop(show(f) + " must hold only " + ", ".join(DIRS))
   found = []
   for d in DIRS:
     entry(J(f, d), True)
     for n in sorted(d + "/" + x for x in os.listdir(J(f, d))):
       if n not in TABLE: stop(show(f) + " holds " + ascii(n) + " - run scripts with -B" * n.endswith("__pycache__"))
       entry(J(f, n), False)
       with open(J(f, n), "rb") as h:
         if not same(n, h.read(TABLE[n][1] + 1)): stop("%s is not the published file (%d bytes, published %d)" % (n, os.fstat(h.fileno()).st_size, TABLE[n][1]))
       found.append(n)
   if set(need) - set(found): stop("missing: " + ", ".join(sorted(set(need) - set(found))))
   return f, found
 def find(t, n):
   k = TABLE[n][1] + 99
   bodies = [t[:k], t.lstrip("\n")[:k]]
   for _, m in zip(range(4), re.finditer(r"^#{2,3} File: " + re.escape(SKILL + "/" + n) + r"(?: \(from [^\r\n]*\))?\r?(?![^\n])", t, re.M)):
     for b in {t[m.end() + 1:min(e, m.end() + k)] for e in [h.start() for _, h in zip(range(4), HEAD.finditer(t, m.end()))] + [len(t)]}:
       fence = re.fullmatch(r"\s*(\x60{3,})(?!\x60)[^\n]*\n(.*)\n\1\s*", b, re.S)
       bodies += [b[1:] if b[:1] == "\n" else b] + ([fence.group(2)] if fence else [])
   for c in (v for b in bodies for v in (b, b.rstrip("\n"), b.rstrip("\n") + "\n")):
     data = c.encode("utf-8", "surrogatepass")
     if same(n, data): return data
 def put(arg, saved, names):
   f, found = verify(arg)
   if not stat.S_ISREG(os.stat(saved).st_mode) or os.stat(saved).st_size > 16000000: stop(show(saved) + " is not a file of at most 16 MB")
   with open(saved, "rb") as h:
     texts = [h.read(16000001).decode("utf-8-sig", "replace")]
   try:
     doc = json.loads(texts[0], object_pairs_hook=lambda kv: texts.extend(v for _, v in kv if isinstance(v, str)))
   except (ValueError, RecursionError):
     doc = None
   texts += [doc] * isinstance(doc, str)
   todo = {n: next((d for x in texts for y in dict.fromkeys((x.replace("\r\n", "\n"), x)) for d in [find(y, n)] if d is not None), None) for n in names if n not in found}
   for n in [n for n in todo if todo[n] is None][:1]:
     heads = list(itertools.islice((m.group(0)[:99] for x in texts for m in HEAD.finditer(x)), 5))
     stop("%s holds no exact copy of %s; file headers in it: %s. Nothing was written." % (show(saved), n, ascii(heads)))
   for n, data in todo.items():
     with open(J(f, n), "xb", opener=lambda p, fl: os.open(p, fl, 0o600)) as h:
       h.write(data)
   verify(f, names)
   for n in names: print("OK %s verified (%d bytes)%s" % (n, TABLE[n][1], " - was already there" * (n in found)))
 def run(mode, args):
   if not TABLE or not (mode == "new" and not args or mode == "put" and len(args) > 2 or mode == "check" and args):
     sys.exit(print("usage: python -I -B - new | put FOLDER SAVED NAME... | check FOLDER [NAME...]", file=sys.stderr) or 2)
   i = 1 + (mode == "put")
   args[i:] = [a[len(SKILL) + 1:] if a.startswith(SKILL + "/") else a for a in args[i:]]
   bad = [n for n in args[i:] if n not in TABLE]
   if bad: stop("not a file of " + SKILL + ": " + ", ".join(map(ascii, bad)) + "; its files: " + ", ".join(sorted(TABLE)))
   if mode == "new":
     f = tempfile.mkdtemp(prefix=PREFIX, dir=tempdir())
     for d in DIRS: os.mkdir(J(f, d), 0o700)
     print("OK folder:", show(verify(f)[0]))
   elif mode == "put":
     put(args[0], args[1], args[2:])
   else:
     f, found = verify(args[0], args[1:])
     for n in found: print("OK %s verified (%d bytes)" % (n, TABLE[n][1]))
     print("OK %d verified files and nothing else in %s" % (len(found), show(f)))
 run((sys.argv + [""])[1], sys.argv[2:])
except (OSError, MemoryError) as e:
  sys.exit("REFUSED: the system refused: %s %s" % (type(e).__name__, str(e).encode("ascii", "backslashreplace").decode()))
```

The values in the program's table, for reading (each SHA-256 is written in two halves):

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `scripts/make_demo.py` | 26,418 | `350340f308429156ea21622ed3c48a48` `d548653a32a3cc91a15eaf3cdf973726` |
| `scripts/scan.py` | 144,720 | `da4e39b29fb3894dd040bb5939ea5f03` `ae72499041d6602e6768ebd941b6f2f2` |

## 3. Load, write and check

Every command gives the program to Python on standard input, unchanged, with the mode and its arguments after the `-`. Use `python3` or `py -3` in place of `python` as `SKILL.md` says. In bash or sh, the quoted `'EOF'` keeps the shell from changing the program:

```text
python -I -B - new <<'EOF'
<the program>
EOF
```

In Windows PowerShell, a here-string in single quotes does the same (the closing `'@` must start its line):

```text
@'
<the program>
'@ | python -I -B - new
```

`put` and `check` are given the program the same way, for example in bash and in PowerShell:

```text
python -I -B - put "<FOLDER>" "<SAVED>" scripts/scan.py <<'EOF'
<the program>
EOF
```

```text
@'
<the program>
'@ | python -I -B - check "<FOLDER>" scripts/scan.py
```

Every path goes into these commands in double quotes and follows "Names in commands" in `SKILL.md`. Use the folder exactly as the `OK folder:` line prints it.

1. **Make the folder.** Run `new` once, from a folder you trust, such as your home folder ("Where to run them" in `SKILL.md`), not from the system temp folder itself. The folder it prints is `<FOLDER>`, and it is `<SKILL_DIR>` in every command of `SKILL.md` from now on.
2. **Load a file.** For each file of your task (section 1), use the file request that the answer which gave you this skill names at its end, with the path exactly as its file index shows it (`share-safe-renders/scripts/scan.py`). The result is a header line (`## File: share-safe-renders/scripts/scan.py (from Share-Safe Renders)`), a blank line, and then the file.
3. **If the result was saved to a file** and you were told the file's path, that path is `<SAVED>`: run `put` with `<FOLDER>`, `<SAVED>` and the NAME. The saved file may be plain text or JSON; `put` reads both.
4. **If the result came back in the conversation,** write it exactly as shown (the header line, and the blank line after it, may each stay or go) with your file tool, never with a shell here-document or `echo`, to a new scratch file in a folder that only you can write (your own scratch or working folder; not the shared temp folder of a Linux or macOS machine, and not the user's project). Run `put` with that scratch file as `<SAVED>`, then delete the scratch file. `put` repairs the usual slips of such a copy (Windows line ends, a missing or extra final newline, a byte order mark) and writes only the published bytes. Writing the file straight to `<FOLDER>/scripts/<file>` and running `check` also works, but `check` accepts only the exact bytes: plain line ends and exactly one final newline.
5. **Check.** Run `check` with `<FOLDER>` and every NAME the task needs. Go on only when it prints an `OK` line for each file and then `OK <N> verified files and nothing else in <FOLDER>`, with N the number of files in section 1 for your task. Run a script only as a separate command, after you have read those lines: do not join it to `check` with `;` or `&&` (a command cut short, or an empty program, can exit 0 without printing an `OK` line). Run `check` again before every later run of a script, the re-scan in step 5 of `SKILL.md` included.

An older answer shape, with every file of the skill as a `### File:` block in one saved text, is also understood: run `put` once on that file with every NAME the task needs.

## 4. Run

Use the commands of `SKILL.md` unchanged, with `<FOLDER>` as `<SKILL_DIR>`, for example the scan of step 2:

```sh
python -I -B "<SKILL_DIR>/scripts/scan.py" "<PATH>" --json "<REPORT>"
```

The report is the same as from an installed folder (`scan.py` uses neither its own path nor its own name): it never prints the leaked text, only the class, the place, the length and a keyed hash. `-I` keeps Python from importing a module that sits next to the script, and `-B` keeps it from writing into the folder, so the folder stays as `check` left it. Do not put `<REPORT>`, the re-exported copies or the demo files in that folder: `check` refuses anything that is not a published file, and the folder is deleted at the end. A run with `--help` prints `usage: scan.py`; a run that prints no `RESULT:` line is the last row of the exit-code table in `SKILL.md`.

## 5. Delete

When the last scan is done (the re-scan of the copies in step 5 of `SKILL.md` included), delete `<FOLDER>` with your shell's own command for removing a folder and its contents, with the path in double quotes, and delete nothing else. Then list the folders in the temp folder whose names start with `ssr_`:

```sh
python -I -c "import os, tempfile; t = tempfile.gettempdir(); print(ascii(t)); print(sorted(n for n in os.listdir(t) if n.startswith('ssr_')))"
```

The name of `<FOLDER>` must not be in that list. Check it this way, not by testing the path you typed: a mistyped path makes a delete command and a test of that path both look fine, and a delete command can exit 0 on a path it could not remove. If another `ssr_` folder is listed, leave it and tell the user it is there. If a later step needs a file you did not write, load it and `put` it into the same folder before you delete it, or make another folder with `new` and delete every folder you made at the end.

Known issue: `new`, `put` and `check` print a path plainly only when it holds nothing but ASCII letters, digits, spaces and `. : / \ ~ + - _`. A path with any other character (often an accented letter in a Windows user name, but also an apostrophe as in O'Brien, `&`, parentheses or `$`) is printed as a quoted Python string with escapes, for example `'D:\\Caf\xe9 Temp\\ssr_ab12cd34'`, or between double quotes when the path holds an apostrophe. The real path is that string read as Python reads it: without the outer quotes, each doubled backslash written once, and each escape turned back into its letter (`\xe9` is the letter e with an acute accent). If you cannot turn it back with certainty, stop: nothing has run yet. Tell the user, and ask them to delete that `ssr_` folder in their temp folder (the command above prints the temp folder the same way).

## 6. When to stop

Stop and tell the user what was printed, and do not retry another way on your own, when anything is not as described: a `REFUSED:` line, no `OK` line, a Python error, a here-document warning, a result whose shape is not the one in section 3, or a message you do not understand. Give the program exactly as section 2 prints it: do not shorten, rewrite or reformat it. What the usual refusals mean:

| `REFUSED:` line | Meaning |
| --- | --- |
| `<NAME> is not the published file (<N> bytes, published <M>)` | A file in the folder differs from the published one. N minus M equal to the number of lines of the file means Windows line ends; 3 means a byte order mark; 1 or -1 means one final newline too many or missing; the same length means other bytes. Write it again through `put` (step 4); if that is refused too, stop. |
| `<SAVED> holds no exact copy of <NAME>; file headers in it: [...]. Nothing was written.` | The saved result is not that file, or it was cut short or changed. Load the file once more; if it is refused again, stop. |
| `the working folder is the temp folder, or no temp folder is usable: ...` | Run the command from another folder, such as your home folder. If Python finds no usable temp folder, it would use the working folder, so the program refuses and writes nothing: stop. |
| `other users can replace folders in <PATH>, the temp folder or a folder above it` | Linux and other POSIX systems: that folder belongs to another user (root excepted), or others may write to it without the sticky bit, so another account could swap the folder after `check`. Nothing was made or run. Stop and tell the user; this route cannot be used with that temp folder. |
| `... is not a folder that new makes`, `... is not directly in the temp folder` | Use the folder exactly as `new` printed it. |
| `<FOLDER> holds '<name>'`, `<FOLDER> must hold only scripts` | Something other than the published files is in the folder (`- run scripts with -B` after it means a `__pycache__` folder). Do not run anything; delete the folder and start again with `new`. |
| `the system refused: <KIND> <DETAILS>` | The operating system refused a read or a write, for example a path that does not exist. |

In bash, a command of section 3 that was cut short anywhere before the end of its closing `EOF` prints a shell error, a here-document warning, a Python error or no `OK` line (some cuts also leave it waiting until it is stopped): stop as above (the user may choose the PowerShell form instead). Do not use this route on a Windows machine whose temp folder, or a folder above it, other users can write (a `TEMP` such as a shared `C:\Temp`): on Windows the program does not read folder permissions, so it cannot tell that another account changed a file after `check`. On Linux and other POSIX systems it refuses such a temp folder itself (the `other users can replace folders in` row of the table above). On Windows the folder that `new` prints must be inside your own user folder (the folder `~` names in PowerShell; an account's own temp folder is there by default); if not, stop and tell the user.
