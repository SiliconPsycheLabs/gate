"""The translator for extra arguments that a tool reads as more files to open, and nothing else. Software, holds no rule.

    read_files_options("t.txt res/a.bin", schema)  -> {("read", "/root/engagement", "")}

radare2 reads its options only before the file the server names (`r2 -q <binary> <extra>`); every word after it is one
more file it opens (measured against r2: `-A` there is a file named `-A`), and a word with a scheme is an I/O plugin
(`dbg:///bin/sh` runs a program under the debugger, `rap://`, `gdb://`, `http://` reach the network). Each word is read
as a file in the table's folders. Refused, never guessed: a `:` anywhere (every scheme has one), a word starting with
`-` or `@` or `=`, and any character a shell reads: only letters, digits, `._/,+%-` and the space pass.
"""
import os

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/,+%- ")


def _folder(path, paths):
    p = os.path.normpath(os.path.join(paths.get("cwd", "/"), path))
    best = None
    for c in paths.get("containers", []):
        if p == c or p.startswith(c.rstrip("/") + "/"):
            if best is None or len(c) > len(best):
                best = c
    if best is None:
        raise ValueError(f"{p} is outside every folder of the table")
    return best


def read_files_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"words with a character a file name here does not have: {''.join(bad)!r}")
    ops = set()
    for w in text.split():
        if w[0] in "-@=":
            raise ValueError(f"{w!r}: the tool opens it as a file; a file name here does not start with {w[0]!r}")
        ops.add(("read", _folder(w, schema.get("paths", {})), ""))
    return ops
