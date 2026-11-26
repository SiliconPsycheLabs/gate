"""The translator for exiftool's extra arguments, read into the operations the table decides. Software, holds no rule.

    read_exiftool_options("-j -G1 -Make -x ThumbnailImage words.jpg", schema)
        -> {("use", "exiftool_options", "-json"), ("use", "exiftool_options", "-groupheadings"),
            ("use", "exiftool_options", "(tag)"), ("use", "exiftool_options", "-exclude"),
            ("read", "/root/engagement", "")}

exiftool reads each word that starts with `-` by testing it, without the dash, against its options in order (measured
against exiftool itself); a word no option takes is the name of a tag to print (`-Make`, `-EXIF:Model`, `--Make` to
leave one out), and a word with `=` or `<` writes a tag. `schema["options"]` is exiftool's own list of tests, in its
order (taken from its source): `["re", pattern, ignore case]`, `["eq", text]` (the word in lower case) or `["eqs",
text]`, each option with the name the table uses for it; `schema["open"]` maps the names of the options that only print
to whether they take the next word (1, or 2 when it is a folder, read in the table's folders). Every other option is a
use no table opens (the names of the options that write files, read more arguments from a file, run Perl code, follow a
settings file). Words that are not options are files, read in the table's folders. Refused, never guessed: `=`, `<` or
`>` in a word (a tag written or copied), `-` and `--` alone, a tag name with a character a tag does not have, a value
that starts with `-`, and any character a shell reads: only letters, digits, `._:/,=@+%-` and the space pass (and `=`,
`<` never in an option).
"""
import os
import re

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_TAG = re.compile(r"^-?[A-Za-z0-9_][A-Za-z0-9_:-]*$")


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


def _option(body, options):
    low = body.lower()
    for opt in options:
        for test in opt["tests"]:
            kind, text = test[0], test[1]
            if kind == "re" and re.match(text, body, re.I if test[2] else 0):
                return opt
            if kind == "eq" and low == text or kind == "eqs" and body == text:
                return opt
    return None


def read_exiftool_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    box, open_, paths = schema["container"], schema["open"], schema.get("paths", {})
    words, ops, i = text.split(), set(), 0
    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--"):
            raise ValueError(f"{w!r} alone is not read")
        if not w.startswith("-"):
            ops.add(("read", _folder(w, paths), ""))
            continue
        body = w[1:]
        if "=" in body or "<" in body:
            raise ValueError(f"{w!r} writes a tag")
        opt = _option(body, schema["options"])
        if opt is None:
            if not _TAG.match(body):
                raise ValueError(f"{w!r}: not a tag name exiftool reads")
            ops.add(("use", box, "(tag)"))
            continue
        name = opt["name"]
        ops.add(("use", box, "-" + name))
        if open_.get(name):
            if i >= len(words):
                raise ValueError(f"-{name} takes a value")
            value = words[i]
            i += 1
            if value.startswith("-"):
                raise ValueError(f"-{name}: a value that starts with '-': {value!r}")
            if open_[name] == 2:                        # a folder named on the line (-i): in the table's folders
                ops.add(("read", _folder(value, paths), ""))
    return ops


def read_exiftool_flag(text, schema):
    """A field the server writes after a dash (`-{output_format}`, `-{tags}`): read as that one word."""
    if not isinstance(text, str):
        raise ValueError("the field is a string")
    if not text:
        return set()
    if " " in text or text.startswith("-"):
        raise ValueError(f"one word, without its dash: {text!r}")
    return read_exiftool_options("-" + text, schema)
