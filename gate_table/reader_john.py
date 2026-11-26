"""The translator for John the Ripper's extra arguments (jumbo), read into the operations the table decides. Software,
holds no rule.

    read_john_options("--wordlist=words.txt --rules=Jumbo --pot=res/j.pot hashes.txt", schema)
        -> {("use", "john_options", "--wordlist"), ("read", "/root/engagement", ""), ("use", "john_options", "--rules"),
            ("use", "john_options", "--pot"), ("write", "/root/engagement", ""), ...}

John reads its command line with its own parser (src/getopt.c, opt_find), and the reader follows it (measured against
john itself): `-name` and `--name` are the same option; a beginning of a name is the first option in John's list that
starts with it, and it is ambiguous (refused by john) unless that first one is a beginning of every other that matches
(`--si` is `--single`, `--pr` is refused); `--no-name` negates; the value is attached only, after the first `=` or `:`
(`--wordlist=FILE`, `--wordlist:FILE`); a word that does not start with `-` is a password file to load. An option that
takes a value never takes the next word: `--wordlist words.txt` is the wordlist of the settings plus a password file.
`schema["options"]` is John's list, in its order: `[name, takes a value: 0, 1 or 2 for an optional one, negatable]`;
`schema["kinds"]` gives an option's kind: `read`, `write` (a file in the table's folders), `read_list` (a comma list
of files), `int` (plain decimal), `value`; `schema["positional"]` is the kind of a word that is not an option.
Refused, never guessed: an ambiguous or unknown beginning, `-` and `--` alone (John reads them as nothing), a value on
an option that takes none, a missing value, `--no-` on an option that is not negatable, a number not in plain decimal,
and any character a shell reads: only letters, digits, `._:/,=@+%-` and the space pass.
"""
import os

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")


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


def _find(word, options):
    """John's opt_find: the option a word names, whether it is negated, and its value (None when there is none)."""
    name = word[1:]
    if name.startswith("-"):
        name = name[1:]
    negated = name.startswith("no-")
    if negated:
        name = name[3:]
    cut = [k for k in (name.find("="), name.find(":")) if k >= 0]
    value = None
    if cut:
        k = min(cut)
        value = name[k + 1:] or None
        name = name[:k]
    length, found = len(name), None
    for entry in options:
        opt = entry[0]
        if negated and opt.startswith("no-") and opt[:length + 3] == "no-" + name:   # an option named no-...
            name, length, negated = "no-" + name, length + 3, False
        if length <= len(opt) and opt[:length] == name[:length]:
            if found is None:
                found = entry
                if length == len(opt):
                    break
            elif not opt.startswith(found[0]):
                raise ValueError(f"{word!r}: a beginning of more than one option")
    if found is None or not name:
        raise ValueError(f"{word!r}: an option john does not have")
    return found, negated, value


def read_john_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    box, kinds, paths = schema["container"], schema.get("kinds", {}), schema.get("paths", {})
    ops = set()
    for w in text.split():
        if w in ("-", "--") or w.startswith("--no-") and len(w) == 5:
            raise ValueError(f"{w!r} alone is not read")
        if not w.startswith("-"):
            kind = schema.get("positional")
            if kind not in ("read", "write"):
                raise ValueError(f"a word that is not an option: {w!r}")
            ops.add((kind, _folder(w, paths), ""))
            continue
        (name, takes, negatable), negated, value = _find(w, schema["options"])
        opt = "--" + name
        if negated and not negatable:
            raise ValueError(f"--no-{name}: not an option john negates")
        if negated and value is not None:
            raise ValueError(f"--no-{name} takes no value")
        if takes == 0 and value is not None:
            raise ValueError(f"{opt} takes no value")
        if takes == 1 and value is None and not negated:
            raise ValueError(f"{opt} takes a value, attached with = (john never takes the next word)")
        ops.add(("use", box, f"{opt}=false" if negated else opt))
        if value is None:
            continue
        if value.startswith("-"):
            raise ValueError(f"{opt}: a value that starts with '-': {value!r}")
        kind = kinds.get(name, "value")
        if kind in ("read", "write"):
            ops.add((kind, _folder(value, paths), ""))
        elif kind == "read_list":
            for item in value.split(","):
                if not item:
                    raise ValueError(f"{opt}: an empty item in {value!r}")
                ops.add(("read", _folder(item, paths), ""))
        elif kind == "int":
            if not (value == "0" or (value.isdigit() and value[0] != "0")):
                raise ValueError(f"{opt} takes a number in plain decimal: {value!r}")
    return ops
