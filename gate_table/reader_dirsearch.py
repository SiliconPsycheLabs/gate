"""The dirsearch translator: the extra command-line arguments an agent passes to dirsearch, read into the operations the
table decides. Software, holds no rule.

    read_dirsearch_options("-x 404 -o out.txt --max-rate 50", schema)
        -> {("use", "dirsearch_options", "--exclude-status"), ("use", "dirsearch_options", "--output-file"),
            ("write", "/root/engagement", ""), ("use", "dirsearch_options", "--max-rate"), ("limit", "rate", 50.0)}

dirsearch reads its command line with Python's optparse, and the reader follows it (measured against dirsearch's own
`parse_options`): `--name value` or `--name=value`, where an option that takes a value takes the next word whatever it is;
a short option `-o value` or `-ovalue` (optparse keeps an `=` after a short option as part of the value); short options
that take no value may be grouped (`-rqf`), the last of a group may take one. `schema["options"]` maps each option, long
and short alike, to `[takes_a_value, kind, long_name]`; whether one is allowed is the table's `dirsearch_options`
container (by long name). Kinds: `url` (read by the target translator on the table's scope), `ip` (an address the
requests are sent to, read as a target), `wordlists` (a comma list of files read), `read`, `write` (one file in the
table's folders), `rate` (requests per second, counted as `rate`), `int`, `float`, `value`.
Refused, never guessed: a word that is not an option (optparse would keep it aside and dirsearch ignore it), `--` and
`-` alone, an abbreviated long option (optparse completes a unique prefix: the reader takes only whole names), an
option the schema does not know, a number not in plain decimal (optparse also reads `0x10`, and `010` as octal), and any
character a shell reads (the server pastes the arguments into a shell line unquoted): only letters, digits,
`._:/,=@+%-` and the space pass.

**A rate may be required** (`schema["rate_required"]`, the engagement's choice): then a call that does not state one, or
states 0 (which the tool reads as no limit), is read as the use `(no rate stated)`, which no
table opens.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"     # a use no table opens: the engagement requires a rate
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_FLOAT = re.compile(r"^[0-9]+(\.[0-9]+)?$")


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


def _value(name, kind, value, schema, ops):
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    if kind == "url":
        ops |= read_target_url(value, scope)
    elif kind == "ip":
        ops |= read_target(value, scope) if value.strip() else set()
    elif kind in ("wordlists", "read", "write"):
        for v in value.split(",") if kind == "wordlists" else [value]:
            if v in ("", "-"):
                raise ValueError(f"--{name}: a file, not standard input or nothing")
            ops.add(("write" if kind == "write" else "read", _folder(v, paths), ""))
    elif kind in ("int", "rate"):
        if not (value == "0" or (value.isdigit() and value[0] != "0")):
            raise ValueError(f"--{name} takes a number in plain decimal: {value!r}")
        if kind == "rate":
            ops.add(("limit", "rate", float(value)))
    elif kind == "float":
        if not _FLOAT.match(value):
            raise ValueError(f"--{name} takes a number such as 2 or 0.5: {value!r}")


def read_dirsearch_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return _required(set(), schema)
    if not isinstance(text, str):
        raise ValueError("dirsearch options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"dirsearch options with a character they do not have: {''.join(bad)!r}")
    known = schema["options"]
    words, ops, i = text.split(), set(), 0

    def take(opt, attached):
        nonlocal i
        takes, kind, name = known[opt]
        ops.add(("use", "dirsearch_options", "--" + name))
        if not takes:
            return
        if attached is None:
            if i >= len(words):
                raise ValueError(f"{opt} takes a value")
            attached = words[i]
            i += 1
        _value(name, kind, attached, schema, ops)

    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not an option: {w!r}")
        if w.startswith("--"):
            opt, eq, value = w.partition("=")
            if opt not in known:
                raise ValueError(f"a dirsearch option the table does not know (written whole): {opt}")
            if eq and not known[opt][0]:
                raise ValueError(f"{opt} takes no value")
            take(opt, value if eq else None)
            continue
        group = w[1:]
        while group:
            opt, rest = "-" + group[0], group[1:]
            if opt not in known:
                raise ValueError(f"a dirsearch short option the table does not know: {opt}")
            if not known[opt][0]:
                take(opt, None)
                group = rest
                continue
            take(opt, rest or None)
            break
    return _required(ops, schema)


def _required(ops, schema):
    """With a rate required, a call states one above 0 (0 is no limit for dirsearch)."""
    if schema.get("rate_required") and not any(o[0] == "limit" and o[1] == "rate" and o[2] > 0 for o in ops):
        ops.add(("use", "dirsearch_options", NO_RATE))    # no rate stated, or 0: no cap
    return ops
