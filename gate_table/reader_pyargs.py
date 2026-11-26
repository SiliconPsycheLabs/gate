"""The translator for tools that read their command line with Python's argparse or optparse (arjun, fierce, wafw00f,
smbmap and the like): the extra arguments an agent passes, read into the operations the table decides. Software, holds
no rule.

    read_pyargs_options("--rate-limit 20 --disable-redirects -oJ out.json", schema)   # schema of arjun
        -> {("use", "arjun_options", "rate_limit"), ("limit", "rate", 20.0), ("use", "arjun_options", "disable_redirects"),
            ("use", "arjun_options", "json_file"), ("write", "/root/engagement", "")}

The reader follows the two parsers (measured against each tool's own, by `pentest/py_parse.py`): `--name value` and
`--name=value`; a unique beginning of a long name stands for it; `-x value` and `-xvalue`; short flags that take no value
may be grouped (`-qr`); an option takes as many values as it declares (`nargs`: a number, `?` one if the next word is
not an option, `*` and `+` every following word that is not an option). `schema["options"]` is the tool's own table
(every option string to its `nargs` and `dest`, stored with the tables); the operations name the option by its `dest`,
so aliases are one; `schema["containers"]` sends a `dest` to a container of the table other than the default
(`schema["container"]`), such as one that asks a person; `schema["kinds"]` names the `dest`s whose values are not plain
values; `schema["positional"]` is the kind of a word that is not an option, when the tool takes such words (wafw00f's
targets), else such a word is refused. Kinds: `target` (an address or a name, read on the table's scope), `url` (a web
address, read on the scope), `read`, `write` (a file in the table's folders), `rate` (requests per second), `delay`
(seconds between requests: counted as `rate` of one over it), `int`, `value`.
What a tool does when nothing is said can be required (`schema["require"]`: a `dest` the line must set; else the use
`(<dest> not set)`, which no table opens). `schema["rate"]` (`workers`, `workers_default`, `delay`) names a tool whose
workers each wait `delay` seconds between requests: the rate is the last value of the one over the last of the other;
with no wait and `schema["rate_required"]`, the use `(no rate stated)`, which no table opens.
Refused, never guessed: `--` and `-` alone, an option the schema does not know or an ambiguous beginning, a value that
starts with `-`, a number not in plain decimal, and any character a shell reads: only letters, digits, `._:/,=@+%-` and
the space pass.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

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


def _value(dest, kind, v, schema, ops):
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    if v.startswith("-"):
        raise ValueError(f"{dest}: a value that starts with '-' is read as an option: {v!r}")
    if kind == "target":
        ops |= read_target(v, scope)
    elif kind == "url":
        ops |= read_target_url(v, scope)
    elif kind in ("read", "write"):
        if v in ("", "-"):
            raise ValueError(f"{dest}: a file, not standard input or nothing")
        ops.add((kind, _folder(v, paths), ""))
    elif kind in ("int", "rate"):
        if not (v == "0" or (v.isdigit() and v[0] != "0")):
            raise ValueError(f"{dest} takes a number in plain decimal: {v!r}")
        if kind == "rate":
            ops.add(("limit", "rate", float(v)) if int(v) > 0 else ("use", schema["container"], "(no rate stated)"))
    elif kind == "delay":
        if not _FLOAT.match(v):
            raise ValueError(f"{dest} takes a number such as 2 or 0.5: {v!r}")
        if float(v) > 0:
            ops.add(("limit", "rate", 1.0 / float(v)))


def _match(word, options, abbrev):
    if word in options:
        return word
    if abbrev and word.startswith("--"):
        hits = sorted({k for k in options if k.startswith(word) and k.startswith("--")})
        if len(hits) == 1:
            return hits[0]
    return None


def read_pyargs_options(text, schema):
    if isinstance(text, str) and not text.strip():
        text = ""
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    options, kinds = schema["options"], schema.get("kinds", {})
    box, boxes = schema["container"], schema.get("containers", {})
    words, ops, i, seen, last = text.split(), set(), 0, set(), {}

    def take(opt, attached):
        nonlocal i
        spec = options[opt]
        dest, nargs = spec["dest"], spec["nargs"]
        ops.add(("use", boxes.get(dest, box), dest))
        seen.add(dest)
        vals = [] if attached is None else [attached]
        if nargs == 0:
            if attached is not None:
                raise ValueError(f"{opt} takes no value")
            return
        if isinstance(nargs, int):
            while len(vals) < nargs:
                if i >= len(words):
                    raise ValueError(f"{opt} takes {nargs} value(s)")
                vals.append(words[i])
                i += 1
        elif nargs in ("?", "*", "+"):
            while (not vals or nargs in ("*", "+")) and i < len(words) and not words[i].startswith("-"):
                vals.append(words[i])
                i += 1
            if nargs == "+" and not vals:
                raise ValueError(f"{opt} takes a value")
        else:
            raise ValueError(f"{opt}: an option that takes the rest of the line is not read")
        for v in vals:
            _value(dest, kinds.get(dest, "value"), v, schema, ops)
        if vals:
            last[dest] = vals[-1]

    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--"):
            raise ValueError(f"{w!r} alone is not read")
        if not w.startswith("-"):
            if not schema.get("positional"):
                raise ValueError(f"a word that is not an option: {w!r}")
            _value("target", schema["positional"], w, schema, ops)
            continue
        word, eq, value = w.partition("=") if w.startswith("--") else (w, "", "")
        opt = _match(word, options, schema.get("allow_abbrev", True))
        if opt is not None:
            take(opt, value if eq else None)
            continue
        if w.startswith("--"):
            raise ValueError(f"an option the table does not know, or a beginning of more than one: {word}")
        group = w[1:]
        while group:                                        # -xVALUE, or grouped flags -qr
            opt, rest = "-" + group[0], group[1:]
            if opt not in options:
                raise ValueError(f"an option the table does not know: {opt}")
            if options[opt]["nargs"] == 0:
                take(opt, None)
                group = rest
                continue
            take(opt, rest or None)
            break
    for dest in schema.get("require", []):
        if dest not in seen:
            ops.add(("use", box, f"({dest} not set)"))
    rate = schema.get("rate")                           # workers that each wait N seconds between requests (xsser)
    if rate:
        delay = last.get(rate["delay"])
        if delay is not None and float(delay) > 0:
            workers = max(1, int(last.get(rate["workers"], rate["workers_default"])))
            ops.add(("limit", "rate", workers / float(delay)))
        elif schema.get("rate_required"):
            ops.add(("use", box, "(no rate stated)"))
    return ops
