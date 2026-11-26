"""The translator for tools that read their command line with Ruby's OptionParser (wpscan and the like): the extra
arguments an agent passes, read into the operations the table decides. Software, holds no rule.

    read_ruby_options("--no-update --throttle 200 -e vp -o out.txt", schema)          # schema of wpscan
        -> {("use", "wpscan_options", "--update=false"), ("use", "wpscan_options", "--throttle"),
            ("limit", "rate", 5.0), ("use", "wpscan_options", "--enumerate"), ...}

The reader takes the forms the tool reads alike and nothing more (measured against the tool's own parser): an exact long
name, `--name value` or `--name=value`; `--no-name` for a switch declared `--[no-]name`; an exact short name, `-x value`
or `-xVALUE`; an option whose value is optional (`--enumerate [OPTS]`) takes the next word when it does not start with
`-` (`-e vp`), as OptionParser does. Refused, never guessed: a beginning of a name (OptionParser completes it, to
one option or another), short options grouped, a short letter the tool does not declare (OptionParser tries it as the
beginning of a long name), a word that is not an option, `--` and `-` alone, a value that starts with `-`, a number not
in plain decimal, and any character a shell reads: only letters, digits, `._:/,=@+%-` and the space pass.

`schema["options"]` maps each long name to `[takes a value: 0, 1 or "optional", kind, [short names and aliases]]`;
`schema["negatable"]` lists the `--[no-]name` switches, read as the uses `--name=true` and `--name=false`;
`schema["containers"]` sends an option to a container other than `schema["container"]` (one that asks a person). Kinds:
`url` (a web address, read on the table's scope), `uri` (a path on the target, or a web address read on the scope),
`domains` (a comma list of names on the scope), `read`, `write` (a file or folder in the table's folders), `list` (a
comma list, or a file when the value names one: a value with `/` must be in the read folders), `int`, `rate_ms`
(milliseconds between requests: counted as `rate` of 1000 over it), `value`. With `schema["rate_required"]`, a call that
states no wait is read as the use `(no rate stated)`, which no table opens; `schema["require"]` names uses a call must
make (`--update=false`), else `(<use> not stated)`.
"""
import os

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"
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


def _plain(name, v):
    if not (v == "0" or (v.isdigit() and v[0] != "0")):
        raise ValueError(f"{name} takes a number in plain decimal: {v!r}")
    return int(v)


def _value(name, kind, v, schema, ops, seen):
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    if v.startswith("-"):
        raise ValueError(f"{name}: a value that starts with '-' is read as an option: {v!r}")
    if kind == "url":
        ops |= read_target_url(v, scope)
    elif kind == "uri":
        if "://" in v or v.startswith("//"):
            ops |= read_target_url(v, scope)
    elif kind == "domains":
        for item in v.split(","):
            if not item or not any(c.isalpha() for c in item.rsplit(".", 1)[-1]):
                raise ValueError(f"{name}: a comma list of domain names: {v!r}")
            ops |= read_target(item, scope)
    elif kind in ("read", "write"):
        if not v:
            raise ValueError(f"{name}: a file, not nothing")
        ops.add((kind, _folder(v, paths), ""))
    elif kind == "list":
        if "/" in v:
            ops.add(("read", _folder(v, paths), ""))
    elif kind == "int":
        _plain(name, v)
    elif kind == "rate_ms":
        seen[name] = _plain(name, v)


def read_ruby_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    longs, box, boxes = schema["options"], schema["container"], schema.get("containers", {})
    negatable = set(schema.get("negatable", ()))
    short = {s[1:]: k for k, v in longs.items() for s in v[2] if not s.startswith("--")}
    alias = {s[2:]: k for k, v in longs.items() for s in v[2] if s.startswith("--")}
    words, ops, i, seen = text.split(), set(), 0, {}

    def take(name, attached):
        nonlocal i
        takes, kind = longs[name][0], longs[name][1]
        opt, where = "--" + name, boxes.get(name, box)
        if takes == 0:
            if attached is not None:
                raise ValueError(f"{opt} takes no value")
            ops.add(("use", where, f"{opt}=true" if name in negatable else opt))
            return
        ops.add(("use", where, opt))
        if attached is None and takes == 1:
            if i >= len(words):
                raise ValueError(f"{opt} takes a value")
            attached = words[i]
            i += 1
        elif attached is None and i < len(words) and not words[i].startswith("-"):   # an optional value: the next word
            attached = words[i]
            i += 1
        if attached is not None:
            _value(opt, kind, attached, schema, ops, seen)

    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--") or not w.startswith("-"):
            raise ValueError(f"a word that is not an option: {w!r}")
        if w.startswith("--"):
            name, eq, value = w[2:].partition("=")
            if name.startswith("no-") and name[3:] in negatable and not eq:
                ops.add(("use", box, f"--{name[3:]}=false"))
                continue
            name = alias.get(name, name)
            if name not in longs:
                raise ValueError(f"an option the table does not know (a beginning of a name is not read): --{name}")
            take(name, value if eq else None)
            continue
        c, rest = w[1], w[2:]
        if c not in short:
            raise ValueError(f"a short option the table does not know: -{c}")
        name = short[c]
        if longs[name][0] == 0 and rest:
            raise ValueError(f"short options are not read grouped: {w!r}")
        take(name, rest or None)
    rate = schema.get("rate")
    if rate:
        ms = seen.get("--" + rate)
        if ms:
            ops.add(("limit", "rate", 1000.0 / ms))
        elif schema.get("rate_required"):
            ops.add(("use", box, NO_RATE))
    for use in schema.get("require", ()):
        if ("use", box, use) not in ops:
            ops.add(("use", box, f"({use} not stated)"))
    return ops
