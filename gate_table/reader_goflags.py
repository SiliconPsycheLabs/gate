"""The translator for tools that read their command line with goflags (ProjectDiscovery's katana, subfinder and the
like): the extra arguments an agent passes, read into the operations the table decides. Software, holds no rule.

    read_goflags_options("-fs fqdn -rl 50 -o out.txt", schema)   # schema of katana
        -> {("use", "katana_options", "-field-scope"), ("use", "katana_options", "-rate-limit"),
            ("limit", "rate", 50.0), ("use", "katana_options", "-output"), ("write", "/root/engagement", "")}

goflags sits on Go's `flag` package, and the reader follows it (measured against each tool's own parser): every flag
has a long name and often a short one, `-name` and `--name` are the same; `-name=value` or `-name value`, where a flag
that takes a value takes the next word whatever it is; a flag that takes no value is `-name` or `-name=true|false`; list
flags split their value on commas. `schema["options"]` is the tool's own flag table (stored with the tables, made by
`pentest/goflags_table.py`); `schema["kinds"]` names, by long name, the flags whose value is not a plain value;
`schema["container"]` is the table's container that says which flags are open. Kinds: `target` (each item read by the
target translator on the table's scope), `web_target` (each item a web address ending in `/`, then read on the scope:
the tool reads a value that is a file's name as a list of targets, and such an address is never a file's name), `read`,
`write` (each item a file in the table's folders), `rate` (requests per second), `rate_minute` (per minute), `int`,
`value`.

What the tool does when nothing is said can be required (`schema["require"]`: a flag, the values it must have, the
value the tool takes by default; anything else is read as the use `(<flag> <value>)`, which no table opens) and the rate
is derived (`schema["rate"]`: a per-minute limit when given, else the per-second one, else the default; 0
means no limit and is read as the use `(no rate stated)`).
Refused, never guessed: a word that is not a flag (Go stops reading flags there), `--` and `-` alone, a flag the schema
does not know, a number not in plain decimal, and any character a shell reads: only letters, digits, `._:/,=@+%-` and
the space pass.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target
except ImportError:
    from reader_target import read_target

NO_RATE = "(no rate stated)"
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_BOOL = {"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"}
_TRUE = {"1", "t", "T", "TRUE", "true", "True"}
_WEB = re.compile(r"^https?://[^,/ ]+(/[^, ]*)?/$")


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


def _number(name, value):
    if not (value == "0" or (value.isdigit() and value[0] != "0")):
        raise ValueError(f"-{name} takes a number in plain decimal: {value!r}")
    return int(value)


def read_goflags_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    flags, kinds, box = schema["options"], schema.get("kinds", {}), schema["container"]
    short = {v["short"]: k for k, v in flags.items() if v["short"]}
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    words, ops, i, seen = text.split(), set(), 0, {}
    if schema.get("all_positional"):        # Go stops reading flags at the first word that is not one, and the
        for w in words:                     # server's line already began with one: every word is a positional
            if w.startswith("-"):
                raise ValueError(f"{w!r}: after the server's first word the tool reads no flag; it would be a target")
            ops |= read_target(w, scope)
        return ops
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not a flag: {w!r} (the tool would stop reading flags there)")
        body = w[2:] if w.startswith("--") else w[1:]
        word, eq, value = body.partition("=")
        name = word if word in flags else short.get(word)
        if name is None:
            raise ValueError(f"a flag the table does not know: -{word}")
        ops.add(("use", box, "-" + name))
        if not flags[name]["takes"]:
            if eq and value not in _BOOL:
                raise ValueError(f"-{name} is true or false: {value!r}")
            seen[name] = value if eq else "true"
            continue
        if not eq:
            if i >= len(words):
                raise ValueError(f"-{name} takes a value")
            value = words[i]
            i += 1
        seen[name] = value
        kind = kinds.get(name, "value")
        items = value.split(",") if flags[name]["comma"] or flags[name]["file"] else [value]
        for v in items:
            if kind == "target":
                ops |= read_target(v, scope)
            elif kind == "web_target":
                if not _WEB.match(v):
                    raise ValueError(f"-{name}: a web address ending in / (the tool reads a value that is a file's name "
                                     f"as a list of targets): {v!r}")
                ops |= read_target(v, scope)
            elif kind in ("read", "write"):
                if v in ("", "-") or "://" in v:
                    raise ValueError(f"-{name}: a file, not standard input, nothing or a web address: {v!r}")
                ops.add((kind, _folder(v, paths), ""))
            elif kind in ("int", "rate", "rate_minute"):
                _number(name, v)
    for req in schema.get("require", []):
        value = seen.get(req["flag"], req["default"])
        if value not in req["values"]:
            ops.add(("use", box, f"({req['flag']} {value})"))
    rate = schema.get("rate")
    if rate:                            # as katana: a per-minute limit when given, else per second, else the default
        minute = [int(seen[n]) for n, k in kinds.items() if k == "rate_minute" and n in seen]
        second = [int(seen[n]) for n, k in kinds.items() if k == "rate" and n in seen]
        per_second = minute[0] / 60.0 if minute and minute[0] > 0 else second[0] if second else rate["default"]
        if per_second <= 0:
            ops.add(("use", box, NO_RATE))
        else:
            ops.add(("limit", "rate", float(per_second)))
    return ops
