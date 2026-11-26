"""The feroxbuster translator: the extra command-line arguments an agent passes to feroxbuster, read into the operations
the table decides. Software, holds no rule.

    read_ferox_options("-x php html -t 20 -o out.txt --rate-limit 50", schema)
        -> {("use", "ferox_options", "--extensions"), ("use", "ferox_options", "--threads"),
            ("use", "ferox_options", "--output"), ("write", "/root/engagement", ""),
            ("use", "ferox_options", "--rate-limit"), ("limit", "rate", 50.0)}

feroxbuster reads its command line with clap, and the reader follows it (measured against feroxbuster's own parser):
`--name value`, `--name=value`, `-o value`, `-ovalue`, `-o=value`; short flags that take no value may be grouped
(`-kqn`, `-vvv`), the last of a group may take one. `schema["options"]` maps each long name to `[values, kind, short]`
(a fourth item, false, when the flag has only its short form) where values is 0 (none), 1 (one), `many` (one or more:
clap takes every following word until one that starts with `-`, so `-w a.txt /etc/shadow` reads two wordlists) or
`any` (zero or more), and a comma splits a value into several where feroxbuster does (`delimited` kinds). Whether a
flag is allowed is the table's `ferox_options` container. Kinds:
- `target`: an address, a network or a name, read on the table's scope; `url`: a web address requests go to, read
  by the target translator on the table's scope;
- `wordlist`: a file read, or a web address the wordlist is fetched from (read on the scope);
- `data`: a request body, where `@path` is a file read;
- `read`, `write`: one file in the table's folders; `rate`: requests per second, counted as `rate`;
- `int`: a number; `value`: any other value.
Another clap tool uses the same reader with `schema["container"]`; `schema["closed_values"]` names values that are a use
of their own (rustscan's `--scripts custom`, read as the use `--scripts=custom`).
Refused, never guessed: a word no flag takes (feroxbuster has no positional argument), `--`, a flag the schema does not
know, a value that starts with `-` (clap reads it as a flag), a number not in plain decimal, a file read from standard
input (`-`), and any character a shell reads (the server pastes the arguments into a shell line unquoted): only letters,
digits, `._:/,=@+%-` and the space pass.

**The rate.** `--rate-limit` is per directory scan, and feroxbuster runs up to `--scan-limit` scans at once (no limit
when not given), so the rate counted as `rate` is rate-limit times scan-limit, or rate-limit alone with
`--no-recursion`. Without both it has no cap: when the engagement requires a rate (`schema["rate_required"]`), that
call, and one that states no rate at all, is read as the use `(no rate stated)`, which no table opens.
"""
import os

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"     # a use no table opens: the engagement requires a rate
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


def _file(name, value, paths):
    if value in ("", "-"):
        raise ValueError(f"--{name}: a file, not standard input or nothing")
    return _folder(value, paths)


def _number(name, value):
    if not (value == "0" or (value.isdigit() and value[0] != "0")):
        raise ValueError(f"--{name} takes a number in plain decimal: {value!r}")
    return int(value)


def _value(name, kind, value, schema, ops):
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    items = value.split(",") if name in schema.get("delimited", ()) else [value]
    for v in items:
        if kind == "target":
            ops |= read_target(v, scope)
        elif kind == "url":
            ops |= read_target_url(v, scope)
        elif kind == "wordlist":
            if "://" in v:
                ops |= read_target_url(v, scope)
            else:
                ops.add(("read", _file(name, v, paths), ""))
        elif kind == "data":
            if v.startswith("@"):
                ops.add(("read", _file(name, v[1:], paths), ""))
        elif kind in ("read", "write"):
            ops.add((kind, _file(name, v, paths), ""))
        elif kind == "rate":
            _number(name, v)
        elif kind == "int":
            _number(name, v)


def read_ferox_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return _rate(set(), {}, schema)
    if not isinstance(text, str):
        raise ValueError("feroxbuster options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"feroxbuster options with a character they do not have: {''.join(bad)!r}")
    known = schema["options"]
    box = schema.get("container", "ferox_options")
    short = {v[2]: k for k, v in known.items() if v[2]}
    words, ops, i, seen = text.split(), set(), 0, {}

    def take(name, first):
        """The values of one occurrence: the attached one, then (for many and any) every following word that is not a
        flag."""
        nonlocal i
        n, kind = known[name][0], known[name][1]
        vals = [] if first is None else [first]
        if n == 1 and first is None:
            if i >= len(words) or words[i].startswith("-"):
                raise ValueError(f"--{name} takes a value")
            vals.append(words[i])
            i += 1
        if n in ("many", "any"):
            while i < len(words) and not words[i].startswith("-"):
                vals.append(words[i])
                i += 1
            if n == "many" and not vals:
                raise ValueError(f"--{name} takes a value")
        if n == 0 and first is not None:
            raise ValueError(f"--{name} takes no value")
        ops.add(("use", box, "--" + name))
        seen[name] = vals[-1] if vals else ""
        for v in vals:                                  # a value that is a use of its own (rustscan --scripts custom)
            if v.lower() in schema.get("closed_values", {}).get(name, []):
                ops.add(("use", box, f"--{name}={v.lower()}"))
        for v in vals:
            if v.startswith("-"):
                raise ValueError(f"--{name}: a value that starts with '-' is read as a flag: {v!r}")
            _value(name, kind, v, schema, ops)

    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word no flag takes: {w!r} (the tool takes no positional word here)")
        if w.startswith("--"):
            name, eq, value = w[2:].partition("=")
            if name not in known or not (known[name][3:] or [True])[0]:     # a flag that has only its short form
                raise ValueError(f"a flag the table does not know: --{name}")
            take(name, value if eq else None)
            continue
        group = w[1:]
        while group:
            c, rest = group[0], group[1:]
            if c not in short:
                raise ValueError(f"a short flag the table does not know: -{c}")
            name = short[c]
            if known[name][0] in (0, "count"):
                ops.add(("use", box, "--" + name))
                seen[name] = ""
                if rest.startswith("="):
                    raise ValueError(f"-{c} takes no value")
                group = rest
                continue
            if rest.startswith("="):
                rest = rest[1:]
                if not rest:
                    raise ValueError(f"-{c}= with nothing after it")
            take(name, rest or None)
            break
    return _rate(ops, seen, schema)


def _rate(ops, seen, schema):
    """rate-limit times scan-limit (or rate-limit alone without recursion), counted as `rate`; or, for a tool whose
    parallel requests each wait a delay in milliseconds (`schema["rate"]`: x8), their number times 1000 over it."""
    spec = schema.get("rate")
    if spec:
        delay = int(seen[spec["delay_ms"]]) if seen.get(spec["delay_ms"]) else 0
        parallel = 1
        for name in spec["parallel"]:
            parallel *= int(seen[name]) if seen.get(name) else spec["defaults"][name]
        if delay > 0:
            ops.add(("limit", "rate", parallel * 1000.0 / delay))
        elif schema.get("rate_required"):
            ops.add(("use", schema.get("container", "ferox_options"), NO_RATE))
        return ops
    if "rate-limit" not in schema["options"]:
        return ops                                      # another clap tool, with no rate of this kind
    rate = int(seen["rate-limit"]) if seen.get("rate-limit") else 0
    scans = 1 if "no-recursion" in seen else (int(seen["scan-limit"]) if seen.get("scan-limit") else 0)
    if rate > 0 and scans > 0:
        ops.add(("limit", "rate", float(rate * scans)))
    elif schema.get("rate_required"):                   # no rate-limit, or no limit on the scans: no cap
        ops.add(("use", schema.get("container", "ferox_options"), NO_RATE))
    return ops
