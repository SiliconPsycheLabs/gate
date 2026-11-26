"""The gobuster translator: the extra command-line arguments an agent passes to gobuster, read into the operations the
table decides. Software, holds no rule.

    read_gobuster_options("-x php,html -t 20 -o out.txt", schema)
        -> {("use", "gobuster_options", "--extensions"), ("use", "gobuster_options", "--threads"),
            ("use", "gobuster_options", "--output"), ("write", "/root/engagement", "")}

gobuster reads its command line with cobra and pflag, and the reader follows them (measured against gobuster's own
parser): `--name value` or `--name=value`, where a flag that takes a value takes the next word whatever it is; a short
flag `-o value`, `-ovalue` or `-o=value`; short flags that take no value may be grouped (`-kqz`), and the last of a
group may take one (`-ko out.txt`); a flag that takes no value is `--name` or `--name=true|false` (also 1, 0, t, f, T, F,
TRUE, FALSE, True, False); a flag given twice keeps its last value, `-H` keeps all. `schema["options"]` maps each long
name to `[takes_a_value, kind, short]` (the union of the `dir`, `vhost` and `fuzz` modes, whose flags never disagree);
whether a flag is allowed is the table's `gobuster_options` container. Kinds: `url` (read by the target translator on
the table's scope), `read`, `write` (one file in the table's folders), `int`, `duration`, `value`.
Other tools on pflag share this reader: `schema["require"]` names switches a call must give (trivy's offline ones;
`--name=false` is not the switch), `schema["container"]` names their container, `schema["positional"]` the
kind of a word that is not a flag when the tool takes such words (gau's domains), and `target` is a kind too.
Refused, never guessed: a word that is not a flag when the tool takes none (pflag would skip it and keep reading), `--` and
`-` alone, a flag the schema does not know, a number not in plain decimal (pflag also reads `0x10`, `010`, `1_000`), a
duration not written as a number and a unit, a wordlist read from standard input (`-`), and any character a shell reads
(the server pastes the arguments into a shell line unquoted): only letters, digits, `._:/,=@+%-` and the space pass.

**A rate may be required** (`schema["rate_required"]`, the engagement's choice). gobuster has no rate option: its rate
is its threads (`-t`, 10 when not given) divided by the wait each thread makes between requests (`--delay`), so threads
over delay is counted as `rate` (requests per second), and without `--delay` it is read as the use `(no rate stated)`, which
no table opens.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"     # a use no table opens: the engagement requires a rate
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_FALSE = {"0", "f", "F", "FALSE", "false", "False"}
_BOOL = {"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"}
_DURATION = re.compile(r"^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$")


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


def _value(name, kind, value, schema, ops, seen):
    seen[name] = value
    if kind == "target":
        ops |= read_target(value, {"containers": schema.get("targets", [])})
    elif kind == "url":
        ops |= read_target_url(value, {"containers": schema.get("targets", [])})
    elif kind in ("read", "write"):
        if value in ("", "-"):
            raise ValueError(f"--{name}: a file, not standard input or nothing")
        ops.add((kind, _folder(value, schema.get("paths", {})), ""))
    elif kind == "int":
        if not (value == "0" or (value.isdigit() and value[0] != "0")):
            raise ValueError(f"--{name} takes a number in plain decimal: {value!r}")
    elif kind == "duration":
        if not _DURATION.match(value):
            raise ValueError(f"--{name} takes a duration such as 1500ms or 2s: {value!r}")


def read_gobuster_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return _rate(_required(set(), schema), {}, schema)
    if not isinstance(text, str):
        raise ValueError("gobuster options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"gobuster options with a character they do not have: {''.join(bad)!r}")
    known = schema["options"]
    short = {v[2]: k for k, v in known.items() if len(v) > 2 and v[2]}
    words, ops, i, seen = text.split(), set(), 0, {}

    box = schema.get("container", "gobuster_options")

    def use(name, value=None):
        if value is not None and value in _FALSE and name in schema.get("require", ()):
            ops.add(("use", box, f"--{name}=false"))      # a required switch turned off is not the switch
            return
        ops.add(("use", box, "--" + name))

    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--"):
            raise ValueError(f"a word that is not a flag: {w!r}")
        if not w.startswith("-"):
            if not schema.get("positional"):
                raise ValueError(f"a word that is not a flag: {w!r}")
            _value("positional", schema["positional"], w, schema, ops, seen)   # pflag keeps reading after it
            continue
        if w.startswith("--"):
            name, eq, value = w[2:].partition("=")
            if name not in known:
                raise ValueError(f"a flag the table does not know: --{name}")
            takes, kind = known[name][0], known[name][1]
            if not takes:
                if eq and value not in _BOOL:
                    raise ValueError(f"--{name} is true or false: {value!r}")
                use(name, value if eq else None)
                continue
            if not eq:
                if i >= len(words):
                    raise ValueError(f"--{name} takes a value")
                value = words[i]
                i += 1
            use(name)
            _value(name, kind, value, schema, ops, seen)
            continue
        group = w[1:]
        while group:
            c, rest = group[0], group[1:]
            if c not in short:
                raise ValueError(f"a short flag the table does not know: -{c}")
            name = short[c]
            takes, kind = known[name][0], known[name][1]
            if not takes:
                if rest.startswith("="):
                    if rest[1:] not in _BOOL:
                        raise ValueError(f"-{c} is true or false: {rest[1:]!r}")
                    use(name, rest[1:])
                    break
                use(name)
                group = rest
                continue
            if rest.startswith("=") and len(rest) > 1:
                value = rest[1:]
            elif rest.startswith("="):
                raise ValueError(f"-{c}= with nothing after it")
            elif rest:
                value = rest
            elif i < len(words):
                value = words[i]
                i += 1
            else:
                raise ValueError(f"-{c} takes a value")
            use(name)
            _value(name, kind, value, schema, ops, seen)
            break
    return _rate(_required(ops, schema), seen, schema)


def _required(ops, schema):
    """Switches the call must give (`schema["require"]`: trivy's offline switches); without one, the use
    `(--name not given)`, which no table opens."""
    box = schema.get("container", "gobuster_options")
    for name in schema.get("require", ()):
        if ("use", box, "--" + name) not in ops:
            ops.add(("use", box, f"(--{name} not given)"))
    return ops


_UNIT = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


def _seconds(text):
    return sum(float(n) * _UNIT[u] for n, _, u in re.findall(r"([0-9]+(\.[0-9]+)?)(ns|us|ms|s|m|h)", text))


def _rate(ops, seen, schema):
    """Threads over delay, counted as `rate`; with a rate required, a call without a delay above 0 does not pass.
    gobuster's flags are `--threads` (10) and `--delay` (a duration); another tool names its own in `schema["rate"]`
    (dalfox: `--worker`, 100, and `--delay` in milliseconds)."""
    spec = schema.get("rate") or {"threads": "threads", "threads_default": "10", "delay": "delay", "unit": None}
    raw = seen.get(spec["delay"])
    if raw is None or raw == "":
        delay = 0.0
    elif spec["unit"] == "ms":
        delay = int(raw) / 1000.0 if raw.isdigit() else 0.0
    else:
        delay = _seconds(raw)
    if delay > 0:
        ops.add(("limit", "rate", int(seen.get(spec["threads"], spec["threads_default"])) / delay))
    elif schema.get("rate_required"):
        ops.add(("use", schema.get("container", "gobuster_options"), NO_RATE))   # no delay: gobuster sends with no cap
    return ops
