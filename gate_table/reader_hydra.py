"""The hydra translator: the extra command-line arguments an agent passes to hydra, read into the operations the table
decides. Software, holds no rule.

    read_hydra_options("-s 2222 -S -f -o found.txt", schema)
        -> {("use", "hydra_options", "-s"), ("use", "hydra_options", "-S"), ("use", "hydra_options", "-f"),
            ("use", "hydra_options", "-o"), ("write", "/root/engagement", "")}

hydra reads its command line with getopt (`hIq64Rrde:vVl:fFg:L:p:OP:o:b:M:C:t:T:m:w:W:s:SUux:yc:K` in hydra 9.5), and the
reader follows it (measured against hydra itself): short options only, grouped (`-vVf`), an option that takes a value
takes the rest of its word (`-s2222`) or the next word whatever it is (`-m -x`). The server and the service come after
the extra arguments on the line the server composes (`hydra ... <extra> <target> <service>`), so a word that is not an
option, or an option left without its value at the end, would change which word hydra takes as the server: both are
refused. `schema["options"]` maps each option letter to `[takes_a_value, kind]`; whether one is allowed is the table's
`hydra_options` container. Kinds: `target`, `url` (read on the table's scope; a later one replaces the server's),
`read`, `write` (one file in the table's folders), `port` (1 to 65535), `int`, `value`. `schema["containers"]` sends an
option to another container (one that asks a person); `schema["closed_values"]` names values that are a use of their
own (dotdotpwn's `-M COPY`); `schema["delay_default_ms"]` is the wait the tool makes when not told.
Other getopt tools share this reader (dirb): `schema["container"]` names their container; `schema["delay_ms"]` names the
option that sets a wait in milliseconds between requests of a single-threaded tool, counted as a `rate` of 1000 over it
(none, or 0, is the use `(no rate stated)` when the engagement requires a rate).
Refused, never guessed: a word that is not an option, `--` and `-` alone, a long option, an option the schema does not
know, a number not in plain decimal, a file read from standard input (`-`), and any character a shell reads (the server
pastes the arguments into a shell line unquoted): only letters, digits, `._:/,=@+%-` and the space pass.
"""
import os

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

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


def read_hydra_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return set()
    if not isinstance(text, str):
        raise ValueError("hydra options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    known, paths = schema["options"], schema.get("paths", {})
    box = schema.get("container", "hydra_options")
    words, ops, i, seen = text.split(), set(), 0, {}
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--") or w.startswith("--"):
            raise ValueError(f"a word that is not an option: {w!r} (the tool would take it as a target or a value)")
        group = w[1:]
        while group:
            c, rest = group[0], group[1:]
            if c not in known:
                raise ValueError(f"a hydra option the table does not know: -{c}")
            takes, kind = known[c]
            ops.add(("use", schema.get("containers", {}).get(c, box), "-" + c))
            if not takes:
                group = rest
                continue
            if rest:
                value = rest
            elif i < len(words):
                value = words[i]
                i += 1
            else:
                raise ValueError(f"-{c} takes a value (left without one, it would take the next word on the line)")
            seen[c] = value
            if value.upper() in schema.get("closed_values", {}).get(c, []):
                ops.add(("use", box, f"-{c}={value.upper()}"))       # a value that is a use of its own (COPY, MOVE)
            if kind == "target":
                ops |= read_target(value, {"containers": schema.get("targets", [])})
            elif kind == "url":
                ops |= read_target_url(value, {"containers": schema.get("targets", [])})
            elif kind in ("read", "write"):
                if value in ("", "-"):
                    raise ValueError(f"-{c}: a file, not standard input or nothing")
                ops.add((kind, _folder(value, paths), ""))
            elif kind in ("int", "port"):
                if not (value == "0" or (value.isdigit() and value[0] != "0")):
                    raise ValueError(f"-{c} takes a number in plain decimal: {value!r}")
                if kind == "port" and not 1 <= int(value) <= 65535:
                    raise ValueError(f"-{c}: a port from 1 to 65535: {value!r}")
            break
    spec = schema.get("delay_ms")                       # a single-threaded tool that waits N ms between requests (dirb -z)
    if spec:
        if spec not in seen and schema.get("delay_default_ms"):
            seen[spec] = str(schema["delay_default_ms"])    # dotdotpwn waits 300 ms when not told
        if seen.get(spec, "0") not in ("", "0"):
            ops.add(("limit", "rate", 1000.0 / int(seen[spec])))
        elif schema.get("rate_required"):
            ops.add(("use", box, "(no rate stated)"))
    return ops
