"""The translator for tools that read their command line with GNU getopt_long or getopt_long_only (C tools: arp-scan
and the like): the extra arguments an agent passes, read into the operations the table decides. Software, holds no rule.

    read_gnu_options("-I eth0 --interval 5 10.10.0.0/24 -W out.pcap", schema)        # schema of arp-scan
        -> {("use", "arp_scan_options", "--interface"), ("use", "arp_scan_options", "--interval"),
            ("limit", "rate", 200.0), ("target", "10.10.0.0/24", None), ("use", "arp_scan_options", "--pcapsavefile"),
            ("write", "/root/engagement", "")}

The reader follows glibc (measured against each tool's own parser): `--name value` and `--name=value`; a unique
beginning of a long name stands for it, an exact name wins over longer ones, two or more candidates are refused; with
`schema["long_only"]` (getopt_long_only) a long name may also follow a single `-`, and a single `-` word that is not a
long name (nor its beginning) is read as short options when its first letter is one; a short option takes the rest of
its word or the next word as its value; short options that take no value may be grouped. Words that are not options are
the tool's positional words (glibc moves them after the options), of kind `schema["positional"]`, or refused when it is
None.

`schema["options"]` maps each long name to `[takes a value (0, 1, or 2 for an optional one, taken only when attached:
`--dwarf=info`, `-W` alone), kind, short]`; `schema["short_only"]` maps a short letter with no long name to `[takes a
value, kind]`; `schema["short_takes"]` gives a short letter's own rule where it differs from its long name's (objdump's
`-d` takes none, `--disassemble` an optional one). With `schema["response_files"]` (binutils), a word starting with `@`
is refused: the tool reads more arguments from that file. The operations name an option by its long name (`--name`), or
`-x` for a short-only one; whether it is allowed is the container `schema["container"]`. Kinds: `target` (an IPv4
address, a network in CIDR form or a host name, read on the table's scope; no port, mask, list or range: arp-scan reads
`a-b` and `a:mask` in its own way and nmap's forms not at all), `read`, `write` (a file in the table's folders), `int`
(plain decimal), `interval` (a number of milliseconds, or of microseconds with `u`, seconds with `s`), `bandwidth` (bits
per second, `k` or `M` after the number), `rpc_commands` (rpcclient's commands, read by `reader_rpccmd` with
`schema["commands"]`), `value`.

**The rate** (`schema["rate"]`: `interval`, `bandwidth`, `frame_bits`, `bandwidth_default`): one packet every interval,
or, without one, the bandwidth over the size of a packet; counted as `rate` (packets per second).

Refused, never guessed: `--` and `-` alone, an option the schema does not know or an ambiguous beginning, a value that
starts with `-`, a number not in plain decimal, and any character a shell reads: only letters, digits, `._:/,=@+%-` and
the space pass.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_rpccmd import read_rpc_commands
    from .reader_target import read_target
except ImportError:
    from reader_rpccmd import read_rpc_commands
    from reader_target import read_target

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
# An address, a CIDR network, or a name with at least one letter (arp-scan resolves `10.0.0.2-4` as a name, where the
# target translator would read nmap's range).
_HOST = re.compile(r"^([0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?|(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9]([A-Za-z0-9-]*"
                   r"[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)$")
_UNIT = re.compile(r"^([0-9]+)([A-Za-z]?)$")


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


def _unit(name, v, units):
    m = _UNIT.match(v)
    if not m or m.group(2) not in units:
        raise ValueError(f"{name} takes a number with one of {sorted(k for k in units if k)}: {v!r}")
    return _plain(name, m.group(1)) * units[m.group(2)]


def _value(name, kind, v, schema, ops, seen):
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    if v.startswith("-"):
        raise ValueError(f"{name}: a value that starts with '-' is read as an option: {v!r}")
    if kind == "target":
        if not _HOST.match(v):
            raise ValueError(f"{name}: an address, a network in CIDR form or a host name, nothing else: {v!r}")
        ops |= read_target(v, scope)
    elif kind in ("read", "write"):
        if v == "":
            raise ValueError(f"{name}: a file, not nothing")
        ops.add((kind, _folder(v, paths), ""))
    elif kind == "int":
        _plain(name, v)
    elif kind == "rpc_commands":                    # rpcclient -c: its commands, read as the commands field is
        ops |= read_rpc_commands(v, schema["commands"])
    elif kind == "interval":
        seen[name] = _unit(name, v, {"": 1000, "u": 1, "U": 1, "s": 1000000, "S": 1000000})
    elif kind == "bandwidth":
        seen[name] = _unit(name, v, {"": 1, "k": 1000, "K": 1000, "m": 1000000, "M": 1000000})


def read_gnu_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    longs, shorts_only = schema["options"], schema.get("short_only", {})
    st = schema.get("short_takes", {})                 # a short letter's own rule (objdump -d: none)
    short = {v[2]: ("--" + k, st.get(v[2], v[0]), v[1]) for k, v in longs.items() if v[2]}
    short.update({c: ("-" + c, st.get(c, v[0]), v[1]) for c, v in shorts_only.items()})
    box = schema["container"]
    words, ops, i, seen = text.split(), set(), 0, {}

    def use(opt, takes, kind, attached):
        nonlocal i
        ops.add(("use", box, opt))
        if not takes:
            if attached is not None:
                raise ValueError(f"{opt} takes no value")
            seen[opt] = ""
            return
        if attached is None and takes == 2:             # an optional value is only an attached one
            seen[opt] = ""
            return
        if attached is None:
            if i >= len(words):
                raise ValueError(f"{opt} takes a value")
            attached = words[i]
            i += 1
        seen[opt] = attached
        _value(opt, kind, attached, schema, ops, seen)

    def long_match(name):
        if name in longs:
            return name
        hits = [k for k in longs if k.startswith(name)]
        if len(hits) > 1:
            raise ValueError(f"the beginning of more than one option: {name!r} ({', '.join(sorted(hits))})")
        return hits[0] if hits else None

    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--"):
            raise ValueError(f"{w!r} alone is not read")
        if schema.get("response_files") and w.startswith("@"):
            raise ValueError(f"{w!r}: the tool reads more arguments from the file after @")
        if not w.startswith("-"):
            if not schema.get("positional"):
                raise ValueError(f"a word that is not an option: {w!r}")
            _value("target", schema["positional"], w, schema, ops, seen)
            continue
        if w.startswith("--") or (schema.get("long_only") and (len(w) > 2 or w[1] not in short)):
            body = w[2:] if w.startswith("--") else w[1:]
            name, eq, value = body.partition("=")
            found = long_match(name)
            if found is not None:
                use("--" + found, longs[found][0], longs[found][1], value if eq else None)
                continue
            if w.startswith("--") or w[1] not in short:
                raise ValueError(f"an option the table does not know: {w.split('=')[0]}")
        group = w[1:]                                       # short options: -xVALUE, -x VALUE, grouped flags
        while group:
            c, rest = group[0], group[1:]
            if c not in short:
                raise ValueError(f"an option the table does not know: -{c}")
            opt, takes, kind = short[c]
            if not takes:
                use(opt, 0, kind, None)
                group = rest
                continue
            use(opt, takes, kind, rest or None)
            break
    rate = schema.get("rate")
    if rate:
        interval = seen.get("--" + rate["interval"]) if ("--" + rate["interval"]) in seen else None
        bandwidth = seen.get("--" + rate["bandwidth"]) if ("--" + rate["bandwidth"]) in seen else None
        if isinstance(interval, int) and interval > 0:
            ops.add(("limit", "rate", 1000000.0 / interval))
        else:
            bw = bandwidth if isinstance(bandwidth, int) else rate["bandwidth_default"]
            ops.add(("limit", "rate", bw / float(rate["frame_bits"])))
    return ops
