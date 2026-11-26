"""The ffuf translator: the extra command-line arguments an agent passes to ffuf, read into the operations the table
decides. Software, holds no rule.

    read_ffuf_options("-mc 200,301 -rate 50 -o out.json", schema)
        -> {("use", "ffuf_options", "-mc"), ("use", "ffuf_options", "-rate"), ("limit", "rate", 50.0),
            ("use", "ffuf_options", "-o"), ("write", "/root/engagement", "")}

ffuf reads its command line with Go's `flag` package, and the reader follows it (measured against ffuf's own
parser): `-name` and `--name` are the same flag; `-name=value` or `-name value`, where a flag that takes a value
takes the next word whatever it is (`-o -r` writes a file named `-r`); a flag that takes no value is `-name` or
`-name=true|false` (also 1, 0, t, f, T, F, TRUE, FALSE, True, False), never `-name false`; a flag given twice keeps its
last value, a list flag (`-H`, `-w`, `-b`) keeps all. `schema["options"]` maps each flag name (without dashes) to
`[takes_a_value, kind]`, and whether a flag is allowed is the table's `ffuf_options` container. Another tool on Go's
`flag` uses the same reader with `schema["container"]`, and `schema["delimited"]` names its flags whose value is a comma
list (amass `-d a,b`). Kinds:
- `url`: a web address the requests go to, read by the target translator (`read_target_url`) on the table's scope;
- `target`: an address, a network, a range or a name, read by the target translator (`read_target`) on the scope;
  `domain`: a name only (its last label has a letter), read the same way;
- `wordlist`: files read, a comma list where each item is `path` or `path:KEYWORD`;
- `read`, `write`: one file read or written, in the table's folders (relative to the workspace);
- `rate`: requests per second, counted as `rate`;
- `int`: a number; `value`: any other value.
Refused, never guessed: a word that is not a flag (Go stops reading flags at the first one, so what follows it would be
silently dropped), `--` and `-` alone, a flag the schema does not know, a number not written in plain decimal (Go also
reads `0x10`, `010` as octal and `1_000`), a wordlist read from standard input (`-`), and any character a shell reads
(the server pastes the arguments into a shell line unquoted): only letters, digits, `._:/,=@+%-` and the space pass.

**A rate may be required** (`schema["rate_required"]`, the engagement's choice): then a call that does not state one, or
states 0 (which the tool reads as no limit), is read as the use `(no rate stated)`, which no
table opens.
"""
import os

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"     # a use no table opens: the engagement requires a rate
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_BOOL = {"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"}


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


def _number(flag, value):
    if not (value == "0" or (value.isdigit() and value[0] != "0")):
        raise ValueError(f"-{flag} takes a number in plain decimal: {value!r}")
    return int(value)


def read_ffuf_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return _required(set(), schema, "-rate N")
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    words, ops, known = text.split(), set(), schema["options"]
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    box, delimited = schema.get("container", "ffuf_options"), schema.get("delimited", ())
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not a flag: {w!r} (the tool would stop reading flags there)")
        name = w[2:] if w.startswith("--") else w[1:]
        if not name or name[0] in "-=":
            raise ValueError(f"a flag the tool does not read: {w!r}")
        name, eq, value = name.partition("=")
        if name not in known:
            raise ValueError(f"a flag the table does not know: -{name}")
        takes, kind = known[name]
        if not takes:
            if eq and value not in _BOOL:
                raise ValueError(f"-{name} is true or false: {value!r}")
            ops.add(("use", box, "-" + name))
            continue
        if not eq:
            if i >= len(words):
                raise ValueError(f"-{name} takes a value")
            value = words[i]
            i += 1
        ops.add(("use", box, "-" + name))
        items = value.split(",") if name in delimited else [value]   # a flag whose value is a comma list (amass -d)
        if name in delimited and any(not item for item in items):
            raise ValueError(f"-{name}: an empty item in {value!r}")
        if kind == "url":
            ops |= read_target_url(value, scope)
        elif kind in ("target", "domain"):
            for item in items:
                if kind == "domain" and not any(c.isalpha() for c in item.rsplit(".", 1)[-1]):
                    raise ValueError(f"-{name}: a domain name, not an address: {item!r}")
                ops |= read_target(item, scope)
        elif kind == "wordlist":
            for item in value.split(","):
                path = item.split(":", 1)[0]
                if path in ("", "-"):
                    raise ValueError(f"-{name}: a wordlist is a file, not standard input or nothing: {item!r}")
                ops.add(("read", _folder(path, paths), ""))
        elif kind in ("read", "write"):
            for item in items:
                ops.add((kind, _folder(item, paths), ""))
        elif kind == "rate":
            ops.add(("limit", "rate", float(_number(name, value))))
        elif kind == "int":
            _number(name, value)
    return _required(ops, schema, "-rate N")


def _required(ops, schema, how):
    """With a rate required, a call states one above 0 (0 is no limit for the tool)."""
    if schema.get("rate_required") and not any(o[0] == "limit" and o[1] == "rate" and o[2] > 0 for o in ops):
        ops.add(("use", schema.get("container", "ffuf_options"), NO_RATE))   # no rate stated, or 0: no cap
    return ops
