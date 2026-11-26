"""The nuclei translator: the extra command-line arguments an agent passes to nuclei, read into the operations the table
decides. Software, holds no rule.

    read_nuclei_options("-ni -rl 50 -severity high -o out.txt", schema)
        -> {("use", "nuclei_options", "-no-interactsh"), ("use", "nuclei_options", "-rate-limit"),
            ("limit", "rate", 50.0), ("use", "nuclei_options", "-severity"), ("use", "nuclei_options", "-output"),
            ("write", "/root/engagement", "")}

nuclei reads its command line with goflags, on Go's `flag` package, and the reader follows it (measured against nuclei's
own parser): every flag has a long name and often a short one (`-rl` is `-rate-limit`), `-name` and `--name` are the
same; `-name=value` or `-name value`, where a flag that takes a value takes the next word whatever it is; a flag that
takes no value is `-name` or `-name=true|false`; list flags split their value on commas and may be given again.
`schema["options"]` is nuclei's own flag table (stored with the tables); `schema["kinds"]` names, by long name, the
flags whose value is not a plain value; whether a flag is allowed is the table's `nuclei_options` container, by long
name. Kinds: `target` (each comma-separated item read by the target translator on the table's scope), `read` (each
item a file in the table's folders; nuclei finds a relative template under its templates folder, which is never outside
them), `write`, `rate` (requests per second), `per_duration` (the window `-rate-limit` counts in), `int`, `value`.

Two settings the reader derives, because nuclei turns them on when nothing is said:
- **the rate**: `-rate-limit` (150 when not given) per `-rate-limit-duration` (1 second), times the targets with
  `-per-host-rate-limit`; 0 means no limit and is read as the use `(no rate stated)`, which no table opens;
- **interactsh**: nuclei sends out-of-band checks through a public interactsh server unless `-no-interactsh` is given
  or `-interactsh-server` names one inside the scope; with `schema["oast_outside"]` false that is read as the use
  `(interactsh to an outside server)`, which no table opens.
Refused, never guessed: a word that is not a flag (Go stops reading flags there), `--` and `-` alone, a flag the schema
does not know, a number not in plain decimal, and any character a shell reads: only letters, digits, `._:/,=@+%-` and
the space pass.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target, read_target_url
except ImportError:
    from reader_target import read_target, read_target_url

NO_RATE = "(no rate stated)"
OAST_OUT = "(interactsh to an outside server)"
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_BOOL = {"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"}
_DURATION = re.compile(r"^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$")
_UNIT = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


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


def read_nuclei_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("nuclei options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"nuclei options with a character they do not have: {''.join(bad)!r}")
    flags, kinds = schema["options"], schema.get("kinds", {})
    short = {v["short"]: k for k, v in flags.items() if v["short"]}
    paths, scope = schema.get("paths", {}), {"containers": schema.get("targets", [])}
    words, ops, i, seen = text.split(), set(), 0, {}
    targets = 1                                           # the server's own -u
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not a flag: {w!r} (nuclei would stop reading flags there)")
        body = w[2:] if w.startswith("--") else w[1:]
        word, eq, value = body.partition("=")
        name = word if word in flags else short.get(word)
        if name is None:
            raise ValueError(f"a nuclei flag the table does not know: -{word}")
        ops.add(("use", "nuclei_options", "-" + name))
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
                targets += 1
            elif kind in ("read", "write"):
                if v in ("", "-") or "://" in v:
                    raise ValueError(f"-{name}: a file, not standard input, nothing or a web address: {v!r}")
                ops.add((kind, _folder(v, paths), ""))
            elif kind in ("int", "rate"):
                _number(name, v)
            elif kind == "per_duration" and not _DURATION.match(v):
                raise ValueError(f"-{name} takes a duration such as 1s or 500ms: {v!r}")
    # the rate nuclei uses: rate-limit (150) per rate-limit-duration (1s), per host with -per-host-rate-limit
    rate = int(seen.get("rate-limit", "150"))
    window = sum(float(n) * _UNIT[u] for n, _, u in re.findall(r"([0-9]+(\.[0-9]+)?)(ns|us|ms|s|m|h)",
                                                                seen.get("rate-limit-duration", "1s")))
    if rate <= 0 or window <= 0:
        ops.add(("use", "nuclei_options", NO_RATE))
    else:
        per_host = seen.get("per-host-rate-limit", "false") in ("1", "t", "T", "TRUE", "true", "True")
        ops.add(("limit", "rate", rate / window * (targets if per_host else 1)))
    # interactsh: off with -no-interactsh, or a server inside the scope
    ni = seen.get("no-interactsh", "false") in ("1", "t", "T", "TRUE", "true", "True")
    if not ni and not schema.get("oast_outside", False):
        server = seen.get("interactsh-server", "")
        if not server:
            ops.add(("use", "nuclei_options", OAST_OUT))
        else:
            ops |= read_target_url(server if "://" in server else "https://" + server, scope)
    return ops
