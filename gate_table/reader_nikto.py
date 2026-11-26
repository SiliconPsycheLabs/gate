"""The nikto translator: the extra command-line arguments an agent passes to nikto, read into the operations the table
decides. Software, holds no rule.

    read_nikto_options("-Tuning 123 -port 8080 -output out.txt", schema)
        -> {("use", "nikto_options", "-Tuning"), ("use", "nikto_options", "-port"), ("use", "nikto_options", "-output"),
            ("write", "/root/engagement", "")}

nikto reads its command line with Perl's Getopt::Long (case-sensitive, abbreviations allowed, no bundling), and the
reader follows it (measured against nikto's own parsing): `-name` and `--name` are the same option; `-name value` or
`-name=value`; a unique beginning of a name stands for it (`-out` is `-output`, `-h` is `-host`; `-P` alone is
ambiguous between `-Pause` and `-Plugins` and nikto refuses it); an option given twice keeps its last value, so a later
`-host` or `-url` replaces the target the server put first, and is read as a target. `schema["options"]` maps each
option name to `[value, kind]`, value being 0 (none), 1 (required) or `opt` (taken only when the next word is not an
option); whether one is allowed is the table's `nikto_options` container, by full name. Kinds: `web_target` (a web address ending
in `/`, read by the target translator on the table's scope: nikto reads a target that is a file's name as a list of
targets), `target` (an address or a name, on the scope), `read`, `write` (one file in the
table's folders), `mutate` (`5`, guessing sub-domains of the target, reaches other hosts and is read as the use
`-mutate=5`), `int`, `float`, `value`.
Other Getopt::Long tools share this reader (dnsenum): `schema["container"]` names their container,
`schema["ignore_case"]` follows Getopt::Long's default of matching names without regard to case, and a table entry
`[value, kind, name]` makes an alias stand for the option's own name.
Refused, never guessed: a word that is not an option (Getopt::Long would set it aside and nikto ignore it), `--` and
`-` alone, an option the schema does not know or an ambiguous beginning, a value that starts with `-`, a number not in
plain decimal, and any character a shell reads (the server pastes the arguments into a shell line unquoted): only
letters, digits, `._:/,=@+%-` and the space pass.
"""
import os
import re

try:                                    # inside the gate_table package, and in the research folder
    from .reader_target import read_target
except ImportError:
    from reader_target import read_target

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")
_FLOAT = re.compile(r"^[0-9]+(\.[0-9]+)?$")
# nikto takes every comma-separated target that is the name of a file in its folder (or `-`) as a list of targets, so a
# file an earlier tool wrote under a target's name would bring its own targets; a web address ending in `/` is never a
# file's name.
_WEB_TARGET = re.compile(r"^https?://[^,/\s]+/[^,\s]*/$|^https?://[^,/\s]+/$")


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


def _name(word, known, ignore_case=False):
    """Getopt::Long's matching: the exact name, else the one name that begins with it (both without regard to case
    when the tool sets ignore_case, Getopt::Long's default; nikto turns it off). Aliases of one option count once."""
    fold = (lambda x: x.lower()) if ignore_case else (lambda x: x)
    exact = [k for k in known if fold(k) == fold(word)]
    if exact:
        return exact[0]
    hits = {_canon(k, known) for k in known if fold(k).startswith(fold(word))}
    if len(hits) != 1:
        raise ValueError(f"an option the table does not know, or a beginning of more than one: -{word}")
    return [k for k in known if _canon(k, known) in hits][0]


def _canon(name, known):
    """The option's own name when the table lists aliases ([value, kind, canonical])."""
    spec = known[name]
    return spec[2] if len(spec) > 2 else name


def read_nikto_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return set()
    if not isinstance(text, str):
        raise ValueError("nikto options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"nikto options with a character they do not have: {''.join(bad)!r}")
    known, paths = schema["options"], schema.get("paths", {})
    box = schema.get("container", "nikto_options")
    words, ops, i = text.split(), set(), 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not an option: {w!r}")
        body = w[2:] if w.startswith("--") else w[1:]
        word, eq, value = body.partition("=")
        name = _name(word, known, schema.get("ignore_case", False))
        takes, kind = known[name][0], known[name][1]
        name = _canon(name, known)
        ops.add(("use", box, "-" + name))
        if takes == 0:
            if eq:
                raise ValueError(f"-{name} takes no value")
            continue
        if not eq:
            if i < len(words) and not words[i].startswith("-"):
                value = words[i]
                i += 1
            elif takes == 1:
                raise ValueError(f"-{name} takes a value")
            else:
                continue
        if value.startswith("-"):
            raise ValueError(f"-{name}: a value that starts with '-' is read as an option: {value!r}")
        if kind == "target":
            ops |= read_target(value, {"containers": schema.get("targets", [])})
        elif kind == "web_target":
            if not _WEB_TARGET.match(value):
                raise ValueError(f"-{name}: nikto reads a target that is also a file's name as a list of targets; give "
                                 f"it as a web address ending in / (such as http://10.10.0.5/): {value!r}")
            ops |= read_target(value, {"containers": schema.get("targets", [])})
        elif kind in ("read", "write"):
            if value in ("", "-"):
                raise ValueError(f"-{name}: a file, not standard input or nothing")
            ops.add((kind, _folder(value, paths), ""))
        elif kind == "mutate":
            if "5" in value:
                ops.add(("use", box, "-mutate=5"))
        elif kind == "int":
            if not (value == "0" or (value.isdigit() and value[0] != "0")):
                raise ValueError(f"-{name} takes a number in plain decimal: {value!r}")
        elif kind == "float":
            if not _FLOAT.match(value):
                raise ValueError(f"-{name} takes a number such as 2 or 0.5: {value!r}")
    return ops
