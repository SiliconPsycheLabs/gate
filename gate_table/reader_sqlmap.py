"""The sqlmap translator: the options an agent passes to sqlmap (a tool's `additional_args`) read into the operations
the table decides. Software, holds no rule.

    read_sqlmap_options("--batch --level 3 --risk 2 --dbs", schema)
      -> {("use", "sqlmap_options", "batch"), ("use", "sqlmap_options", "level"), ("use", "sqlmap_options", "risk=2"),
          ("use", "sqlmap_options", "getDbs")}

`schema["options"]` is sqlmap's own option table (each flag, the setting it fills and whether it takes a value), taken
from sqlmap's command-line parser and stored with the table; the reader is measured against that parser.
`schema["containers"]` maps a setting (or `setting=value` for the settings in `schema["valued"]`, such as `risk=3`) to
the container that decides it; a setting the map does not name goes to `sqlmap_closed`. `schema["paths"]` holds the
folders for `--output-dir`.

Read: `--opt value`, `--opt=value`, a short option and its value as two words. Refused: an option sqlmap's table does not
have (an abbreviation included), a word that is not an option (the target goes in the URL field), any character a shell
reads, a tamper script given as a path or a file (`--tamper` takes the names of sqlmap's own scripts).
"""
import os

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,:/=+@% ")


def _folder(path, schema):
    paths = schema.get("paths", {})
    p = os.path.normpath(os.path.join(paths.get("cwd", "/"), path))
    best = None
    for c in paths.get("containers", []):
        if p == c or p.startswith(c.rstrip("/") + "/"):
            if best is None or len(c) > len(best):
                best = c
    if best is None:
        raise ValueError(f"{p} is outside every folder of the table")
    return best


def read_sqlmap_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return set()
    if not isinstance(text, str):
        raise ValueError("sqlmap options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"sqlmap options with a character options do not have: {''.join(bad)!r}")
    table, where, valued = schema["options"], schema["containers"], set(schema.get("valued", ()))
    words, ops, i = text.split(), set(), 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not an option: {w!r} (the target goes in the URL field)")
        flag, value = (w.split("=", 1) if w.startswith("--") and "=" in w else (w, None))
        if flag not in table:
            raise ValueError(f"an sqlmap option the table does not know: {flag!r}")
        dest, takes = table[flag]["dest"], table[flag]["value"]
        if takes and value is None:
            if i >= len(words) or words[i].startswith("-"):
                raise ValueError(f"{flag} takes a value")
            value = words[i]
            i += 1
        elif not takes and value is not None:
            raise ValueError(f"{flag} takes no value")
        key = f"{dest}={value}" if dest in valued else dest
        ops.add(("use", where.get(key, where.get(dest, "sqlmap_closed")), key))
        if dest == "tamper" and any(c in value for c in "/\\") or dest == "tamper" and ".py" in value:
            raise ValueError("--tamper takes the names of sqlmap's own scripts, not a file")
        if dest == "outputDir":
            ops.add(("write", _folder(value, schema), ""))
    return ops
