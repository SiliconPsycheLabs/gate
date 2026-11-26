"""The nmap options translator: the options an agent passes to nmap (a tool's `scan_type` or
`additional_args`) read into the operations the table decides. Software, holds no rule.

    read_nmap_options("-sV -sC --script=http-title,vuln -oN scan.txt --min-rate 500", schema)
      -> {("use", "options", "-sV"), ("use", "options", "-sC"), ("use", "options", "--script"),
          ("use", "options", "-oN"), ("use", "options", "--min-rate"),
          ("script", "scripts_open", "default"), ("script", "scripts_ask_a_person", "vuln"), ...,
          ("write", "/root/engagement", ""), ("limit", "rate", 500)}

`schema` (written by the table compiler, so the reader itself knows nothing):
- `options`: every option the table knows, with the number of values it takes (`{"-sV": 0, "-p": 1, ...}`); an option
  missing from it is not read. Whether a known option is allowed is the table's `options` container.
- `scripts`: nmap's script database, script name to its categories (from `script.db` of the nmap the box runs).
- `script_containers`: category to the container that decides it (`scripts_open`, `scripts_ask_a_person`, `scripts_closed`).
- `paths`: `containers` and `cwd` for the output files (`-oN`, `-oX`, `-oG`, `-oA`).

Read: options only (a target belongs in the target field: a word that is not an option or an option's value is
refused); `--opt=value` and `--opt value`; `-p`, `-PS`, `-PA`, `-PU`, `-PY` with their value attached (`-p80,443`).
`--script` takes a comma list of script names and category names, as nmap resolves them: a name selects that script, a
category every script in it, and every category of every selected script is decided (a `default` script that is also
`intrusive` is decided as intrusive). `-sC`, `-sCV`, `-sVC` and `-A` select `default`. Refused: a boolean or wildcard script expression
(`and`, `or`, `not`, `*`), a script file or folder, a name nmap does not have; any character a shell reads (one of the
servers pastes the field into a shell line); `--min-rate` and `--max-rate` are counted as `rate`.
"""

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,:/=+%@ ")
_ATTACHED = ("-PS", "-PA", "-PU", "-PY", "-p")
_OUTPUT = {"-oN", "-oX", "-oG", "-oA", "-oS"}
_RATE = {"--min-rate", "--max-rate"}


def _folder(path, schema):
    import os
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


def _decided(cats):
    """The categories a script is decided by. nmap marks `safe` the scripts not designed to crash services, use much
    bandwidth or exploit security holes; for those, `auth` (an anonymous-login check), `external` (a lookup at a public
    service), `vuln` (a check for a known weakness, such as an exposed `.git`) and `malware` (a check whether the target
    is infected) are decided as safe, so `-sC` passes. `broadcast` and `intrusive` count even on a safe script (traffic
    to the whole local network reaches hosts outside the scope). Every other category counts as written."""
    return set(cats) - {"auth", "external", "vuln", "malware"} if "safe" in cats else set(cats)


def _scripts(value, schema):
    """The categories every script a `--script` value selects is decided by."""
    db = schema["scripts"]
    cats = {c for v in db.values() for c in v}
    out = set()
    for item in value.split(","):
        if not item:
            raise ValueError("an empty name in a script list")
        if any(ch in item for ch in "*/\\") or item.endswith(".nse") or item in ("and", "or", "not", "all"):
            raise ValueError(f"a script expression the reader does not read: {item!r}")
        if item in cats:
            for script_cats in db.values():
                if item in script_cats:
                    out.update(_decided(script_cats))
        elif item in db:
            out.update(_decided(db[item]))
        else:
            raise ValueError(f"nmap has no script or category named {item!r}")
    return out


def read_nmap_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("nmap options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"nmap options with a character options do not have: {''.join(bad)!r}")
    words, ops, known = text.split(), set(), schema["options"]
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w == "-" or w == "--":
            raise ValueError(f"a word that is not an option: {w!r} (targets go in the target field)")
        flag, value = w, None
        if w.startswith("--") and "=" in w:
            flag, value = w.split("=", 1)
        elif flag not in known:
            for pre in _ATTACHED:
                if w.startswith(pre) and w[len(pre):] and all(c in "0123456789,-TU:" for c in w[len(pre):]):
                    flag, value = pre, w[len(pre):]
                    break
        if flag not in known:
            raise ValueError(f"an nmap option the table does not know: {flag!r}")
        if known[flag] and value is None:
            if i >= len(words) or words[i].startswith("-"):
                raise ValueError(f"{flag} takes a value")
            value = words[i]
            i += 1
        elif not known[flag] and value is not None:
            raise ValueError(f"{flag} takes no value")
        ops.add(("use", "options", flag))
        if flag == "--script":
            selected = _scripts(value, schema)
        elif flag in ("-sC", "-A", "-sCV", "-sVC"):
            selected = _scripts("default", schema)
        else:
            selected = set()
        for cat in selected:
            ops.add(("script", schema["script_containers"].get(cat, "scripts_closed"), cat))
        if flag in _OUTPUT:
            ops.add(("write", _folder(value, schema), ""))
        if flag in _RATE:
            try:
                ops.add(("limit", "rate", float(value)))
            except ValueError:
                raise ValueError(f"{flag} takes a number") from None
    return ops


def read_nmap_scripts(text, schema):
    """A tool's script field (`nse_scripts`), pasted by the server as `--script=<text>`: read as that option. An empty
    field selects no script."""
    if isinstance(text, str) and not text.strip():
        return set()
    if not isinstance(text, str) or " " in text.strip():
        raise ValueError("a script list is one comma list, no space")
    return read_nmap_options("--script " + text.strip(), schema)
