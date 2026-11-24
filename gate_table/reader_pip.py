"""A `pip install` command read into operations. Software, holds no rule of its own.

    read_pip(line, schema) -> {(operation, container, part), ...}

`schema["packages"]` is the table's list of what may be installed, `{canonical name: [versions]}`, and
`schema["flags"]` the options it lets through. For each requirement the reader takes the version pip would choose
among the listed ones (the highest that the requirement's specifier accepts; a pre-release only when the specifier
names one), and reads:

- `("install", "packages", "<name>==<version>")`, or `<name>==none` when no listed version fits (the table has no
  such part, so it does not pass);
- `("extra", "extras", "<name>[<extra>]")` for each extra asked;
- `("flag", "options", "<option>")` for each option.

Names are compared as pip compares them (case, `-`, `_` and `.` alike: `packaging.utils.canonicalize_name`). A
requirement the reader does not read raises `ValueError` and does not pass: a direct URL (`name @ url`), a link, a
local path, an environment marker, an option that takes a value (`-r`, `-e`, `-i`, `--find-links`, ...), a command
that is not `pip install`.
"""
import shlex

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

_HEADS = (["pip", "install"], ["pip3", "install"], ["python", "-m", "pip", "install"], ["python3", "-m", "pip", "install"])


def read_pip(line, schema):
    try:
        words = shlex.split(line) if isinstance(line, str) else None
    except ValueError as e:
        raise ValueError(f"a line the reader does not split: {e}") from None
    if not words:
        raise ValueError("an empty command")
    head = next((h for h in _HEADS if words[:len(h)] == h), None)
    if head is None:
        raise ValueError("not a pip install command")
    allowed = {canonicalize_name(k): [Version(v) for v in vs] for k, vs in schema["packages"].items()}
    ops, reqs = set(), 0
    for w in words[len(head):]:
        if w.startswith("-"):
            if "=" in w or w not in schema.get("flags", []):
                raise ValueError(f"an option the reader does not read: {w}")
            ops.add(("flag", "options", w))
            continue
        if "/" in w or "\\" in w or w.startswith(".") or ":" in w:
            raise ValueError(f"a path, link or URL: {w}")
        try:
            r = Requirement(w)
        except InvalidRequirement as e:
            raise ValueError(f"a requirement the reader does not read: {w}: {e}") from None
        if r.url or r.marker:
            raise ValueError(f"a requirement with a URL or a marker: {w}")
        name = canonicalize_name(r.name)
        fits = [v for v in allowed.get(name, []) if r.specifier.contains(v, prereleases=r.specifier.prereleases or None)]
        ops.add(("install", "packages", f"{name}=={max(fits)}" if fits else f"{name}==none"))
        for e in r.extras:
            ops.add(("extra", "extras", f"{name}[{canonicalize_name(e)}]"))
        reqs += 1
    if not reqs:
        raise ValueError("nothing to install")
    return ops
