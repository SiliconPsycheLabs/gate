"""The path translator: a file tool's path read into one operation on the folder that holds it.
Software, holds no rule.

    read_path_read({"path": p}, schema)  -> {("read", folder, "")}
    read_path_write({"path": p}, schema) -> {("write", folder, "")}

`schema` holds `cwd` and `containers` (folders or single files). A relative path is read from `cwd`; `.` and `..`
are resolved as text (the file may not exist yet: a write creates it), and the longest container that holds the path
is its folder. A path outside every container, an empty path or a NUL raises `ValueError` and does not pass; with
`schema["empty_is_none"]` (a tool whose file fields are optional and default to "") an empty path names no file.
"""
import os


def _folder(p, containers):
    best = None
    for c in containers:
        if p == c or p.startswith(c.rstrip("/") + "/"):
            if best is None or len(c) > len(best):
                best = c
    if best is None:
        raise ValueError(f"{p} is outside every folder of the table")
    return best


def _read(kind):
    def read(args, schema):
        p = args.get("path") if isinstance(args, dict) else args
        if schema.get("empty_is_none") and p == "":    # an optional file field left at its default "": no file named
            return set()
        if not isinstance(p, str) or not p or "\x00" in p:
            raise ValueError("a path is a non-empty string")
        p = os.path.normpath(os.path.join(schema.get("cwd", "/"), p))
        return {(kind, _folder(p, schema["containers"]), "")}
    return read


read_path_read = _read("read")
read_path_write = _read("write")
