"""HTTP requests to a company API, routed to the door of their operation.

A request is `{"method", "path", "query", "headers", "body"}` (`body` absent or `None` when there is none; query values
are strings, or lists of strings when a name is repeated). The table's `http` block lists the routes compiled from the
company's OpenAPI document (`openapi_table.py`):

    "http": {"base": "/api/v3", "routes": [{"method": "get", "path": "/pet/{petId}", "door": "getPetById"}, ...]}

`route(request, http)` gives `(door, args)`, or `None` when no route holds the method and the path: what the document
does not hold is not in the menu. `args` always has the same four parts, so a door's form is the same for every
operation: `{"path": {...}, "query": {...}, "header": {...}, "body": {"present": bool, "value": ...}}`. Header names
are lowercased (HTTP header names do not depend on case). A path with a character a URL path cannot carry
(RFC 3986: a space, `{`, `}`, `"`, `<`, `>`, `\\`, `^`, a backtick, `|`, anything outside ASCII) is in no route. A path segment matches a template segment `{name}` when it
is not empty; a route with more literal segments wins over one with fewer, so `/pet/findByStatus` is not read as
`/pet/{petId}`. Nothing here judges a value: the door's conditions do.
"""


import re
from urllib.parse import unquote_plus

UNREAD = "\u0000unread"     # the query name that carries why a raw query string could not be read (no route declares it)
_KEY = re.compile(r"^([^\[\]]+)((?:\[[^\[\]]*\])*)$")


def form_decode(text):
    """A form encoding (`a=1&b[c]=2&d[]=x&e[0][f]=y`) read into the structure its brackets name, values as text.
    `[]` appends to a list; `[0]`, `[1]` ... are explicit positions, which must run from 0 with no gap (as Stripe
    reads them); any other name inside brackets is a key of a mapping; a key given twice with the same value is read
    once. Raises ValueError on what is not read: a key that is not `name[...]...`, a name used both as a value and
    as a container, a list written both ways, one key with two different values."""
    root = {}
    if text == "":
        return root
    for pair in text.split("&"):
        if pair == "":
            continue
        k, _, v = pair.partition("=")
        k, v = unquote_plus(k), unquote_plus(v)
        m = _KEY.match(k)
        if not m:
            raise ValueError(f"a form key that is not name[...]: {k!r}")
        segs = [m.group(1)] + re.findall(r"\[([^\[\]]*)\]", m.group(2))
        node = root
        for i, seg in enumerate(segs):
            last = i == len(segs) - 1
            nxt = None if last else segs[i + 1]
            if seg == "":
                if not isinstance(node, _List) or node.explicit:
                    raise ValueError(f"{k}: a list written both with [] and with positions")
                node.appended = True
                if not last:
                    raise ValueError(f"{k}: [] followed by more brackets is not read")
                node.items.append(v)
                break
            if isinstance(node, _List):
                if not seg.isdigit() or node.appended:
                    raise ValueError(f"{k}: a list written both with [] and with positions")
                node.explicit = True
                seg = int(seg)
                store = node.items_by_pos
            else:
                store = node
            if last:
                if seg in store and store[seg] != v:
                    raise ValueError(f"{k}: two different values for one key")
                store[seg] = v
            else:
                want = _List() if (nxt == "" or nxt.isdigit()) else {}
                cur = store.setdefault(seg, want)
                if isinstance(cur, str) or type(cur) is not type(want):
                    raise ValueError(f"{k}: a name used both as a value and as a container, or as two kinds of container")
                node = cur
    return _finish(root)


class _List:
    def __init__(self):
        self.items, self.items_by_pos, self.explicit, self.appended = [], {}, False, False


def _finish(x):
    if isinstance(x, _List):
        if x.explicit:
            pos = sorted(x.items_by_pos)
            if pos != list(range(len(pos))):
                raise ValueError("an array with explicit keys must run from 0 with no gap")
            return [_finish(x.items_by_pos[p]) for p in pos]
        return list(x.items)
    if isinstance(x, dict):
        return {k: _finish(v) for k, v in x.items()}
    return x


_PATH =re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})*")   # RFC 3986 path: pchar and "/"


def _match(template, parts):
    """(the path values, the number of literal segments) when the path's segments follow the template; None when
    not. `{name}` takes one segment that is not empty; `{name+}` takes one or more, joined by `/` (a branch
    `feat/x`, a file path). With several ways to match, the one that gives `{name+}` the fewest segments wins."""
    t = [s for s in template.strip("/").split("/") if s != ""]
    literal = sum(not (a.startswith("{") and a.endswith("}")) for a in t)

    def walk(i, j):
        if i == len(t):
            return {} if j == len(parts) else None
        a = t[i]
        if a.startswith("{") and a.endswith("+}"):
            for k in range(j + 1, len(parts) - (len(t) - i - 1) + 1):
                seg = parts[j:k]
                if "" in seg:
                    break
                rest = walk(i + 1, k)
                if rest is not None:
                    return {a[1:-2]: "/".join(seg), **rest}
            return None
        if j >= len(parts):
            return None
        b = parts[j]
        if a.startswith("{") and a.endswith("}"):
            if b == "":
                return None
            rest = walk(i + 1, j + 1)
            return None if rest is None else {a[1:-1]: b, **rest}
        return walk(i + 1, j + 1) if a == b else None

    if not any(a.endswith("+}") for a in t) and len(t) != len(parts):
        return None
    values = walk(0, 0)
    return None if values is None else (values, literal)


def route(request, http):
    path = request.get("path") or ""
    base = (http.get("base") or "").rstrip("/")
    if base:
        if not (path == base or path.startswith(base + "/")):
            return None
        path = path[len(base):]
    if not _PATH.fullmatch(path):            # a character a URL path cannot carry (RFC 3986): `{`, `}`, a space, ...
        return None
    parts = [s for s in path.strip("/").split("/")] if path.strip("/") else []
    method = str(request.get("method") or "").lower()
    best = None
    for r in http.get("routes", []):
        if r["method"] != method:
            continue
        m = _match(r["path"], parts)
        if m and (best is None or m[1] > best[1]):
            best = (r, m[1], m[0])
    if best is None:
        return None
    r, _, values = best
    body = request.get("body")
    raw_query = request.get("query") or {}
    if isinstance(raw_query, str):          # a raw query string: names with brackets are read as a form
        try:
            query = form_decode(raw_query)
        except ValueError as e:
            query = {UNREAD: str(e)}
    else:
        query = {k: v for k, v in raw_query.items() if v != []}   # a name with no value is not sent
    ctype = str({str(k).lower(): v for k, v in (request.get("headers") or {}).items()}.get("content-type", "")).lower()
    if isinstance(body, str) and ctype.split(";")[0].strip() == "application/x-www-form-urlencoded":
        try:
            return r["door"], {"path": values, "query": query,
                               "header": {str(k).lower(): v for k, v in (request.get("headers") or {}).items()},
                               "body": {"present": True, "value": form_decode(body)}}
        except ValueError as e:
            return r["door"], {"path": values, "query": query,
                               "header": {str(k).lower(): v for k, v in (request.get("headers") or {}).items()},
                               "body": {"present": True, "value": None, "unread": str(e)}}
    args = {"path": values, "query": query,
            "header": {str(k).lower(): v for k, v in (request.get("headers") or {}).items()},
            "body": {"present": body is not None, "value": body}}
    return r["door"], args
