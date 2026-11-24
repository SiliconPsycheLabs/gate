"""The Redis reader: from a command and its arguments to the operations it performs. No rule here.

    read_redis(argv, schema) -> set of (operation, name, None)
        ("command", "get") or ("command", "config|get")
        ("read" | "write" | "read+write" | "any", key)      what the command does to each key
        ("channel", name) / ("channel_pattern", pattern)    for publish and subscribe
        schema: {"commands": Redis's own description of every command (tables/redis_commands.json)}

Which arguments are keys, and what is done to each, is read from Redis's own description (its key specifications).
A command that does not exist or has the wrong number of arguments raises ValueError; one whose keys Redis's
description does not give in full raises Closed.
"""
import re


class Closed(ValueError):
    pass


def _rights(flags):
    need = set()
    if "access" in flags:
        need.add("read")
    if {"insert", "delete", "update"} & set(flags):
        need.add("write")
    return "+".join(sorted(need)) or "any"


# Two commands whose key is read or not depending on their own arguments (Redis marks them "variable flags").
def _set_flags(argv):
    return ["access", "update"] if any(a.lower() == "get" for a in argv[3:]) else ["update"]


def _bitfield_flags(argv):
    i = 2
    while i < len(argv):
        if argv[i].lower() == "get" and len(argv) - i - 1 >= 2:
            i += 3
        else:
            return ["access", "update"]
    return ["access"]


VARIABLE = {"set": _set_flags, "bitfield": _bitfield_flags}
CHANNELS = {"publish": (1, 2, "channel"), "spublish": (1, 2, "channel"), "subscribe": (1, None, "channel"),
            "ssubscribe": (1, None, "channel"), "psubscribe": (1, None, "channel_pattern")}


def read_redis(argv, schema):
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("a command is a list of words")
    name = argv[0].lower()
    c = schema["commands"].get(name)
    if c is None:
        raise ValueError(f"unknown command {name}")
    if c["sub"]:
        if len(argv) < 2:
            raise ValueError("wrong number of arguments")
        name = name + "|" + argv[1].lower()
        c = c["sub"].get(name)
        if c is None:
            raise ValueError(f"unknown subcommand {name}")
    n, arity = len(argv), c["arity"]
    if (arity > 0 and n != arity) or (arity < 0 and n < -arity):
        raise ValueError("wrong number of arguments")
    ops = {("command", name, None)}
    for spec in c["keys"]:
        flags = spec["flags"]
        if "not_key" in flags:
            continue
        if "incomplete" in flags or spec["begin_search"]["type"] == "unknown" or spec["find_keys"]["type"] == "unknown":
            raise Closed(f"the keys of {name} are not described in full")
        if name in VARIABLE:
            flags = VARIABLE[name](argv)
        b, f = spec["begin_search"], spec["find_keys"]
        if b["type"] == "index":
            first = b["spec"]["index"]
        else:
            start, word = b["spec"]["startfrom"], b["spec"]["keyword"].lower()
            scan = range(start, n) if start >= 0 else range(n + start, 0, -1)
            hit = next((i for i in scan if argv[i].lower() == word), None)
            if hit is None:
                continue
            first = hit + 1
        if f["type"] == "range":
            s = f["spec"]
            if s["lastkey"] >= 0:
                last = first + s["lastkey"]
            elif not s["limit"]:
                last = n + s["lastkey"]
            else:
                last = first + ((n - first) // s["limit"] + s["lastkey"])
            step = s["keystep"]
        else:
            s = f["spec"]
            at = first + s["keynumidx"]
            if at >= n or not re.fullmatch(r"-?\d+", argv[at]):
                raise Closed("the number of keys cannot be read")
            count = int(argv[at])
            if count < 1:                       # zero keys where the command needs some: Redis then checks no key at all
                raise Closed("the number of keys cannot be read")
            first += s["firstkey"]
            last = first + count - 1
            step = s["keystep"]
        if last >= n or last < first or first >= n:
            raise Closed("the keys do not fit the arguments")
        for i in range(first, last + 1, step):
            ops.add((_rights(flags), argv[i], None))
    if name in CHANNELS:
        a, z, kind = CHANNELS[name]
        for ch in argv[a:z]:
            ops.add((kind, ch, None))
    return ops


def redis_glob(pattern, text):
    """Redis's own pattern matching: * ? [abc] [^abc] [a-z] and \\ to escape."""
    if text == "":                              # Redis's matcher: an empty name matches only an empty pattern
        return pattern == ""
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            out += ".*"
        elif ch == "?":
            out += "."
        elif ch == "\\" and i + 1 < len(pattern):
            i += 1
            out += re.escape(pattern[i])
        elif ch == "[":
            j, neg = i + 1, False
            if j < len(pattern) and pattern[j] == "^":
                neg, j = True, j + 1
            body = ""
            while j < len(pattern) and pattern[j] != "]":
                if pattern[j] == "\\" and j + 1 < len(pattern):
                    j += 1
                    body += re.escape(pattern[j])
                elif pattern[j] == "-" and body and j + 1 < len(pattern) and pattern[j + 1] != "]":
                    body += "-"
                else:
                    body += re.escape(pattern[j])
                j += 1
            out += "[" + ("^" if neg else "") + body + "]" if body else ("." if neg else "(?!)")
            i = j
        else:
            out += re.escape(ch)
        i += 1
    return re.fullmatch(out, text, re.S) is not None
