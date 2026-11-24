"""MQTT actions read into operations, and the topic matcher of the rules. Software, holds no rule.

    read_mqtt({"op": "publish" | "subscribe", "topic": ...}, schema=None) -> {(kind, topic or filter, None)}
    mqtt_rule(pattern, name) -> bool

A publish reads as `write` on its topic; a subscription reads as `read` on its filter. A topic for a publish holds no
`+` or `#`; a filter has `#` only as its whole last level and `+` only as a whole level; an empty string, a NUL or a
malformed filter raises `ValueError` and does not pass.

The rules (`container_rule: deny_wins`) list patterns, as the broker's ACL file does. `mqtt_rule(p, name)`:
- for a topic (a publish): the pattern matches it (`+` one level, `#` the rest and the level above it, so `a/#` matches
  `a`; a topic starting with `$` is matched only by a pattern that starts with the same literal level);
- for a filter (a subscription) and an allowing pattern: the pattern covers every topic the filter matches;
- a pattern written `{"overlap": p}` (how a deny is written) matches a topic `p` matches, or a filter that shares at
  least one topic with `p`: a subscription that could receive one message the deny closes does not pass.
"""


def _levels(s):
    return s.split("/")


def _valid_filter(f):
    lv = _levels(f)
    for i, x in enumerate(lv):
        if "#" in x and (x != "#" or i != len(lv) - 1):
            return False
        if "+" in x and x != "+":
            return False
    return True


def read_mqtt(op, schema=None):
    if not isinstance(op, dict):
        raise ValueError("an action is an object")
    kind, t = op.get("op"), op.get("topic")
    if not isinstance(t, str) or t == "" or "\x00" in t:
        raise ValueError("a topic is a non-empty string")
    if kind == "publish":
        if "+" in t or "#" in t:
            raise ValueError("a topic to publish holds no wildcard")
        return {("write", t, None)}
    if kind == "subscribe":
        if not _valid_filter(t):
            raise ValueError(f"a filter that is not valid: {t!r}")
        return {("read", t, None)}
    raise ValueError(f"an action the translator does not read: {kind!r}")


def _dollar_ok(p, t):
    """MQTT: `+` and `#` at the first level do not match a topic that starts with `$`."""
    return not (t.startswith("$") and _levels(p)[0] in ("+", "#"))


def topic_match(p, t):
    if not _dollar_ok(p, t):
        return False
    pl, tl = _levels(p), _levels(t)
    for i, x in enumerate(pl):
        if x == "#":
            return True
        if i >= len(tl):
            return False
        if x != "+" and x != tl[i]:
            return False
    return len(pl) == len(tl)


def covers(p, f):
    """Every topic the filter `f` matches is matched by `p`."""
    if f.startswith("$") and not _dollar_ok(p, f):
        return False
    pl, fl = _levels(p), _levels(f)
    for i, x in enumerate(pl):
        if x == "#":
            return True
        if i >= len(fl):
            return False
        y = fl[i]
        if y == "#":
            return False
        if x != "+" and (y == "+" or y != x):
            return False
    if len(pl) == len(fl):
        return True
    return False if len(fl) > len(pl) else pl[len(fl):] == ["#"]


def overlaps(p, f):
    """Some topic is matched by both `p` and `f`."""
    pl, fl = _levels(p), _levels(f)
    if (pl[0] in ("+", "#") and fl[0].startswith("$")) or (fl[0] in ("+", "#") and pl[0].startswith("$")):
        return False
    for i in range(max(len(pl), len(fl))):
        x = pl[i] if i < len(pl) else None
        y = fl[i] if i < len(fl) else None
        if x == "#" or y == "#":
            return True
        if x is None or y is None:
            rest = (fl if x is None else pl)[i:]
            return rest == ["#"]
        if x != "+" and y != "+" and x != y:
            return False
    return True


def mqtt_rule(pattern, name):
    is_filter = "+" in name or "#" in name
    if isinstance(pattern, dict):
        p = pattern["overlap"]
        return overlaps(p, name) if is_filter else topic_match(p, name)
    return covers(pattern, name) if is_filter else topic_match(pattern, name)


def mqtt_action(p, kind):
    return p == kind
