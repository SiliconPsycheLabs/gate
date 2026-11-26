"""The masscan translator: the targets and options an agent passes to masscan, read into the operations the table
decides. Software, holds no rule.

    read_masscan_target("10.10.0.0/28,10.10.1.5-10.10.1.9", schema) -> {("target", "10.10.0.0/24", None), ...}
    read_masscan_options("--banners --rate 500 -oJ out.json", schema) -> {("use", "masscan_options", "--banners"), ...}

**Targets** are read as masscan reads them (its own `--echo` lists the ranges it would scan, and the reader is measured
against it): items separated by commas or spaces; an IPv4 address, a network in CIDR form, a range written as two
full addresses (`10.0.0.1-10.0.0.9`), or one IPv6 address in brackets (`[fd00::5]`; masscan takes no bare IPv6 target). Each item is cut into networks and mapped to the narrowest scope entry
that holds it; a network also reaches every entry inside it (as in `reader_target`). Refused: a name (masscan does not
resolve names), an address not in plain dotted decimal, a range that runs backwards or mixes families, an octet range
(`10.0.0.1-5`, nmap's form, which masscan reads differently), any character a shell reads, a word starting with `-`.

**Options** (`schema["options"]`: option to the number of values it takes; whether one is allowed is the table's
`masscan_options` container): `--opt value` and `--opt=value`; `--rate` and `--max-rate` are counted as `rate`;
output files (`-oX`, `-oJ`, `-oL`, `-oG`, `-oB`, `-oD`) are writes in the table's folders; `--excludefile` is a read.
A word that is not an option is refused (targets go in the target field).
"""
import ipaddress
import os

_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/-,_=+@[] ")
_OUTPUT = {"-oX", "-oJ", "-oL", "-oG", "-oB", "-oD", "--output-filename"}
_RATE = {"--rate", "--max-rate"}


def _check(text, what):
    if not isinstance(text, str):
        raise ValueError(f"{what} is a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"{what} with a character it does not have: {''.join(bad)!r}")


def _address(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"not an address masscan reads plainly: {text!r}") from None
    if ip.version == 4 and str(ip) != text:
        raise ValueError(f"an address not in plain dotted decimal: {text!r}")
    return ip


def _networks(item):
    if item.startswith("[") and item.endswith("]"):     # masscan takes an IPv6 target in brackets, one address
        ip = _address(item[1:-1])
        if ip.version != 6:
            raise ValueError(f"brackets hold an IPv6 address: {item!r}")
        return [ipaddress.ip_network(ip)]
    if ":" in item:
        raise ValueError(f"masscan reads an IPv6 target only in brackets, one address: {item!r}")
    if "-" in item:
        lo, _, hi = item.partition("-")
        a, b = _address(lo), _address(hi)
        if a.version != b.version or a > b:
            raise ValueError(f"a range that runs backwards or mixes families: {item!r}")
        return list(ipaddress.summarize_address_range(a, b))
    if "/" in item:
        addr, _, bits = item.partition("/")
        _address(addr)
        if not bits.isdigit() or (len(bits) > 1 and bits[0] == "0"):
            raise ValueError(f"a network suffix the reader does not read: {item!r}")
        return [ipaddress.ip_network(item, strict=False)]
    return [ipaddress.ip_network(_address(item))]


def read_masscan_target(text, schema):
    if isinstance(text, str) and not text.strip():
        return set()
    _check(text, "a masscan target")
    nets, keys = [], schema["containers"]
    for k in keys:
        try:
            nets.append((ipaddress.ip_network(k, strict=True), k))
        except ValueError:
            continue
    ops = set()
    for item in text.replace(",", " ").split():
        if item.startswith("-"):
            raise ValueError(f"an option where a target is expected: {item!r}")
        for net in _networks(item):
            holders = [(n, k) for n, k in nets if n.version == net.version and net.subnet_of(n)]
            if not holders:
                raise ValueError(f"{net} is not inside one scope entry of the table")
            ops.add(("target", max(holders, key=lambda x: x[0].prefixlen)[1], None))
            ops.update(("target", k, None) for n, k in nets
                       if n.version == net.version and n != net and n.subnet_of(net))
    return ops


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


def read_masscan_options(text, schema):
    if isinstance(text, str) and not text.strip():
        return set()
    _check(text, "masscan options")
    words, ops, known = text.split(), set(), schema["options"]
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if not w.startswith("-") or w in ("-", "--"):
            raise ValueError(f"a word that is not an option: {w!r} (targets go in the target field)")
        flag, value = (w.split("=", 1) + [None])[:2] if w.startswith("--") and "=" in w else (w, None)
        if flag not in known:
            raise ValueError(f"a masscan option the table does not know: {flag!r}")
        if known[flag] and value is None:
            if i >= len(words) or words[i].startswith("-"):
                raise ValueError(f"{flag} takes a value")
            value = words[i]
            i += 1
        elif not known[flag] and value is not None:
            raise ValueError(f"{flag} takes no value")
        ops.add(("use", "masscan_options", flag))
        if flag in _OUTPUT:
            ops.add(("write", _folder(value, schema), ""))
        if flag == "--excludefile":
            ops.add(("read", _folder(value, schema), ""))
        if flag in _RATE:
            try:
                ops.add(("limit", "rate", float(value)))
            except ValueError:
                raise ValueError(f"{flag} takes a number") from None
    return ops
