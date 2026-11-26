"""The target translator: what an offensive tool is pointed at, read into one operation per scope entry it
reaches. Software, holds no rule.

    read_target("10.10.0.5 10.10.1.0/28", schema)       -> {("target", "10.10.0.0/24", None), ("target", "10.10.1.0/24", None)}
    read_target_url("https://app.lab.example/login", schema) -> {("target", "*.lab.example", None)}

`schema["containers"]` lists the scope entries of the table: networks (`10.10.0.0/24`, `fd00::/64`), host names
(`app.lab.example`) and name patterns for every name below a domain (`*.lab.example`). Each entry is a container of the
table with the right `target` true (in scope) or false (inside the scope but excluded, such as the gateway). A target is
mapped to the narrowest entry that holds all of it; a network target also reaches every entry that lies inside it, so an
excluded host inside a scanned range closes the range. A target that no entry holds does not pass.

**`read_target` reads the target list of nmap** (the form most tools copy): targets separated by spaces; an IPv4
address in dotted decimal where an octet may be a number, a range `a-b`, `*` or a comma list of those (`10.0.0.1-5`,
`10.0.0.1,3,7`); a network in CIDR form; an IPv6 address or network; a host name; an optional port after a colon
(`10.0.0.5:8080`, `[fd00::1]:443`, `app.lab.example:8443`). nmap itself (`nmap -sL -n`) is the reference the reader is
measured against.

What two programs could read differently is refused, never guessed:
- a character outside letters, digits and `.:/-,*_[]` and the space: one of the servers runs its command line through a
  shell, where `;`, `$( )`, a quote or a redirection is a second command;
- a word starting with `-` (an option slipped in as a target: `-iL file`, `--script ...`);
- an IPv4 address not in plain dotted decimal (anything the C resolver's `inet_aton` takes): a single number, hex, an octet with a leading zero (read as octal by
  some resolvers), fewer or more than four octets, an open range (`5-`);
- a name with a network suffix (`host.lab/24`: needs name resolution), a `*` or a comma in a name;
- an IPv4-mapped IPv6 address is read as the IPv4 address it carries;
- a range or wildcard that expands to more than 65,536 addresses.
No name is resolved: a name is matched by name, an address by address (the network fence of the attack box covers
what a name resolves to).
"""
import ipaddress
import socket
from urllib.parse import urlsplit

EXPAND_MAX = 65536
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/-,*_[] ")
_URL_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@*+,=%")
_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class _Scope:
    def __init__(self, containers):
        self.nets, self.names, self.suffixes = [], set(), []
        for c in containers:
            if c.startswith("*."):
                self.suffixes.append(c)
                continue
            try:
                self.nets.append((ipaddress.ip_network(c, strict=True), c))
            except ValueError:
                self.names.add(c)

    def holder(self, net):
        """The narrowest network entry holding all of `net`, or None."""
        best = None
        for n, key in self.nets:
            if n.version == net.version and net.subnet_of(n) and (best is None or n.prefixlen > best[0].prefixlen):
                best = (n, key)
        return best[1] if best else None

    def inside(self, net):
        """Entries that lie inside `net` without holding it (a scanned range reaches them)."""
        return {key for n, key in self.nets if n.version == net.version and n != net and n.subnet_of(net)}

    def name(self, host):
        if host in self.names:
            return host
        best = None
        for s in self.suffixes:
            if host.endswith(s[1:]) and (best is None or len(s) > len(best)):
                best = s
        return best


def _ipv4_octet(text):
    """The values one octet of an nmap target names."""
    out = set()
    for part in text.split(","):
        if part == "*":
            out.update(range(256))
            continue
        lo, sep, hi = part.partition("-")
        for v in (lo, hi) if sep else (lo,):
            if not v.isdigit() or (len(v) > 1 and v[0] == "0") or int(v) > 255:
                raise ValueError(f"an octet the reader does not read: {part!r}")
        lo, hi = int(lo), int(hi) if sep else int(lo)
        if lo > hi:
            raise ValueError(f"an octet range that runs backwards: {part!r}")
        out.update(range(lo, hi + 1))
    return out


def _ipv4_set(text):
    octets = text.split(".")
    if len(octets) != 4:
        raise ValueError(f"an IPv4 target is four octets: {text!r}")
    sets = [_ipv4_octet(o) for o in octets]
    n = len(sets[0]) * len(sets[1]) * len(sets[2]) * len(sets[3])
    if n > EXPAND_MAX:
        raise ValueError(f"{text} names {n} addresses, more than the reader expands ({EXPAND_MAX})")
    return [ipaddress.ip_address(f"{a}.{b}.{c}.{d}") for a in sorted(sets[0]) for b in sorted(sets[1])
            for c in sorted(sets[2]) for d in sorted(sets[3])]


def _strip_port(word):
    """`host:port` and `[v6]:port` lose their port; a bare IPv6 address keeps all its colons."""
    if word.startswith("["):
        host, sep, rest = word[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(f"a bracketed address the reader does not read: {word!r}")
        port = rest[1:]
    elif word.count(":") == 1:
        host, port = word.split(":")
    else:
        return word
    if port and not (port.isdigit() and port[0] != "0" and 1 <= int(port) <= 65535):
        raise ValueError(f"a port outside 1 to 65535: {word!r}")
    return host


def _name(host):
    try:                                    # `0x0a0a0001`, `10.10.1`, `0xa.0xa.0.1`: the C resolver reads these as
        socket.inet_aton(host.rstrip("."))  # addresses, so a tool would scan an address the reader took for a name
    except OSError:
        pass
    else:
        raise ValueError(f"an address not written in plain dotted decimal: {host!r}")
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"a host name that cannot be written in ASCII: {host!r}") from None
    labels = host.split(".")
    if not host or any(not lab or set(lab) - _NAME_CHARS or lab[0] == "-" or lab[-1] == "-" for lab in labels):
        raise ValueError(f"not a host name: {host!r}")
    if labels[-1].isdigit():
        raise ValueError(f"a name whose last label is a number is not read: {host!r}")
    return host


def _ops_of(host, scope, ops):
    """One target word, port removed, into the scope entries it reaches."""
    if "/" in host:
        addr, _, bits = host.partition("/")
        if not bits.isdigit() or (len(bits) > 1 and bits[0] == "0"):
            raise ValueError(f"a network suffix the reader does not read: {host!r}")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(f"a network whose address is not plain (a name needs resolution): {host!r}") from None
        if ip.version == 4 and _ipv4_set(addr) != [ip]:
            raise ValueError(f"a network written with ranges: {host!r}")
        net = ipaddress.ip_network(f"{ip}/{bits}", strict=False)
        targets = [net]
    elif ":" in host:
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError(f"not an IPv6 address: {host!r}") from None
        targets = [ipaddress.ip_network(ip.ipv4_mapped or ip)]
    elif all(ch in "0123456789.,-*" for ch in host):
        targets = [ipaddress.ip_network(ip) for ip in _ipv4_set(host)]
    else:
        if set(host) & set(",*_[]"):
            raise ValueError(f"a name with a character names do not have: {host!r}")
        name = _name(host)
        key = scope.name(name)
        if key is None:
            raise ValueError(f"{name} is outside every scope entry of the table")
        ops.add(("target", key, None))
        return
    for net in targets:
        if net.version == 6 and net.network_address.ipv4_mapped and net.prefixlen >= 96:
            v4 = net.network_address.ipv4_mapped
            net = ipaddress.ip_network(f"{v4}/{net.prefixlen - 96}")
        key = scope.holder(net)
        if key is None:
            raise ValueError(f"{net} is not inside one scope entry of the table")
        ops.add(("target", key, None))
        ops.update(("target", k, None) for k in scope.inside(net))


def _check_text(text, allowed=_ALLOWED):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("a target is a non-empty string")
    bad = sorted(set(text) - allowed)
    if bad:
        raise ValueError(f"a target with a character targets do not have: {''.join(bad)!r}")


def read_target(text, schema):
    """An empty text names no target (a tool's optional target field left at its default ""): no operation. A text that
    holds `://` is one web address (nuclei, httpx and the crawlers take a host or a URL in the same field)."""
    if isinstance(text, str) and not text.strip():
        return set()
    if isinstance(text, str) and "://" in text:
        return read_target_url(text.strip(), schema)
    _check_text(text)
    scope, ops = _Scope(schema["containers"]), set()
    for word in text.split():
        if word.startswith("-"):
            raise ValueError(f"an option where a target is expected: {word!r}")
        _ops_of(_strip_port(word), scope, ops)
    return ops


def read_target_url(text, schema):
    """A web address a tool attacks (sqlmap `-u`, nuclei `-u`, a crawler): the host it reaches, mapped to the scope.
    Only http and https; a user or password in the address, an empty host or a port outside 1 to 65535 is refused, and
    so is any character a shell reads (`&`, `;`, `$`, `|`, quotes, parentheses, braces, `<`, `>`, `!`, a space): one of
    the servers pastes the address into a shell line unquoted, where `&` starts a second command. An empty text names
    no target."""
    if isinstance(text, str) and not text.strip():
        return set()
    _check_text(text, _URL_ALLOWED)
    u = urlsplit(text)
    if u.scheme.lower() not in ("http", "https"):
        raise ValueError(f"only http and https addresses are read, not {u.scheme or 'none'}")
    if "@" in u.netloc:
        raise ValueError("a web address carrying a user name or a password")
    try:
        port = u.port
    except ValueError:
        raise ValueError("a port outside 1 to 65535") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("a port outside 1 to 65535")
    host = u.hostname or ""
    if not host:
        raise ValueError("a web address with no host")
    ops = set()
    _ops_of(host, _Scope(schema["containers"]), ops)
    return ops
