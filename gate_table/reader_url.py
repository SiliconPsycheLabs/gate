"""The URL translator: a web address an agent passes to a tool (a fetch, a webhook, a download) read into one operation
on the host it reaches. Software, holds no rule.

    read_url("https://api.example.org/v1/x?q=1", schema) -> {("connect", "api.example.org", None)}

The host is a container of the table like a folder or a database table: `{"api.example.org": {"connect": true}}` opens
it, a host the table does not declare does not pass. Only `http` and `https` are read; the host is lowercased, a
trailing dot is dropped, and a name written in another script is read in its ASCII form (IDNA), so one host has one
name. What a parser and a client could read differently is refused: a backslash, whitespace or a control character
anywhere, user and password in the address, an empty host, a port outside 1 to 65535. An IP address is read as the host
it names (the table declares it or not).
"""
from urllib.parse import urlsplit


def read_url(text, schema=None):
    if not isinstance(text, str) or not text:
        raise ValueError("a web address is a non-empty string")
    if any(c == "\\" or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("a web address with a backslash, a space or a control character")
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
    host = (u.hostname or "").rstrip(".")
    if not host:
        raise ValueError("a web address with no host")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("a host name that cannot be written in ASCII") from None
    return {("connect", host, None)}
