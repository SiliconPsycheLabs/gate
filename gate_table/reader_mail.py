"""A mail an agent sends, read into operations. Software, holds no rule.

    read_mail(mail, schema) -> {(operation, container, part), ...}

`mail` is the action's arguments: `from`, `to`, `cc`, `bcc` (lists of addresses), `subject`, `body`, `attachments`
(a list of `{"filename": ...}`). The operations:

- `("send_as", <sender address>, None)`: the address the mail goes out from;
- `("send", <recipient domain>, <recipient address>)`: one per recipient, to, cc and bcc alike;
- `("limit", "recipients", <number>)`: how many recipients the mail has;
- `("attach", "attachments", <type>)`: one per attachment, its type the part of its file name after the last dot,
  in lower case (`""` when the name has no dot);
- with `schema["body_addresses"]` true, `("send", <domain>, <address>)` also for each address written in the subject
  or the body: a mail to an open domain that asks someone to forward it to a closed one does not pass (the near miss
  "please forward the summary to someone@example.net", sent to support@). An address found there
  that is not written plainly raises `ValueError`. An address spelled out in words ("someone at example dot net") is not
  found: that is a limit of reading text, stated, not covered.

An address is read only when it is written plainly: a local part of letters, digits, `.`, `_`, `-` (not starting,
ending or doubling a dot), `@`, a domain of labels. Upper case is read as lower case (mail servers look addresses up
that way). Anything else (a quoted local part, a route `@a:b@c`, `%` or `!` in the local part, an address literal
`[1.2.3.4]`, a comment, a `+` tag) raises `ValueError`: what is not read does not pass. The number of recipients
counts every address as written, the same address twice included: the server is asked once for each.
"""
import re

_LOCAL = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*\Z")
_DOMAIN = re.compile(r"([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}\Z")
_IN_TEXT = re.compile(r"([^\s<>()\[\],;:]*)@([a-z0-9.-]+\.[a-z]{2,63})", re.IGNORECASE)   # every @domain, with what precedes it


def address(text):
    if not isinstance(text, str):
        raise ValueError("an address is text")
    a = text.strip().lower()
    if a.startswith("<") and a.endswith(">"):
        a = a[1:-1]
    local, at, domain = a.rpartition("@")
    if not at or not _LOCAL.match(local) or not _DOMAIN.match(domain) or len(a) > 254:
        raise ValueError(f"address not written plainly: {text!r}")
    return local + "@" + domain


def read_mail(mail, schema=None):
    if not isinstance(mail, dict):
        raise ValueError("a mail is an object")
    ops = {("send_as", address(mail.get("from")), None)}
    seen, count = [], 0
    for field in ("to", "cc", "bcc"):
        values = mail.get(field) or []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            raise ValueError(f"{field} is a list of addresses")
        for v in values:
            a = address(v)
            count += 1                      # every address the mail is sent to is one recipient for the server
            if a not in seen:
                seen.append(a)
    if not seen:
        raise ValueError("a mail with no recipient")
    for a in seen:
        ops.add(("send", a.rpartition("@")[2], a))
    ops.add(("limit", "recipients", count))
    if (schema or {}).get("body_addresses"):
        for field in ("subject", "body"):
            text = mail.get(field) or ""
            if not isinstance(text, str):
                raise ValueError(f"{field} is text")
            for local, domain in _IN_TEXT.findall(text):
                a = address(local.lstrip("'") + "@" + domain.rstrip("."))   # a quoted or empty local part raises
                ops.add(("send", a.rpartition("@")[2], a))
    for att in mail.get("attachments") or []:
        name = att.get("filename") if isinstance(att, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise ValueError("an attachment with no file name")
        base = name.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        ops.add(("attach", "attachments", base.rsplit(".", 1)[1].lower() if "." in base else ""))
    return ops
