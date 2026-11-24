"""A systemd service unit read into operations. Software, holds no rule of its own.

    read_unit(text, schema=None) -> {(operation, container, part), ...}

The unit is read as systemd reads it (systemd.syntax(7), systemd.exec(5)):
- a line ending in `\\` continues on the next; a line whose first character (after spaces) is `#` or `;` is a comment;
- `[Section]` headers are compared exactly; only settings in `[Service]` count, and keys are compared exactly
  (`nonewprivileges=` is not `NoNewPrivileges=`); spaces around `=` and around the value are dropped;
- a later assignment replaces an earlier one; a value that does not parse is ignored and the earlier one stays;
- booleans: `1 yes y true t on` and `0 no n false f off`, in any case; an empty boolean is ignored;
- `User=` empty resets to root; `root` and `0` are root, and `nobody` is its own case, `DynamicUser=` or not;
- `DynamicUser=` with a value that is not a boolean (an empty one included) stops systemd: the unit is not loaded,
  and the reader raises; a service with no `ExecStart=` is not loaded either;
- `DynamicUser=yes` brings `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `RestrictSUIDSGID` and
  `ProtectHome=read-only` with it;
- `CapabilityBoundingSet=` lines merge: by OR, or by AND when prefixed with `~`; a word that is not a capability is
  skipped; a line replaces the set instead of merging when it names no capability systemd knows (`""`, `~`,
  `~CAP_FOO`) or when the set is still every capability (the start, or after such a line);
- a line with no `=` is ignored, as systemd ignores it;
- `ProtectSystem=` and `ProtectHome=` take their words (`strict`, `full`, `read-only`, `tmpfs`) exactly as written.

For each of the settings the company rules ask about it reads one operation `("setting", "service", "<name>=<value>")`
with the value in force (the default when the unit does not set it), so a setting left out reads as its default and
does not pass unless the table lists the default. Each `ExecStart=` reads `("exec", "programs", "<program>")` and, for
each special prefix, `("prefix", "programs", "<prefix>")`.
"""
import re

_TRUE = {"1", "yes", "y", "true", "t", "on"}
_FALSE = {"0", "no", "n", "false", "f", "off"}
_BOOLS = ("NoNewPrivileges", "PrivateTmp", "PrivateDevices", "RestrictSUIDSGID", "DynamicUser")
_KNOWN_CAPS = {"CAP_" + c for c in (
    "CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE "
    "NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN "
    "SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE "
    "MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE").split()}


def _bool(v):
    v = v.lower()
    return True if v in _TRUE else False if v in _FALSE else None


def _lines(text):
    out, cur = [], None
    for raw in text.split("\n"):
        s = raw.strip()
        if cur is None and (not s or s[0] in "#;"):
            continue
        if cur is not None and s[:1] in ("#", ";"):
            continue
        part = raw.rstrip()
        if part.endswith("\\"):
            cur = (cur + " " if cur is not None else "") + part[:-1]
            continue
        out.append((cur + " " if cur is not None else "") + part)
        cur = None
    if cur is not None:
        out.append(cur)
    return out


def read_unit(text, schema=None):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("an empty unit")
    st = {k: False for k in _BOOLS}
    user, protect_system, protect_home, caps, execs = None, "no", "no", _KNOWN_CAPS, []
    section = None
    for line in _lines(text):
        s = line.strip()
        if s.startswith("["):
            if not s.endswith("]"):
                raise ValueError(f"a section header that is not closed: {s!r}")
            section = s[1:-1]
            continue
        key, eq, val = s.partition("=")
        if not eq:
            continue                                            # systemd: "Missing '=', ignoring line."
        key, val = key.strip(), val.strip()
        if section != "Service":
            continue
        if key in _BOOLS:
            b = _bool(val)
            if b is not None:
                st[key] = b
            elif key == "DynamicUser":                       # systemd stops here: the unit is not loaded
                raise ValueError(f"DynamicUser= takes a boolean: {val!r}")
        elif key == "User":
            user = None if val == "" else "root" if val in ("root", "0") else val
        elif key == "ProtectSystem":
            b = _bool(val)
            if b is not None:
                protect_system = "yes" if b else "no"
            elif val in ("full", "strict"):                   # the words are compared exactly, booleans in any case
                protect_system = val
        elif key == "ProtectHome":
            b = _bool(val)
            if b is not None:
                protect_home = "yes" if b else "no"
            elif val in ("read-only", "tmpfs"):
                protect_home = val
        elif key == "CapabilityBoundingSet":
            invert = val.startswith("~")
            names = {n.upper() for n in (val[1:] if invert else val).split()} & _KNOWN_CAPS   # other words are skipped
            if not names or caps == _KNOWN_CAPS:               # nothing known, or the set is still "all": replaces
                caps = (_KNOWN_CAPS - names) if invert else names
            else:                                               # merged: AND for "~" lines, OR for the others
                caps = (caps - names) if invert else (caps | names)
        elif key == "ExecStart":
            if val == "":
                execs = []
                continue
            m = re.match(r"([-@:+!]*)(\S+)", val)
            if not m:
                raise ValueError(f"an ExecStart that cannot be read: {val!r}")
            execs.append((m.group(1), m.group(2)))
    if st["DynamicUser"]:
        st.update(NoNewPrivileges=True, PrivateTmp=True, RestrictSUIDSGID=True)
        protect_system = "strict"
        if protect_home in ("no",):
            protect_home = "read-only"
    if not execs:
        raise ValueError("a service with no ExecStart: systemd does not load it")
    identity = (user if user in ("nobody", "root") else "dynamic" if st["DynamicUser"] else "root" if user is None
                else f"user:{user}")
    yn = lambda b: "yes" if b else "no"  # noqa: E731
    ops = {("setting", "service", f"identity={identity}"),
           ("setting", "service", f"NoNewPrivileges={yn(st['NoNewPrivileges'])}"),
           ("setting", "service", f"PrivateTmp={yn(st['PrivateTmp'])}"),
           ("setting", "service", f"PrivateDevices={yn(st['PrivateDevices'])}"),
           ("setting", "service", f"RestrictSUIDSGID={yn(st['RestrictSUIDSGID'])}"),
           ("setting", "service", f"ProtectSystem={protect_system}"),
           ("setting", "service", f"ProtectHome={protect_home}"),
           ("setting", "service", f"CAP_SYS_ADMIN={'kept' if 'CAP_SYS_ADMIN' in caps else 'dropped'}")}
    for prefix, program in execs:
        ops.add(("exec", "programs", program))
        for p in re.findall(r"!!|[-@:+!]", prefix):
            ops.add(("prefix", "programs", p))
    return ops
