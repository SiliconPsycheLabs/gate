"""The translator for rpcclient's commands (the text HexStrike sends on rpcclient's standard input, or `-c`): read into the
operations the table decides. Software, holds no rule.

    read_rpc_commands("enumdomusers;queryuser 500", schema)
        -> {("use", "rpcclient_commands", "enumdomusers"), ("use", "rpcclient_commands", "queryuser")}
    read_rpc_commands("setuserinfo2 admin 23 pass", schema)
        -> {("use", "rpcclient_commands_ask_a_person", "setuserinfo2")}

Commands are separated by `;` (the server turns each into a line), the first word of each is the command, the others
its arguments. `schema["commands"]` lists every command rpcclient has (taken from its source); `schema["open"]` the ones
that only read; a command in the first list and not in the second goes to `schema["ask"]`, a container that asks a
person (setting a password, creating or deleting an account, shutting the host down). Refused, never guessed: a name
rpcclient does not have, an argument that starts with `-`, and any character a shell or `echo -e` reads inside the
server's quotes: only letters, digits, `._:/,=@+%-?`, the space and `;` pass.
"""
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ;?")


def read_rpc_commands(text, schema):
    if not isinstance(text, str):
        raise ValueError("the commands are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"commands with a character they do not have: {''.join(bad)!r}")
    known, open_ = set(schema["commands"]), set(schema["open"])
    ops = set()
    for part in text.split(";"):
        words = part.split()
        if not words:                                   # an empty line: rpcclient reads nothing from it
            continue
        name = words[0]
        if name not in known:
            raise ValueError(f"a command rpcclient does not have: {name!r}")
        if any(w.startswith("-") for w in words[1:]):
            raise ValueError(f"{name}: an argument that starts with '-': {part!r}")
        ops.add(("use", schema["container"] if name in open_ else schema["ask"], name))
    return ops
