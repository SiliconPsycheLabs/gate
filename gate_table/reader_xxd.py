"""The translator for xxd's extra arguments, read into the operations the table decides. Software, holds no rule.

    read_xxd_options("-c 16 -g 2 -u", schema)  -> {("use", "xxd_options", "-c"), ("use", "xxd_options", "-g"),
                                                    ("use", "xxd_options", "-u")}

xxd (vim's) reads its options by their first letter (measured against xxd itself): `-a`, `-autoskip` and `-anything` are
the same option, `--a...` too; an option that takes a value (`-c`, `-g`, `-o`, `-s`, `-l`, `-n`, `-R`) takes the rest
of its word, or the next word when the rest is empty or is the start of its own name (`-cols 16`, `-seek 8`); `-c`
followed by `apitalize` is the switch `-C`. The words that are not options are xxd's input and OUTPUT files: the server
puts its file last, so one more word would make the server's file the one xxd writes. Refused, never guessed: a word that
is not an option (and `-` or `--`), a letter xxd does not have, and any character a shell reads: only letters, digits,
`._:/,=@+%-` and the space pass. `schema["options"]` maps each letter to `[takes a value, the rest of its long name]`.
"""
_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/,=@+%- ")


def read_xxd_options(text, schema):
    if not isinstance(text, str):
        raise ValueError("the options are a string")
    bad = sorted(set(text) - _ALLOWED)
    if bad:
        raise ValueError(f"options with a character they do not have: {''.join(bad)!r}")
    known, box = schema["options"], schema["container"]
    words, ops, i = text.split(), set(), 0
    while i < len(words):
        w = words[i]
        i += 1
        if w in ("-", "--") or not w.startswith("-"):
            raise ValueError(f"a word that is not an option: {w!r} (xxd would take it as its input or output file)")
        pp = w[1:] if w.startswith("--") else w
        letter, rest = pp[1], pp[2:]
        if letter == "c" and rest.startswith("apitalize"):
            letter, rest = "C", ""
        if letter not in known:
            raise ValueError(f"an option xxd does not have: -{letter}")
        takes, long_rest = known[letter]
        ops.add(("use", box, "-" + letter))
        if not takes:
            continue
        if not rest or any(rest.startswith(r) for r in long_rest):
            if i >= len(words):
                raise ValueError(f"-{letter} takes a value")
            value = words[i]
            i += 1
            if value.startswith("-") and letter not in ("s",):
                raise ValueError(f"-{letter}: a value that starts with '-': {value!r}")
    return ops
