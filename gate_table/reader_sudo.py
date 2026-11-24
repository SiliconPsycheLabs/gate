"""The sudo reader: from a command to run as another user to the one operation it is. No rule here.

    read_sudo(call, schema) -> {("run", (run_as, path as given, real file, arguments joined, how many arguments), None)}
        call: {"run_as": "root", "argv": ["/usr/bin/ls", "/var/log"]}
        schema: {"path": the directories sudo searches for a command given by name}

The command is found as sudo finds it: by its path, or by name along the search path. A command that does not
exist raises ValueError.
"""
import fnmatch
import os
import shutil


def read_sudo(call, schema):
    argv = call.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv) or not argv[0]:
        raise ValueError("a command is a list of words")
    given = argv[0] if "/" in argv[0] else shutil.which(argv[0], path=schema["path"])
    if given is None or not (os.path.isfile(given) and os.access(given, os.X_OK)):
        raise ValueError("command not found")
    return {("run", (call.get("run_as") or "root", given, os.path.realpath(given), " ".join(argv[1:]), len(argv) - 1), None)}


def sudoers_match(rule, name):
    """One sudoers rule against one command: the user to run as, the command, the arguments."""
    run_as, given, real, args, count = name
    if "ALL" not in rule["run_as"] and run_as not in rule["run_as"]:
        return False
    cmd = rule["command"]
    if cmd != "ALL":
        if cmd.endswith("/"):                       # a directory: any command directly in it
            if os.path.dirname(real) != os.path.realpath(cmd) and os.path.dirname(given) != cmd.rstrip("/"):
                return False
        elif any(ch in cmd for ch in "*?["):        # wildcards do not cross a "/"
            if not (_path_match(cmd, given) or _path_match(cmd, real)):
                return False
        elif not (given == cmd or (os.path.exists(cmd) and os.path.realpath(cmd) == real)):
            return False
    want = rule.get("args")
    if want is None:
        return True
    if want == "":                                  # the rule says: with no arguments (an empty argument is still one)
        return count == 0
    return fnmatch.fnmatchcase(args, want)          # in the arguments a wildcard matches anything, spaces and "/" too


def _path_match(pattern, path):
    a, b = pattern.split("/"), path.split("/")
    return len(a) == len(b) and all(fnmatch.fnmatchcase(y, x) for x, y in zip(a, b))
