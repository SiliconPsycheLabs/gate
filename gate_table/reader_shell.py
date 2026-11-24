"""The shell reader: from a command line to the operations it performs on containers (directories). No rule here.

    read_shell(text, schema) -> set of (operation, container, "")
        operation: read, write, delete, permissions
        schema: {"cwd": dir, "containers": [dirs], "devices": [paths], "commands": the table of known commands}

It uses the bashlex parser, the table of known commands (which arguments a command reads, writes or deletes) and
the real file tree (to follow `..` and symbolic links, and to see what exists). Reaching anything inside a
container needs passing through the containers above it. A line with a command the table does not list, a
command that runs other code, an expansion, or a construct the reader does not model raises Closed.
"""
import os

import bashlex


class Closed(ValueError):
    pass


GLOB = set("*?[")


def _container(path, containers):
    best = None
    for c in containers:
        if path == c or path.startswith(c.rstrip("/") + "/"):
            if best is None or len(c) > len(best):
                best = c
    return best


def _under(path, containers):
    return [c for c in containers if c == path or c.startswith(path.rstrip("/") + "/")]


class _Line:
    def __init__(self, schema):
        self.s, self.ops = schema, set()
        self.gone, self.commands = set(), 0     # entries the line destroys (rm, rmdir, find -delete); commands in the line
        self.destroyer = False                  # the line holds a command that deletes, whatever it finds to delete
        self.containers = [os.path.realpath(c) for c in schema["containers"]]

    def add(self, kind, path):
        if path in self.s.get("devices", []):
            return
        c = _container(path, self.containers)
        if c is None:
            raise Closed(f"{path} is outside every container")
        self.ops.add((kind, c, ""))

    def walk_to(self, path):
        """Every container passed through on the way to `path` must let itself be traversed."""
        cur = path
        while True:
            cur = os.path.dirname(cur)
            c = _container(cur, self.containers)
            if c is None:
                break
            if cur == c:
                self.ops.add(("read", c, ""))
            if cur == "/":
                break

    def walk_raw(self, word):
        """Every directory entered while resolving the word as written (`A/../B` enters A)."""
        cur = "/" if word.startswith("/") else self.s["cwd"]
        if not word.startswith("/"):
            self.pass_through(cur)
        for comp in [p for p in word.split("/") if p not in ("", ".")][:-1]:
            cur = os.path.realpath(os.path.join(cur, comp))
            self.pass_through(cur)

    def pass_through(self, d):
        c = _container(d, self.containers)
        if c is not None:
            self.ops.add(("read", c, ""))

    def lexical(self, p):
        return os.path.normpath(os.path.join(self.s["cwd"], p))

    def op(self, kind, word):
        if word in self.s.get("devices", []):
            return
        if GLOB & set(os.path.dirname(word)):
            raise Closed("wildcard in a directory name")
        if GLOB & set(os.path.basename(word)):          # a pattern over the entries of one directory
            d = os.path.realpath(self.lexical(os.path.dirname(word) or "."))
            self.walk_to(os.path.join(d, "x"))
            self.add("read", d)
            import glob as _glob
            if "delete" in kind and not _glob.glob(os.path.join(d, os.path.basename(word))):
                return                                  # a pattern that matches nothing deletes nothing
            if kind in ("delete", "tree_delete", "write", "edit", "make"):
                self.add("delete" if "delete" in kind else "write", d)
            return
        lex = self.lexical(word)
        self.walk_raw(word)
        parent = os.path.realpath(os.path.dirname(lex))
        entry = os.path.join(parent, os.path.basename(lex))          # the entry itself, final link not followed
        real = os.path.realpath(lex)                                   # what it points to
        if kind == "look":                              # the entry is looked at, a final link is not followed
            self.add("read", parent)
            return
        if kind == "place" and not os.path.isdir(real):  # a move puts the entry in the directory as written
            self.add("write", parent)
            return
        if kind == "place":
            kind = "write"
        if kind not in ("delete", "tree_delete", "make"):
            self.walk_to(real)
        if kind in ("read", "list", "tree_read"):
            if kind == "list" and not os.path.isdir(real):
                kind = "read"
            target = real if os.path.isdir(real) else os.path.dirname(real)
            self.add("read", target)
            if kind == "tree_read" and os.path.isdir(real):
                for c in _under(real, self.containers):
                    self.add("read", c)
        elif kind in ("write", "edit"):
            if kind == "edit" and not os.path.exists(real):
                return                                  # nothing there: nothing is edited
            target = real if os.path.isdir(real) else os.path.dirname(real)
            if kind == "edit":                          # the new file is made beside the path as written
                self.add("read", target)
                self.add("write", parent)
            else:
                self.add("write", target)
        elif kind == "make":
            if os.path.lexists(entry):
                return                                  # the name is already there: the system makes nothing
            self.add("write", parent)
        elif kind == "tree_delete_inside":               # entries inside the directory, not the directory itself
            hit = {_container(os.path.dirname(g), self.containers) for g in self.gone}
            for c in _under(real, self.containers):
                self.add("read", c)
                if c in hit:                            # find -delete deletes what it matches: a folder with no match loses nothing
                    self.add("delete", c)
        elif kind in ("delete", "tree_delete"):
            if not os.path.lexists(entry):
                return                                  # nothing there: nothing is deleted
            self.add("delete", parent)
            if kind == "tree_delete" and os.path.isdir(entry) and not os.path.islink(entry):
                for c in _under(real, self.containers):
                    self.add("read", c)
                    self.add("delete", c)
        else:
            raise Closed(f"operation {kind} not modelled")

    def command(self, words):
        t = self.s["commands"]
        name, rest = words[0], words[1:]
        if "/" in name:
            raise Closed("a program given by its path runs other code")
        if name in t["no_paths"]:
            return
        if name in t["permissions"]:
            raise Closed(f"{name} changes permissions")
        if name in t["runs_other_code"]:
            raise Closed(f"{name} runs other code")
        spec = t["commands"].get(name)
        if spec is None:
            raise Closed(f"{name} is not a known command")
        plan = [list(x) for x in spec["args"]]
        allowed = (set(spec.get("flags", [])) | set(spec.get("value_flags", [])) | set(spec.get("path_flags", {})) | set(spec.get("flag_switch", {}))
                   | set(spec.get("destroys_with", {})))
        takes_value = set(spec.get("value_flags", [])) | set(spec.get("path_flags", {}))
        paths, flagged, seen, queue, plain = [], [], [], list(rest), False
        while queue:
            w = queue.pop(0)
            if plain or not (w.startswith("-") and len(w) > 1):
                paths.append(w)
                continue
            if w == "--":
                plain = True
                continue
            if w.startswith("--"):                      # a long option: only the ones the table maps to a listed one
                key, eq, value = w.partition("=")
                if key not in spec.get("long_flags", {}):
                    raise Closed(f"{name} with an option the table does not list")
                flags = [spec["long_flags"][key]]
                if eq:
                    queue.insert(0, value)
            elif spec.get("word_flags"):                # find: an option is a whole word
                flags = [w]
            elif spec.get("count_flag") and w[1:].isdigit():
                continue                                # head -5
            else:                                       # short options written together; one that takes a value takes the rest
                flags, j = [], 1
                while j < len(w):
                    f = "-" + w[j]
                    flags.append(f)
                    if f in takes_value:
                        if w[j + 1:]:
                            queue.insert(0, w[j + 1:])
                        break
                    j += 1
            for f in flags:
                if f not in allowed:
                    raise Closed(f"{name} with an option the table does not list")
                seen.append(f)
                if f in takes_value:
                    if not queue:
                        raise Closed("flag without its value")
                    value = queue.pop(0)
                    if f in spec.get("path_flags", {}):
                        flagged.append((spec["path_flags"][f], value))
                    elif spec.get("script_check") and f in spec.get("script_given_by", []):
                        self.script(spec["script_check"], value)
                elif f in spec.get("flag_switch", {}):
                    new = spec["flag_switch"][f]
                    plan = [[sel, new if op in ("read", "delete", "tree_read", "list") else op] for sel, op in plan]
        if set(seen) & set(spec.get("script_given_by", [])):     # the script came with an option: every plain word is a file
            plan = [["all", op] for sel, op in plan if sel == "rest"] or plan
        elif spec.get("script_check") and paths:
            self.script(spec["script_check"], paths[0])
        if spec.get("refuses_dot_operands"):            # rm refuses an operand whose last part is "." or "..": it removes nothing
            paths = [p for p in paths if os.path.basename(p.rstrip("/")) not in (".", "..")]
            if not paths:
                return
        if not paths:
            if spec.get("no_args") == "list_here":
                self.op("list", ".")
            if spec.get("no_args") == "tree_here":
                paths = ["."]
            else:
                return
        if any(sel in ("init", "last") for sel, _ in plan) and len(paths) < 2:
            raise Closed("this command needs a source and a destination")
        chosen = {"all": paths, "first": paths[:1], "rest": paths[1:], "init": paths[:-1], "last": paths[-1:]}
        how = spec.get("destroys")
        for w in seen:
            how = spec.get("destroys_with", {}).get(w, how)
        if how:
            self.destroyer = True
            self.destroyed(how, paths, rest)
        if spec.get("needs_a_source"):
            # a source that is not there, or that is the destination itself, does nothing; with none left, nothing is written
            dest = os.path.realpath(self.lexical(paths[-1]))
            follow = spec.get("follows_links")

            def entry(q):                               # the directory entry itself, a final link not followed
                lex = self.lexical(q)
                return os.path.join(os.path.realpath(os.path.dirname(lex)), os.path.basename(lex))

            live = []
            for p in paths[:-1]:
                src = self.lexical(p)
                into = os.path.join(dest, os.path.basename(src)) if os.path.isdir(dest) else self.lexical(paths[-1])
                there = os.path.join(dest, os.path.basename(src)) if os.path.isdir(dest) else entry(paths[-1])
                # a command that does not follow links: the same entry, or a link moved onto the file it points to
                onto_its_file = os.path.islink(src) and not os.path.islink(there) and os.path.realpath(src) == there
                same = (os.path.realpath(src) == os.path.realpath(into)) if follow else (entry(p) == there or onto_its_file)
                if os.path.lexists(src) and not same:
                    live.append(p)
                else:
                    self.walk_raw(p)
                    if os.path.lexists(src):            # it exists and is the destination itself: both were looked at
                        self.walk_raw(paths[-1])
                        if follow or onto_its_file:
                            self.walk_to(os.path.realpath(src))
            chosen["init"] = live
            if not live:
                chosen["last"] = []
        if spec.get("outputs_need_inputs") and any(not os.path.exists(self.lexical(p)) for p in paths):
            flagged = []
        for kind, p in flagged:
            self.op(kind, p)
        for sel, kind in plan:
            if kind == "skip":
                continue
            for p in chosen[sel]:
                self.op(kind, p)

    def script(self, kind, text):
        """A script given to a command is a small language of its own: only the plain forms are read."""
        import re
        if kind == "sed":
            if re.fullmatch(r"(\d+|\$)?(,(\d+|\$))?[pdq]", text):
                return
            if len(text) > 3 and text[0] == "s" and not text[1].isalnum() and text[1] not in "\\\n":
                parts, cur, i = [], "", 2
                while i < len(text):
                    if text[i] == "\\" and i + 1 < len(text):
                        cur += text[i:i + 2]
                        i += 2
                        continue
                    if text[i] == text[1]:
                        parts.append(cur)
                        cur = ""
                    else:
                        cur += text[i]
                    i += 1
                if len(parts) == 2 and re.fullmatch(r"[gIi0-9]*", cur) and "\n" not in text:
                    return
        raise Closed("a script the reader does not read")

    def destroyed(self, how, paths, rest):
        """The entries this command makes disappear, seen on the real tree before it runs."""
        import fnmatch
        import glob
        want_type = rest[rest.index("-type") + 1] if "-type" in rest and rest.index("-type") + 1 < len(rest) else None
        pattern = rest[rest.index("-name") + 1] if "-name" in rest and rest.index("-name") + 1 < len(rest) else None
        if how == "matching" and any(w.startswith("-") and w not in ("-name", "-type", "-delete") for w in rest):
            raise Closed("find with a test the reader does not model, before -delete")
        for p in paths:
            lex = self.lexical(p)
            hits = sorted(glob.glob(lex)) if GLOB & set(os.path.basename(p)) else [lex]
            for h in hits:
                e = os.path.join(os.path.realpath(os.path.dirname(h)), os.path.basename(h))     # the entry, final link not followed
                if not os.path.lexists(e):
                    continue
                real_dir = os.path.isdir(e) and not os.path.islink(e)
                if how == "files" and not real_dir:
                    self.gone.add(e)
                elif how == "empty_dir" and real_dir and not os.listdir(e):
                    self.gone.add(e)
                elif how == "tree":
                    self.gone.add(e)
                    if real_dir:
                        for d, subs, files in os.walk(e):
                            self.gone.update(os.path.join(d, x) for x in subs + files)
                elif how == "matching":
                    inside = [os.path.join(d, x) for d, subs, files in os.walk(e, topdown=False) for x in files + subs] if real_dir else []
                    for x in inside + [e]:
                        is_dir = os.path.isdir(x) and not os.path.islink(x)
                        if pattern is not None and not fnmatch.fnmatchcase(os.path.basename(x), pattern):
                            continue
                        kind = "l" if os.path.islink(x) else "d" if is_dir else "f"
                        if want_type is not None and kind != want_type:
                            continue
                        if not is_dir or all(os.path.join(x, y) in self.gone for y in os.listdir(x)):
                            self.gone.add(x)                # a directory goes only when nothing is left in it

    def node(self, n):
        k = n.kind
        if k == "list":
            for p in n.parts:
                if p.kind == "operator":
                    if p.op not in (";", "\n"):
                        raise Closed(f"'{p.op}': what runs depends on what happened before")
                else:
                    self.node(p)
        elif k == "pipeline":
            for p in n.parts:
                if p.kind != "pipe":
                    self.node(p)
        elif k == "command":
            words, dead = [], False
            for p in n.parts:
                if p.kind == "word":
                    if p.parts:
                        raise Closed("an expansion in a word")
                    words.append(p.word)
                elif p.kind == "redirect":
                    if isinstance(p.output, int) or p.type in (">&", "<&"):
                        continue
                    if p.output.parts or p.heredoc:
                        raise Closed("an expansion in a redirection")
                    if dead:
                        continue
                    self.op("read" if p.type == "<" else "write", p.output.word)
                    if p.type == "<" and not os.path.exists(self.lexical(p.output.word)):
                        dead = True                     # the shell stops here: the command never runs
                else:
                    raise Closed(f"{p.kind} not modelled")
            if words and not dead:
                self.commands += 1
                self.command(words)
        else:
            raise Closed(f"{k} not modelled")


def read_shell(text, schema):
    try:
        trees = bashlex.parse(text)
    except Exception as e:  # noqa: BLE001
        raise Closed(f"not parsed: {type(e).__name__}") from None
    line = _Line(schema)
    for t in trees:
        line.node(t)
    if line.gone:                               # what the line destroys, per container: files and directories
        count = {}
        for e in line.gone:
            c = _container(os.path.dirname(e), line.containers)
            if c is None:
                raise Closed(f"{e} is outside every container")
            k = "destroy_dirs" if os.path.isdir(e) and not os.path.islink(e) else "destroy_files"
            count[(k, c)] = count.get((k, c), 0) + 1
        line.ops |= {(k, c, n) for (k, c), n in count.items()}
    if line.destroyer:
        line.ops.add(("commands", line.commands, 1))
    return line.ops
