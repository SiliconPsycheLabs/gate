"""The git reader: from a push of one ref to the one operation it performs. No rule here.

    read_git(push, schema) -> {(operation, ref, None)}
        push: {"ref": "refs/heads/x", "source": "<commit in the local repository>" or "" to delete}
        operation: create, update (the new commit descends from the old), rewrite (it does not), delete,
        delete_absent (a delete of a ref that is not there);
        no operation when the ref is already there
        schema: {"local": path of the working repository, "remote": path of the repository pushed to}

It asks the two repositories: what the ref points to now, what the source is, and whether one descends from the
other. A tag that already exists and is pushed again to another commit is a rewrite.
"""
import subprocess


def _git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def read_git(push, schema):
    if not isinstance(push, dict) or set(push) != {"ref", "source"}:
        raise ValueError("a push names one ref and one source")
    ref, source = push["ref"], push["source"]
    if not ref.startswith("refs/") or _git(schema["remote"], "check-ref-format", ref)[0] != 0:
        raise ValueError("not a ref name")
    code, old = _git(schema["remote"], "rev-parse", "-q", "--verify", ref + "^{}")
    code2, old_raw = _git(schema["remote"], "rev-parse", "-q", "--verify", ref)
    old = old if code == 0 else None
    if source == "":
        if old is None:
            return {("delete_absent", ref, None)}    # nothing is there; the server still asks its rules
        return {("delete", ref, None)}
    code, new = _git(schema["local"], "rev-parse", "-q", "--verify", source + "^{commit}")
    if code != 0:
        raise ValueError("the source is not a commit of the local repository")
    if old is None:
        return {("create", ref, None)}
    if old == new and _git(schema["local"], "rev-parse", "-q", "--verify", source)[1] == old_raw:
        return set()                            # already there: the push changes nothing
    if ref.startswith("refs/tags/"):
        return {("rewrite", ref, None)}
    descends = _git(schema["local"], "merge-base", "--is-ancestor", old, new)[0] == 0
    return {("update" if descends else "rewrite", ref, None)}
