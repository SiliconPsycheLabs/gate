"""v0.1.53: a write to a path component named .git is a write to git's internals at any depth and in any letter case.

Found by SATA-VVAH-01 (PSA #7640, probing the confinement rules of Visa's Vulnerability Agentic Harness on the gate):
`.git/hooks/pre-commit` was held, but `.GIT/hooks/post-checkout`, `.Git/config`, `.git/HOOKS/pre-commit` (the same files
on macOS and Windows) and a nested `vendor/lib/.git` file with a `gitdir:` line were allowed. These tests read the
engine's fields; decisions belong to the rule packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def write(path):
    return normalize({"type": "tool", "name": "Write", "arguments": {"file_path": path, "content": "id"}}, CFG)


def shell(cmd):
    return normalize({"type": "shell", "command": cmd}, CFG)


def test_lowercase_hooks_and_config_still_held():
    for p in ("/work/repo/.git/hooks/pre-commit", "/work/repo/.git/config", "/work/repo/app/../.git/hooks/pre-push"):
        assert write(p)["writes_git_internals"], p


def test_other_letter_cases_are_git_internals():
    for p in ("/work/repo/.GIT/hooks/post-checkout", "/work/repo/.Git/config", "/work/repo/.git/HOOKS/pre-commit"):
        assert write(p)["writes_git_internals"], p


def test_shell_redirect_into_mixed_case_hooks():
    assert shell("echo id > .GIT/hooks/pre-commit")["writes_git_internals"]


def test_nested_git_file_is_git_internals():
    assert write("/work/repo/vendor/lib/.git")["writes_git_internals"]
    assert shell("printf 'gitdir: /tmp/evil' > vendor/lib/.git")["writes_git_internals"]


def test_gitignore_and_github_are_not_git_internals():
    for p in ("/work/repo/.gitignore", "/work/repo/.github/workflows/ci.yml", "/work/repo/.gitattributes",
              "/work/repo/docs/git/hooks.md"):
        assert not write(p)["writes_git_internals"], p


def test_delete_of_mixed_case_git_dir_is_protected():
    assert shell("rm -rf .GIT")["deletes_protected"]
