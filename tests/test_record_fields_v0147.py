"""Record fields added in v0.1.47: tool_words, invocations, http_path, code_calls, destructive_sql; inline code feeding
deletes, writes and decode_then_execute; git clean; a tool that installs packages; credentials in free text."""

import pytest

from gate import Config
from gate.normalize import normalize

C = Config(workspace="/work/repo", home="/home/agent")
S = lambda c: {"type": "shell", "command": c, "cwd": "/work/repo"}
T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}
PY = lambda code: S(f'python -c "{code}"')


def n(a):
    return normalize(a, C)


def test_tool_words_split_snake_and_camel_case():
    assert n(T("mcp__github__deleteRepository", owner="a"))["tool_words"] == ["delete", "repository"]
    assert n(T("mcp__k8s__delete_deployment", name="api"))["tool_words"] == ["delete", "deployment"]


@pytest.mark.parametrize("cmd,inv", [
    ("npm publish", ["npm publish"]),
    ("gh pr merge 12 --squash", ["gh pr", "gh pr merge"]),
    ("sudo gh auth token", ["gh auth", "gh auth token"]),
    ("redis-cli FLUSHALL", ["redis-cli flushall"]),
])
def test_invocations(cmd, inv):
    assert set(inv) <= set(n(S(cmd))["invocations"])


def test_inline_code_is_not_an_invocation():
    assert n(PY("import shutil; shutil.rmtree('/x')"))["invocations"] == []


def test_http_path():
    assert n({"type": "http", "method": "POST", "url": "https://api.example.com/v1/Transfers?x=1"})["http_path"] == "/v1/transfers"


def test_inline_code_deletes_and_writes_meet_the_file_fields():
    r = n(PY("import shutil; shutil.rmtree('/home/agent/projects')"))
    assert r["deletes"] == ["/home/agent/projects"] and r["deletes_outside_workspace"]
    r = n(PY("open('/work/repo/.claude/settings.json','w').write('{}')"))
    assert r["writes"] == ["/work/repo/.claude/settings.json"] and r["writes_agent_config"]


def test_inline_code_decode_then_exec():
    assert n(PY("exec(__import__('base64').b64decode('cHJpbnQoMSk='))"))["decode_then_execute"]
    assert not n(PY("print(1)"))["decode_then_execute"]


def test_inline_code_calls_and_sql():
    r = n(PY("import sqlite3; sqlite3.connect('/work/repo/a.db').execute('DROP TABLE users')"))
    assert r["destructive_sql"] and "sqlite3.connect" in r["code_calls"]
    assert "stripe.transfer.create" in n(PY("import stripe; stripe.Transfer.create(amount=5)"))["code_calls"]


@pytest.mark.parametrize("cmd,want", [
    ('psql -c "DROP TABLE users"', True), ("redis-cli FLUSHALL", True), ('mongosh --eval "db.dropDatabase()"', True),
    ('psql -c "DELETE FROM users WHERE id = 3"', False), ("redis-cli GET k", False),
])
def test_destructive_sql_in_shell_arguments(cmd, want):
    assert n(S(cmd))["destructive_sql"] is want


def test_git_clean_force_discards_work():
    assert n(S("git clean -fdx"))["git_discard"]
    assert not n(S("git clean -n"))["git_discard"]


def test_a_tool_that_installs_packages_gets_the_package_record():
    r = n(T("mcp__packages__install", name="reqeusts", manager="pip"))
    assert r["package_install"] and r["packages"] == ["reqeusts"] and r["package_unpinned"]
    r = n(T("mcp__packages__install", name="left-pad", version="1.3.0", manager="npm"))
    assert r["packages"] == ["left-pad@1.3.0"] and not r["package_unpinned"]


def test_a_credential_in_free_text_is_a_secret_value():
    r = n(T("mcp__slack__post_message", channel="C1", text="DB_PASSWORD=hunter22 attached"))
    assert "hunter22" in r["tool_secret_values"]
    assert n(T("mcp__slack__post_message", channel="C1", text="the build passed"))["tool_secret_values"] == []


@pytest.mark.parametrize("cmd", [
    'grep -rn "DELETE FROM" app/',
    'git commit -m "guard against DROP TABLE in migrations"',
    "python - <<'EOF'\nP = ['DROP TABLE', 'DELETE FROM x']\nprint(len(P))\nEOF",
])
def test_naming_a_statement_is_not_running_it(cmd):
    assert n(S(cmd))["destructive_sql"] is False


def test_a_path_built_from_a_variable_is_not_read_as_written_out():
    r = n(S("python - <<EOF\nopen('$D/out.jsonl','w').write('x')\nEOF"))
    assert not any("$D" in w for w in r["writes"])


def test_a_where_in_another_string_is_not_a_destructive_statement_in_code():
    code = 'q = text("UPDATE usage SET n = n + 1 " "WHERE user_id = :u"); conn.execute(q)'
    assert n(S(f"python - <<'EOF'\n{code}\nEOF"))["destructive_sql"] is False
