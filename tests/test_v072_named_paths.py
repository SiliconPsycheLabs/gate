"""v0.1.72: a path the user's request names is in the task's scope (PSA #7812, GATE-DBENCH-06)."""

from gate import Gate, PolicySet
from gate.config import Config


def facts(user, command):
    g = Gate(PolicySet("permit (principal, action, resource);"), Config(workspace="/app"))
    s = g.new_session()
    s.observe_user(user)
    return g.check({"type": "shell", "command": command, "cwd": "/app"}, session=s).record["facts"]


def test_named_path_in_scope():
    f = facts("Find the persistence entries under /etc/cron.d and /var/spool/cron.", "ls -la /etc/cron.d/")
    assert not f["reads_outside_scope_unnamed"]
    f = facts("Find the persistence entries under /etc/cron.d.", "cat /etc/shadow")
    assert f["reads_outside_scope_unnamed"]


def test_shallow_names_name_nothing():
    f = facts("Look at /etc and fix it.", "cat /etc/hosts")
    assert f["reads_outside_scope_unnamed"]


def test_named_shared_file_is_not_unowned():
    f = facts("Summarise the log at /tmp/run/output.log.", "cat /tmp/run/output.log")
    assert not f["reads_unowned_shared"]
    f = facts("Summarise the log at /tmp/run/output.log.", "cat /tmp/daemon.log")
    assert f["reads_unowned_shared"]


def test_scp_style_path_named():
    f = facts("Set up a git server reachable as git@localhost:/git/server and deploy pushes to /var/www.",
              "ls /git/server/hooks")
    assert not f["reads_outside_scope_unnamed"]


def test_url_path_still_not_a_path():
    from gate.normalize import normalize
    r = normalize({"type": "shell", "command": "curl -s https://x.org/tests/a"}, Config(workspace="/app"))
    assert not r["reads_outside_scope"] and not any(p.startswith("//") for p in r["text_paths"])


def test_tool_caches_in_scope():
    from gate.normalize import normalize
    cfg = Config(workspace="/app", home="/root")
    assert not normalize({"type": "shell", "command": "ls /root/.gradle/caches"}, cfg)["reads_outside_scope"]
    assert normalize({"type": "shell", "command": "ls /root/.daytona"}, cfg)["reads_outside_scope"]
