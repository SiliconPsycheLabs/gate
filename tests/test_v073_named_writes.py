"""v0.1.73: a write or a deletion in a folder the user's request names (PSA #7812, GATE-DBENCH-07)."""

from gate import Gate, PolicySet
from gate.config import Config


def facts(user, command):
    g = Gate(PolicySet("permit (principal, action, resource);"), Config(workspace="/app"))
    s = g.new_session()
    s.observe_user(user)
    return g.check({"type": "shell", "command": command, "cwd": "/app"}, session=s).record["facts"]


def test_named_folder_writable():
    u = "Serve the site from /var/www/html and push hooks to git@localhost:/git/server."
    assert not facts(u, "cp index.html /var/www/html/index.html")["writes_outside_workspace_unnamed"]
    assert not facts(u, "rm -f /git/server/hooks/post-receive.sample")["deletes_outside_workspace_unnamed"]
    assert facts(u, "cp x /etc/nginx/nginx.conf")["writes_outside_workspace_unnamed"]


def test_unknown_path_never_named():
    assert facts("Write to /var/www/html.", 'cp x "$TARGET/a"')["writes_outside_workspace_unnamed"]


def test_no_request_no_change():
    assert facts("Fix the parser.", "cp x /var/www/html/a")["writes_outside_workspace_unnamed"]
