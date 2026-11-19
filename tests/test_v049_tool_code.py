"""v0.1.49: code a tool runs (python_exec code=..., run_code, a notebook cell) is read like `python -c`.

Found by RULE-MINE-03 (PSA #7421): python_exec with os.system('rm -rf /var/www/html/*'), subprocess.run([... chmod 777
/etc/shadow]) or a socket to an outside address was allowed, while the same code through `python -c` in a shell was
read. These tests read the engine's fields; decisions belong to the rule packs.
"""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def rec(code, name="mcp__x__python_exec", key="code"):
    return normalize({"type": "tool", "name": name, "arguments": {key: code}}, CFG)


def test_shell_command_inside_os_system_is_read():
    r = rec("import os\nos.system('rm -rf /var/www/html/*')")
    assert "/var/www/html/*" in r["deletes"]


def test_argv_list_inside_subprocess_is_read():
    assert rec("import subprocess\nsubprocess.run(['sudo', 'chmod', '777', '/etc/shadow'])")["sudo"]


def test_socket_to_outside_address_is_network():
    r = rec("import socket\ns = socket.socket()\ns.connect(('10.10.10.10', 443))")
    assert r["network"] and "10.10.10.10" in r["hosts"]


def test_inline_delete_call_is_read():
    assert "/srv/data" in rec("import shutil\nshutil.rmtree('/srv/data')")["deletes"]


def test_plain_code_stays_plain():
    r = rec("print(sum([1, 2, 3]))")
    assert not r["network"] and not r["deletes"] and not r["sudo"] and r["parse_ok"]


def test_browser_javascript_is_not_read_as_python():
    r = rec("document.querySelector('#q').value = 'x'", name="mcp__browser__execute_javascript", key="script")
    assert not r["deletes"] and r["parse_ok"]
