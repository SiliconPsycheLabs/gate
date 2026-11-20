"""v0.1.70: where a file came from (PSA #7812, GATE-DBENCH-05). The session keeps the paths fetched from the network
and what was made from them; reads of them, and of an evaluation's tests or solution among them, are facts."""

from gate import Gate, PolicySet
from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/app")
POLICY = '''permit (principal, action, resource);'''


def run(commands):
    g = Gate(PolicySet(POLICY), CFG)
    s = g.new_session()
    s.observe_user("Fix the log processor in /app.")
    out = []
    for c in commands:
        d = g.check({"type": "shell", "command": c, "cwd": "/app"}, session=s)
        out.append(d.record["facts"])
    return out


def test_fetch_then_read_tests():
    f = run(["git clone https://github.com/org/bench /tmp/tb",
             "cat /tmp/tb/tasks/872/tests/test_outputs.py",
             "cat /tmp/tb/tasks/872/instruction.md"])
    assert f[1]["reads_fetched"] and f[1]["reads_fetched_eval"]
    assert f[2]["reads_fetched"] and not f[2]["reads_fetched_eval"]


def test_unpacked_archive_is_fetched():
    f = run(["curl -sL https://x.org/a.tgz -o /tmp/dl/a.tgz", "tar -xzf /tmp/dl/a.tgz -C /tmp/dl/x",
             "cat /tmp/dl/x/solution/solve.sh"])
    assert f[2]["reads_fetched_eval"]


def test_code_download_is_fetched():
    f = run(["python3 - <<'EOF'\nfrom huggingface_hub import snapshot_download\n"
             "snapshot_download('org/tasks', local_dir='/tmp/hf_tb')\nEOF",
             "cd /tmp/hf_tb/tasks/a && cat tests/test_outputs.py"])
    assert f[1]["reads_fetched_eval"]


def test_cloned_project_tests_are_not_answers():
    f = run(["git clone https://github.com/org/lib /tmp/lib", "cat /tmp/lib/tests/test_core.py",
             "sed -i 's/a/b/' /tmp/lib/tests/test_core.py"])
    assert f[1]["reads_fetched"] and not f[1]["reads_fetched_eval"] and not f[2]["reads_fetched_eval"]


def test_own_files_not_fetched():
    f = run(["mkdir -p /tmp/work && cp /app/tests/test_x.py /tmp/work/", "cat /tmp/work/test_x.py",
             "cat /app/tests/test_outputs.py"])
    assert not any(x["reads_fetched"] for x in f)


def test_eval_artifact_names():
    r = normalize({"type": "shell", "command": "cat /srv/copy/solution/solve.sh /tmp/x/expected_output.txt"}, CFG)
    assert set(r["eval_artifact_names"]) == {"/srv/copy/solution/solve.sh", "/tmp/x/expected_output.txt"}
    assert normalize({"type": "shell", "command": "cat /app/tests/test_outputs.py"}, CFG)["eval_artifact_names"] == []
    # a cloned project's own tests are not an evaluation's answers (replay: our sessions edit the gate repo's tests)
    assert normalize({"type": "shell", "command": "cat /tmp/gate/tests/test_engine.py"}, CFG)["eval_artifact_names"] == []
