# gate

A deterministic gate for the actions of AI agents.

Every action an agent is about to take (run a shell command, write or delete a file, call a URL, push to git,
install a package, change a service) is turned into a structured record, checked against rules you wrote, and
**allowed**, **denied** or **held for a person**. The model gets a fixed reply. Same action, same rules, same answer,
every time.

Built for agents that run on models you own (an open-weights model behind vLLM driven by an agent framework, or a
hand-written loop), where nothing between the model and your shell decides what is allowed.

From [Silicon Psyche Labs](https://splabs.io). Apache-2.0.

## Why deterministic

You cannot tell from text alone whether an action is the one you wanted: a planted instruction and a real request
can look exactly the same to any classifier. So the gate does not try to guess intention. It enforces what you
declared: which directories can change, which hosts can be reached, which branches can be pushed, which operations
need a person. Its correctness is measured against your rules, never against what the agent "meant", and it is
not a safety rating.

What it gives you is a ceiling on what an agent can do, and an exact count of how often the agent tried to go past it.

Every input a rule reads is computed deterministically from the action and the session transcript (parsing, path
resolution, string matching for provenance). No model, classifier or probability score feeds a decision: the same
action in the same session always gets the same answer, and an action either passes or it does not.

## Install

```bash
pip install "git+https://github.com/SiliconPsycheLabs/gate@v0.1.45"
```

Requires Python 3.10+. Rules are evaluated with [Cedar](https://www.cedarpolicy.com/) (`cedarpy`); shell commands are
parsed with `bashlex`.

This package is the engine: it normalises actions, computes provenance and evaluates Cedar rules. It ships no rules.
The maintained rule packs, drawn from what agents actually try, are served by the gate service on
[splabs.io](https://splabs.io); on your own machine the engine runs the rules you write.

## Claude Code

Every action of your Claude Code sessions (shell commands, file writes, web fetches, MCP tool calls) goes to the gate
before it runs. Create a gate-only key in Settings on [splabs.io](https://splabs.io) (it starts with `psa_gate_` and
works only on the gate). Then install it one of two ways; both run the same hook.

**As a Claude Code plugin** (no pip; needs Python 3 on the machine). Inside Claude Code:

```
/plugin install splabs-gate --marketplace SiliconPsycheLabs/gate
```

On Claude Code older than 2.1.275, run `/plugin marketplace add SiliconPsycheLabs/gate` and then
`/plugin install splabs-gate@splabs`. Claude Code asks for the key (kept in the system's secure store), the mode
and the hosts the agent may contact without asking; `/config` changes them later. The plugin (folder
`claude-code-plugin/`) ships the hook only: if the service cannot be reached in enforce mode, an action that cannot be
checked is refused. With the package installed too (below) and `GATE_PACKS_DIR` pointing to a directory of rule
packs, the engine decides on your machine instead.

**With pip:**

```bash
pip install "git+https://github.com/SiliconPsycheLabs/gate@v0.1.45"
gate claude-code install --key psa_gate_...
```

`gate claude-code status` shows the setup, `gate claude-code uninstall` removes the hook. Options: `--scope project`
(this repository only), `--egress host1,host2` (hosts allowed without asking), `--redact-file` (a `KEY=value` file
whose values are never sent). If both are installed, the plugin's hook stands down and this one decides.

Either way it starts in **shadow mode**: the gate decides and logs, nothing is blocked, and you see on the console what
it would have stopped. When the count looks right, switch to **enforce** (the plugin's Mode option, or the same
command with `--mode enforce`): a refused action is refused in Claude Code with the rule's fixed reply, a held one
becomes Claude Code's normal "allow?" prompt and your answer is logged on the decision. The service's rules protect the hook
itself in enforce mode: an agent's edits to `.claude/settings*.json`, the hooks, `~/.claude/plugins/` and
`~/.splabs-gate` are refused. macOS and Linux.

## Quick start

```cedar
// my_rules.cedar
@id("permit-all")
permit (principal, action, resource);

@id("no-force-push")
@reason("force pushes are not allowed.")
forbid (principal, action, resource)
when { context.n.git_force };
```

```python
from gate import Gate, Config, PolicySet

gate = Gate(PolicySet.from_paths(["my_rules.cedar"]), Config(workspace="/work/repo"), log_path="gate.jsonl")
session = gate.new_session()
session.observe_user("The tests in tests/test_api.py fail, please fix them.")

d = gate.check({"type": "shell", "command": "pytest -q tests/test_api.py"}, session=session)
d.outcome  # "allow"

d = gate.check({"type": "shell", "command": "git push --force origin main"}, session=session)
d.outcome  # "deny"
d.reply    # "DENIED by rule no-force-push: force pushes are not allowed. ..."
```

With a directory of rule packs (`common.cedar` plus `coding.cedar`, `ops.cedar`, `strict.cedar`, `harness.cedar`), set
`GATE_PACKS_DIR` or call `gate.set_packs_dir(...)`, then `Gate.from_pack("coding", ...)` loads `common` and `coding`.

Wrap your tool executor so nothing runs without the gate:

```python
from gate.adapters import action_from_openai_tool_call, guarded

run = guarded(gate, session, execute=my_tool_executor, on_confirm=ask_a_human)
result = run(action_from_openai_tool_call(tool_call))  # executes, or returns the gate's fixed reply
```

Tell the session what the tools returned, so the gate knows where each value came from:

```python
session.observe_tool_output("read_1", file_contents)
```

## Command line

```bash
gate check action.json --policies my_rules.cedar --config config.json --transcript transcript.json
gate validate my_rules.cedar
gate replay gate.jsonl --policies my_rules.cedar
gate packs
```

`check` exits 0 on allow, 1 on deny, 2 on confirm. `validate` checks every rule against the context schema, so a
rule that names a field that does not exist is caught before it runs. `replay` re-runs a decision log against new
rules and reports which decisions would change: it is the tool for writing rules from what your agents actually did.
`--pack` loads packs from `GATE_PACKS_DIR`; `gate packs` lists which are installed. See `examples/`.

## Actions

| `type` | fields |
|---|---|
| `shell` | `command`, optional `cwd` |
| `file.read`, `file.write`, `file.delete` | `path`, optional `cwd` |
| `http` | `url`, optional `method`, `body` |
| `git`, `package.install`, `service` | `argv` (list), optional `cwd` |
| `tool` | `name`, `arguments` (object or JSON string): a tool that is none of the above, such as an MCP server's tool (`mcp__<server>__<tool>`) or a harness built-in |

An action no rule permits is denied.

A `tool` call is recorded by name: `tool_name`, `tool_server` (the MCP server, empty for a built-in), `tool_verb_class`
(`read` when the name starts with a reading verb such as `get`, `list`, `search`; otherwise `write`; `check` followed by an active test such as `sqli`, `xss`, `ports` or `exploit` is a `write`) and
`tool_targets`, the values of the arguments that name a target (`to`, `cc`, `recipient`, `email`, `owner`, `repo`,
`channel`, `account`, `url`, `webhook`, `assignee` and the like, at any depth). Targets get a provenance like hosts and
paths do.

What a tool call reaches is recorded in the same fields as a shell command or an HTTP request, so the same rules
apply to it. A tool that runs commands (a name with `execute`, `run`, `shell`, `terminal`, `command` and the like, and
a `command`, `cmd` or `script` argument) has its command normalised as a shell command (`tool_shell_command`). A full
URL in a `url`, `endpoint`, `webhook` or similar argument is a network request to that host (`hosts`, `urls`). A read
from a secret store sets `tool_reads_secret`; a call to an MCP server that is not on the agent's own machine sets
`tool_outbound`; a tool named for sending a file to an outside server with a local path in its arguments sets
`tool_uploads_local_file`. The files a tool reads, writes or deletes (`path`, `file`, `source`, `destination` and the
like, at any depth) go to `reads`, `writes` and `deletes`; the hosts in a probe tool's `host`, `target`, `ip`,
`domain` arguments go to `hosts`. An action that moves money sets `moves_money` and `payment_targets`.

Report the tool definitions the agent was given with `Session.observe_tools(definitions, server=...)` at the start
and whenever they are listed again (MCP, OpenAI and Anthropic shapes). The first definition of each tool is its pin;
a call to a tool whose description or parameters no longer match the pin sets the fact `tool_definition_changed`.
`Session.repin(...)` makes the new definition the pin.

Other fields a rule can read: `tool_words` (the words of a tool's name, `deleteRepository` gives `delete`,
`repository`), `invocations` (each program with its first one or two words, `npm publish`, `gh pr merge`), `http_path`
(the path of an HTTP request), `code_calls` (the dotted calls in inline code, lower-cased) and `destructive_sql` (a
destructive statement sent to a database from a client or from code). A tool that installs packages gets the same
package fields as the install command.

Shell commands are parsed and normalised: the commands run (through `sudo`, `env`, `xargs` and other wrappers), pipes,
redirects, substitutions, `cd` changes, paths read, written and deleted, hosts and URLs, git push targets and force
flags, package names, pinning and registries, the verb class of service tools (read, mutate, destroy).

**It fails closed.** A command that does not parse, or that runs hidden code (`eval`, `sh -c`, a sourced script,
piping into an interpreter, decoding then executing), is marked so in the record: the shell is a full language, and
what cannot be normalised is never read as harmless. A rule that errors at evaluation denies the action; it is never
skipped.

## Rules

Rules are Cedar policies. The request is:

- principal `Agent::"<name>"`, action `Action::"<type>"`, resource `Target::"<type>"`;
- `context.n`: the normalised record (see `gate/normalize.py::default_record` for every field);
- `context.facts`: provenance sets (`from_user`, `from_system`, `from_tool_output`, `from_model`), session facts
  (`secret_read_in_session`, `denials_in_session`, `holds_in_session`);
- `context.config`: `workspace`, `egress_hosts`, `environment`, `change_window`, `default_branches`.

Annotations the gate reads:

```cedar
@id("egress-from-data")            // stable id, used in replies and logs (required on forbid)
@outcome("confirm")                // on a forbid: hold for a person instead of denying
@reason("this address first appeared in tool output, not in the user's request.")
forbid (principal, action, resource)
when { context.n.network && context.n.hosts.containsAny(context.facts.from_tool_output) };
```

Nothing is allowed unless a `permit` matches, and a `forbid` always wins over a `permit`.

### The maintained rules

The rule packs we maintain (`common`, `coding`, `ops`, `strict`, `harness`) are not in this repository. They are
served by the gate service on [splabs.io](https://splabs.io), where each decision names the rule that made it and the
count is shown; your own rules sit on top of them there, or run alone with this engine.

### Provenance

`Session` records the user's messages and the tool outputs. Each host, URL, path, package name and tool target in an action gets a
source: `user` (named by the user), `system` (in your configuration), `tool_output` (first seen in what a tool
returned) or `model` (appears nowhere before). An attacker who plants text in a web page or a file must plant its own
address or package name too, and that value arrives with `tool_output` provenance however the text is worded. A package is matched by its name: a version, extras or an
index marker attached to it do not change where the name came from.

## Measured

On 3,000 distinct shell commands from real coding-agent sessions (OpenHands on Python repositories,
`nebius/SWE-rebench-openhands-trajectories`) every command parses. On the 7,587 human-written one-liners of NL2Bash,
99.7% parse; 20 of the rest are not valid shell as written.

## Log

With `log_path`, every decision is appended as one JSON line (action, normalised record, facts, outcome, rule ids),
flushed to disk at once. Use it to write new rules (`gate replay`) and to count: denials and holds per 100 tasks, per
rule, and how many of them were false blocks on tasks you mark as legitimate.

## Limits

- The gate checks the action, not what the program it launches does afterwards. Run agents in a sandbox (container,
  restricted user, network policy) as well: the gate decides what is attempted, the sandbox limits what an allowed
  command can reach.
- Path and host extraction from arbitrary programs is best effort; for unknown programs only path-like arguments and
  redirects are seen. Tighten with rules on `context.n.commands`.
- `/tmp` is writable by default (`Config.extra_writable`); set it to `[]` to forbid.
- `~` is the home of the user the gate runs as. When the gate runs on another machine or as another user (a hosted
  gate), set `Config.home` to the agent's home.
- `Config.model_paths` lists the directories that hold the models in use (default: the Hugging Face, torch, Ollama
  and LM Studio caches under the agent's home); a write, move or deletion under them, or of a weights file anywhere,
  sets `writes_model_weights`.
- `Config.workspaces_root`: the directory that holds the workspaces of agents that share a machine.
- `ls`, `find`, `du` and `tree` with no path read the current directory: `cd /root && ls` is a look at `/root`.
- Code given inline to an interpreter (`python -c`, `node -e`, a here-document) is scanned for the plain forms of
  network access, process start, a read of the whole environment, files removed or written with a path written out,
  text decoded and then executed, and statements sent to a database. Code built at run time is out of reach of any
  reading of text: keep the sandbox.
- Provenance is string matching. A value the attacker gets the user to type is `user`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

`ci/github-actions-test.yml` is the CI workflow (tests on Python 3.10 to 3.13); it goes in `.github/workflows/`.

## License

Apache-2.0. See `LICENSE`.
