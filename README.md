# gate

A deterministic gate for the actions of AI agents, from [Silicon Psyche Labs](https://splabs.io). Apache-2.0.

This repository is the engine (`gate_table`): one piece of software that reads the rules as tables and holds no rule of
its own, the one that runs the gate on [splabs.io](https://splabs.io/products/gate). Beside it is the SDK
(`splabs_gate`), which puts the hosted gate in front of an agent. Every version of the engine is on the
[changelog](https://splabs.io/changelog). The table format is in [docs/FORMAT.md](docs/FORMAT.md).

> **Coming from v0.1?** The previous engine (Cedar rules, the `gate` command line, the Claude Code plugin) was retired
> on 24 November 2026 and its hosted service is switched off. If you installed the plugin, remove it
> (`/plugin uninstall splabs-gate@splabs` in Claude Code, or `gate claude-code uninstall` if you installed it with
> pip): in enforce mode it refuses every action it can no longer check. Its code is kept at the tag `v0.1.101` and its
> documentation in [docs/README-v0.1.md](docs/README-v0.1.md).

## Install

```bash
pip install "git+https://github.com/SiliconPsycheLabs/gate"
```

Python 3.10 or later. The package is `gate_table`; it needs `cel-python` (expressions), `sqlglot` (SQL), `bashlex`
(shell) and `packaging` (pip).

## Quick start

A table for a billing agent ([examples/payments.json](examples/payments.json)): it may read invoices and pay a
validated invoice of up to 5,000; removing a supplier is closed; nothing else is in the menu.

```python
import json
from gate_table import manager

table = json.load(open("examples/payments.json"))
rec, state = manager.decide(table, {"tool": "pay_invoice", "args": {"number": "INV-2"}}, view)
rec["outcome"], rec["reason"], rec["rule"]
# ('nopass', 'invoice INV-2 is registered: only a validated invoice is paid', 'pay_invoice#1')
```

`view` is how the gate reads the company's records: the gate keeps no copy of them. In
[examples/quickstart.py](examples/quickstart.py) it is a few records in memory; in a company it is a small connector
next to its own system (the calls it answers are listed in `gate_table/view.py`). Run the example:

```bash
python examples/quickstart.py
```

```
pay_invoice {"number": "INV-1"}
    passes  (rule: pay_invoice)
pay_invoice {"number": "INV-2"}
    does not pass: invoice INV-2 is registered: only a validated invoice is paid  (rule: pay_invoice#1)
pay_invoice {"number": "INV-3"}
    does not pass: invoice INV-3 is over 5,000: a person pays it  (rule: pay_invoice#2)
pay_invoice {"number": "INV-1", "iban": "XX00 0000"}
    does not pass: field not in the function's form: iban  (rule: form)
delete_supplier {"id": "S-7"}
    does not pass: suppliers are removed by a person, not by the agent  (rule: delete_supplier:closed)
wire_money {"to": "anyone"}
    does not pass: this function is not in the menu  (rule: menu)
```

The engine ships no maintained rules: you write your tables, or the hosted gate on splabs.io serves the ones we
maintain, drawn from what agents actually try.

## What the gate does

An agent acts on systems: a company function, a database, a shell, an HTTP API, a mail server, a document store, a
package manager. It asks for one action at a time, through a tool. Before the action runs, it goes to the gate, which
gives one of two answers:

- **passes**: the action runs;
- **does not pass**: the action does not run, and the model reads the rule's fixed reason as the tool's result.

The gate is deterministic. A rule reads only facts: the action as the agent asked it, and the company's records about
it (the state of an invoice, who is acting, the time). No score, no reading of the model and no guess reaches a
decision, and the gate keeps no memory of a session. The same action on the same facts always gets the same answer.

A planted instruction can make a model want anything. The model can do only what the owner's rules allow, and every
decision is counted.

## The rules: one table per agent

The rules for an agent are one table: the tools it may call, the fields of each, and the conditions under which a call
passes ("only a validated invoice is paid", "an amount up to 5,000", "whoever registered the invoice does not validate
it"). For a tool that takes a language (SQL, shell, HTTP, MongoDB, mail, pip, a Terraform plan, MQTT), a translator
turns the text into the operations it performs, and each one is checked against what the table opens.

What is not in the table does not pass: a tool not listed, a field not in its form, an SQL function or a shell option
nobody wrote down. If the table cannot be read, or the company's system does not answer, the action does not pass.

Where a rule carries a lock, a person whose role the lock names can open one exact action, once, for one session.
Nothing waits for a person: the agent asks again, and the decision records who opened it.

## Connecting an agent to the hosted gate

The service is at `https://splabs.io/api/gate/table/v1`, with a gate key of your account (prefix `psa_gate_`), which
can ask for decisions and nothing else. Before each action runs, send it:

```bash
curl -s https://splabs.io/api/gate/table/v1/manager/decide \
  -H "Authorization: Bearer $GATE_KEY" -H "Content-Type: application/json" \
  -d '{"table": "payments", "session": "task-1842", "agent": "billing",
       "tool": "pay_invoice", "args": {"number": "INV-0042"}}'
```

The reply carries `ref`, `passes`, `reason`, `rule`, `opened`, `table` and `table_version`. Then:

1. If `passes` is true, run the action, and send `POST /manager/ran` with `session` and `ref` once it has run (or
   `POST /manager/release` if it did not run).
2. If `passes` is false, do not run it: give `reason` to the model as the tool's result.
3. If the service answers with an error or does not answer, do not run the action.

Every decision is written to the tape, which you read, with the rules, in the console at
[/gate/console](https://splabs.io/gate/console).

## The SDK: the hosted gate in front of an agent

The package `splabs_gate` carries an agent's actions to the hosted gate and its answers back; it holds no rule.
Standard library only (each framework is imported only by its own adapter). Settings, each also a keyword of
`Gate(...)`: `GATE_TOKEN` (a gate key), `GATE_TABLE`, `GATE_SESSION`, `GATE_AGENT`, `GATE_URL`. If the gate cannot be
reached, the action does not pass.

```python
from splabs_gate import Gate

gate = Gate(table="payments", session="task-1842", agent="billing")
d = gate.decide("pay_invoice", {"number": "INV-0042"})
if d.passes:
    pay_invoice("INV-0042")
    gate.ran(d)
else:
    tell_the_model(d.reason)
```

| Where your agent runs | Adapter |
|---|---|
| Any Python function an agent calls | `splabs_gate.guard`: the `@guard(gate)` decorator |
| OpenAI-style function calling (the OpenAI API, vLLM, Ollama, LM Studio, llama.cpp server ...) | `splabs_gate.openai.run_tool_calls` |
| LangChain and LangGraph tools | `splabs_gate.langchain.gate_tools` (extra `langchain`) |
| The OpenAI Agents SDK | `splabs_gate.openai_agents.gate_agent` (extra `openai-agents`) |
| CrewAI | `splabs_gate.crewai.gate_tools` (extra `crewai`) |
| Any MCP client (Claude Desktop, Cursor, Windsurf, Claude Code ...) in front of a local server | `python -m splabs_gate.mcp_proxy --table T -- <server command>` |
| An MCP client in front of a remote server (Streamable HTTP) | `python -m splabs_gate.mcp_http_proxy --table T --upstream <url>` |
| Coding agents with hooks: Claude Code, OpenAI Codex CLI, Cursor | `python -m splabs_gate.hooks --agent claude-code --table T` |

Each module's first lines show how to wire it.

## Checked against the systems' own judges

For each system we wrote its maker's own rule language as a table and ran the real system beside it, as judge, on the
same actions. Twenty are done, among them PostgreSQL grants and row-level security, MySQL grants, the shell and files,
the network, Redis, git, sudo, MinIO policies, Kubernetes pod security and RBAC, HTTP APIs from an OpenAPI document,
Postfix, Terraform plans (Open Policy Agent), pip, systemd services and timers, OpenLDAP, MongoDB, MCP tool servers and
Mosquitto. On PostgreSQL 16 grants, for example, 39,721 of 39,721 actions that had to pass passed and 80,279 of 80,279
that must not pass did not. Where a maker's rule language lets through more than its author meant, the table closes
the gap instead of copying it.

## Claude Code

The hook in `splabs_gate.hooks` puts the gate in front of a Claude Code session (and of Codex CLI and Cursor): the agent
runs it before every tool call, the gate decides the call against the session's table (which repositories GitHub calls
may touch, which files are read only, which tools are closed), and each decision goes to the tape. In
`.claude/settings.json`:

```json
{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command",
  "command": "python -m splabs_gate.hooks --agent claude-code --table coding_agent"}]}]}}
```

`GATE_HOOK_MODE=shadow` (the default) records every decision and lets the call run; `enforce` refuses a call that does
not pass, and any call the gate could not decide. Start in shadow, read the tape, then enforce. To write the table for
your team's sessions with us, [talk with us](https://splabs.io/products/gate/claude-code).

## License

Apache-2.0, see [LICENSE](LICENSE).
