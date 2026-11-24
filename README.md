# gate

A deterministic gate for the actions of AI agents, from [Silicon Psyche Labs](https://splabs.io). Apache-2.0.

This repository is the engine: one piece of software that reads the rules as tables and holds no rule of its own. It
is the engine that runs the gate on [splabs.io](https://splabs.io/products/gate); every version is on the
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

## Checked against the systems' own judges

For each system we wrote its maker's own rule language as a table and ran the real system beside it, as judge, on the
same actions. Twenty are done, among them PostgreSQL grants and row-level security, MySQL grants, the shell and files,
the network, Redis, git, sudo, MinIO policies, Kubernetes pod security and RBAC, HTTP APIs from an OpenAPI document,
Postfix, Terraform plans (Open Policy Agent), pip, systemd services and timers, OpenLDAP, MongoDB, MCP tool servers and
Mosquitto. On PostgreSQL 16 grants, for example, 39,721 of 39,721 actions that had to pass passed and 80,279 of 80,279
that must not pass did not. Where a maker's rule language lets through more than its author meant, the table closes
the gap instead of copying it.

## Claude Code

A hook puts the gate in front of a Claude Code session: Claude Code runs it before every tool call, the hook decides
the call with the same engine and a table for the session (which repositories GitHub calls may touch, which files are
read only, which tools are closed), and each decision goes to the tape. It starts in shadow (nothing is blocked,
everything is recorded), then enforce. It runs today on our own sessions; to put it in front of your team's sessions,
[talk with us](https://splabs.io/products/gate/claude-code) and we write the table with you.

## License

Apache-2.0, see [LICENSE](LICENSE).
