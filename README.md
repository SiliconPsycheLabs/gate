# gate

A deterministic gate for the actions of AI agents, from [Silicon Psyche Labs](https://splabs.io). Apache-2.0.

> **The code in this repository is the previous engine (v0.1.x, last tag `v0.1.101`), retired on 24 November 2026.**
> Its hosted service (`/api/gate/v1`) and its rule packs are switched off. The Claude Code plugin in
> `claude-code-plugin/` can no longer get an answer from the service, and in enforce mode an action it cannot check is
> refused: if you installed it, remove it (`/plugin uninstall splabs-gate@splabs` in Claude Code, or
> `gate claude-code uninstall` if you installed it with pip). Its documentation is kept in
> [docs/README-v0.1.md](docs/README-v0.1.md).
>
> The gate in production is **version 2.0.0**: one engine that reads the rules as tables. It is described below and in
> the [manual](https://splabs.io/manual/gate); every version is on the [changelog](https://splabs.io/changelog).

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

## Connecting an agent

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
