# The gate table: format

A table is one JSON document per agent (or per group of agents with the same rights). It is the whole law for that
agent: what is not in it does not pass. In plain words a table is the **rules**, a door is a **tool**, a container is
a **resource**, a reader is a **translator**; the keys below keep their short names.

## What a table holds

| Key | What it holds |
|---|---|
| `table`, `version`, `source` | name, number of the published version, where the rules come from |
| `doors` | the menu: one entry per function the agent may call, and one per language door |
| `every_door`, `every_door_except` | conditions that hold for every door, and the doors they skip (example: "identify the user first") |
| `containers`, `schema` | for language doors: folders, tables and columns, hosts, addresses, with what may be done on each; a right given as a list names the parts it covers, `except` closes parts inside an open right |
| `limits` | numbers a reader counts, with the most allowed (`{"recipients": 5}`); an operation over it does not pass |
| `transactions`, `http` | the SQL door may open and close its own transactions inside one text; the routes of an HTTP API, compiled from its OpenAPI document |
| `network` | for the network door: address ranges and ports that may be reached |
| `state_field`, `empty_allowed` | name of the field that holds a record's state; whether an empty text field is accepted |

## A door

```json
"pay_invoice": {
  "does": "pay a validated invoice",
  "form": {"number": "string"},
  "requires": [
    {"if": "state_in", "record": "invoice", "id": "number", "states": ["validated"],
     "else": "invoice {id} is {state}: only a validated invoice is paid"}
  ]
}
```

- `does`: one sentence, for people.
- `form`: every field and its type (`string`, `number`, `integer`, `list`, `object`). A call with a field that is not
  in the form, or without one that is, does not pass. A function whose field decides what the function does is split
  into several doors.
- Then exactly one of:
  - `requires`: a list of conditions, all of which must hold;
  - `closed`: a fixed reason. The door is in the menu and shut; only an opening by a person lets one call through;
  - `language` + `arg`: a language door. A translator turns the text into atomic operations and each one is checked
    against `containers` / `schema` / `network`. `arg` may name a field inside a field (`arguments.command`);
    `languages` lists several texts of one call, every one read; `schemas` gives each language its own schema.
- `bind`: records the conditions may read, by name (`{"res": {"record": "reservation", "id": "reservation_id"}}`, a
  record reached through another one with `id_from`, a whole collection with `all`). `each` binds only the entries
  the action names (`{"flights": {"each": "flight", "keys": ["args.flights[].flight_number"]}}`): the company's
  system is asked for those entries alone. Bound names are read in the order of what they need; a circle among them
  is a table the engine refuses.
- `binds`: the value the company's side notes for the conversation when this door returns. The gate remembers
  nothing: the company keeps the conversation's record and sends it with each action, and an expression reads it as
  `session.<name>` (helper: `engine.noted`).
- `pairs`: two list fields read side by side (item to replace, item that replaces it).
- `moves_to`: where the company's system moves a record when it carries the action out. Descriptive: the engine does
  not decide on it.

## Conditions

Each condition has `if` (its kind) and `else` (the fixed reason given when it fails).

| Kind | Reads | Example |
|---|---|---|
| `record_exists` | a record | the invoice exists |
| `state_in` | a record's state | the invoice is validated |
| `linked_state_in` | the state of a record reached through another | the invoice's supplier is active |
| `record_field_max`, `arg_max` | a number | amount up to 5,000 |
| `arg_in_list`, `arg_ends_with` | a field against a list of the owner | the address is one of the company's |
| `time_between` | the clock | between 08:00 and 18:00 |
| `actor_not_field` | who is acting | whoever registered the invoice does not validate it |
| `address_allowed` | the network list | this address and port are in an allowed range |
| `no_planted_value` | every text of the call, at any depth, also URL-decoded | none of the fake keys the owner planted is used |
| `expr` | anything bound | the payments add up to the price |

`expr` is an expression in CEL (Common Expression Language), a public standard for policy checks: no loops of its
own, no side effects, always ends. An expression that cannot be evaluated does not pass.

## What the gate keeps and what it reads

The gate keeps no memory of a session: no counter, no switch, no value bound for a session, no sum over a session. A
table that names `counters`, `switches` or a session limit is refused by the validator. Everything a rule reads comes
with the action or from the company's records, through the **view**: the state of a record, a count or a limit as a
field of a record, the conversation's record (`session`), whether a transaction is open (`transaction`). The only
state of the gate's own is an owner's opening (one exact action once, or a door for the length of a task).

The view is answered by a small connector the company runs next to its own system (`gate_table/view.py` lists its
calls and has a reference connector on SQLite). A call that fails is answered with the value that lets nothing
through: a system that does not answer never lets an action pass.

## What is not listed is closed

A translator that skips what it does not know is a hole. So a shell command not in the table of known commands is
closed, and so is a known command with an option the table does not list for it (`find -exec` runs another command;
`rm -fr` is `rm -r`); in SQL a function outside `functions_allowed` closes the statement, and a text the database
itself does not compile does not pass.

## Language doors

| Door | Translator (holds no rule) | The table says |
|---|---|---|
| SQL | `reader_sql`: a parser plus the schema | per table: readable columns, updatable columns, insert, delete; structure changes; optional row rules |
| Shell | `reader_shell`: a parser, the real file tree, a list of known commands and how each reads its arguments | per folder: read, write; commands that run other code, change permissions or are unknown are closed |
| Network | none | address ranges with their ports; everything else closed |
| Mail | `reader_mail`: the sender, each recipient as domain and address, the number of recipients, each attachment's type; an address not written plainly is not read; optionally every address written in the subject or body | the addresses to send as (`send_as`), the recipient domains (`send`) with `except`, the attachment types; `limits`: `{"recipients": 5}` |
| HTTP API | `reader_http`: method and path to the operation's door, query, headers and body as arguments | one door per operation, with required parameters, types, enums and ranges; a path or method the document does not hold is not in the menu |
| pip | `reader_pip`: each requirement as the version pip would choose, names compared as pip compares them, extras and options | the packages with their versions, extras, options |
| systemd unit | `reader_unit`: the unit read as systemd reads it, one setting per hardening option with the value in force, each program started | the settings and values allowed, the programs |
| Timer | `reader_calendar`: each `OnCalendar=` expression read as systemd reads it, and the times it fires | how often it may run, the hours, the units it starts |
| MongoDB | `reader_mongo`: the operation read into MongoDB's own privilege actions on each collection it reads or writes | one container per collection with one right per action |
| Terraform plan | `reader_tfplan`: each resource change of `terraform show -json` read into its actions and its values after the change | one container per resource type with the actions and the values allowed |
| Web address | `reader_url`: the host an `http` or `https` address reaches, normalised; an address with a user or password, a space, a backslash or a bad port is not read | one container per host, `{"api.example.org": {"connect": true}}` |
| MQTT | `reader_mqtt`: a publish as `write` on its topic, a subscription as `read` on its filter; patterns matched as the broker matches them | one container per ACL line |
| Redis, S3, git, sudo, LDAP | `reader_redis`, `reader_s3`, `reader_git`, `reader_sudo`, `reader_ldap` | keys, commands and channels; policy statements; refs; commands run as another user; attributes of entries |

## Limits and locks on dangerous operations

A dangerous operation is stated by what it does, counted before it runs, not by how it is written.

| Key | On | Meaning |
|---|---|---|
| `delete_rows_max`, `update_rows_max` | a database table | rows one statement may remove or touch; the gate counts them with a read first |
| `destroy_files_max` | a folder | files one line may make disappear |
| `destroy_dirs` | a folder | whether a directory in it may be deleted |
| `one_statement` | the table | a text holds one change; a command that deletes stands alone on its line |
| `functions_allowed` | the table | for SQL: the functions a statement may call |
| `live_schema` | the table | the translator works on the names the system has now, asked through the view |
| `compile_check` | the table | the gate asks the system whether the text is a statement it takes (compiled, not run) |
| `commands_allowed`, `command_locks`, `channels` | the table | for systems made of commands (Redis) |
| `container_match`, `container_rule` | the table | containers are patterns matched by the system's own matcher; which match decides |
| `locks`, `lock`, `structure_lock` | the table, a container, a door | who may open one exact action once: `{"open": [roles], "edit": [roles]}` |

`open_once(door, args, by=role)` accepts an opening only from a role the lock of the stopping rule names (or the
owner), lets that exact action pass once, and is then spent.

## Measured against the systems' own judges

For each system, its maker's rule language was written as a table and the real system was run beside it, as judge, on
random rule sets and random actions. Both answers had to be yes: what had to pass passed, what must not pass did not.

| Rules | Judge | Had to pass, passed | Must not pass, did not |
|---|---|---|---|
| SQL | the database | 69,191 of 69,191 | 130,809 of 130,809 |
| Network | the kernel firewall | 13,775 of 13,775 | 39,908 of 39,908 |
| Shell, rule sets never seen | the operating system | 24,058 of 24,058 | 27,933 of 27,933 |
| Redis | the Redis server | 6,546 of 6,546 | 82,250 of 82,250 |
| git pushes | real pushes through gitolite | 2,860 of 2,860 | 6,140 of 6,140 |
| Object storage (S3) policies | MinIO's policy engine | 12,292 of 12,292 | 77,708 of 77,708 |
| Pod security, baseline | Kubernetes's own admission code | 65,446 of 65,446 | 24,554 of 24,554 |
| Pod security, restricted | Kubernetes's own admission code | 20,648 of 20,648 | 69,352 of 69,352 |
| sudo | sudo 1.9.15 | 10,726 of 10,726 | 19,274 of 19,274 |
| PostgreSQL grants | PostgreSQL 16 | 39,721 of 39,721 | 80,279 of 80,279 |
| Kubernetes RBAC | Kubernetes's own matching functions | 41,762 of 41,762 | 48,238 of 48,238 |
| HTTP API from an OpenAPI document | openapi-core 0.19.5 | 14,221 of 14,221 | 4,840 of 4,840 |
| Mail | Postfix 3.8 over SMTP | 1,289 of 1,289 | 3,598 of 3,598 |
| MySQL grants | MariaDB 10.11 | 12,177 of 12,177 | 27,691 of 27,691 |
| MCP tool schemas | jsonschema (Draft 2020-12) | 11,598 of 11,598 | 8,344 of 8,344 |
| Directory of users | OpenLDAP slapd 2.6 | 2,931 of 2,931 | 5,260 of 5,260 |
| pip packages | pip 24.0 | 160 of 160 | 2,542 of 2,542 |
| systemd services | systemd 255 | 6,116 of 6,116 | 3,548 of 3,548 |
| Row rules | PostgreSQL 16 row-level security | 14,522 of 14,522 | 63,427 of 63,427 |
| Timer calendars | systemd 255 | 4,516 of 4,516 | 15,476 of 15,476 |
| MongoDB roles | MongoDB 8.0.4 | 11,161 of 11,161 | 28,831 of 28,831 |
| Terraform plans | Open Policy Agent 0.70 | 8,624 of 8,624 | 20,730 of 20,730 |
| MQTT topics | Mosquitto 2.0.18 | 546 of 546 | 3,454 of 3,454 |

Where a maker's rule language lets through more than its author meant (a sudo wildcard that also matches spaces, a
mail address written another way that the access list does not recognise), the table closes the gap instead of
copying it, and those cases are counted apart from the comparison.

## In plain words

A company's rules for an agent fit in one table: a list of the functions the agent may call, and for each one the
conditions under which it passes. The software that reads the table is the same for every company and holds no rule.
