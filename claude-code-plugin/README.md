# Gate by Silicon Psyche Labs

> **Retired on 24 November 2026.** This plugin belongs to the previous engine (v0.1.x), whose service is switched off:
> it can no longer get an answer, and in enforce mode an action it cannot check is refused. If you installed it, remove
> it with `/plugin uninstall splabs-gate@splabs`. The gate in production is described in the
> [README](../README.md) and the [manual](https://splabs.io/manual/gate).

A deterministic gate in front of every tool call Claude Code makes. Fixed rules decide, before the call runs:

- **allowed**: nothing changes, Claude Code's own permission settings apply;
- **refused**: the call does not run, and the model reads the rule's fixed reply;
- **held**: Claude Code asks you with its normal permission prompt, and your answer is logged on the decision.

Every decision is logged and counted on your console at [splabs.io/gate](https://splabs.io/gate). The hook never
approves a call and never changes a call's input.

## Install

Inside Claude Code:

```
/plugin install splabs-gate --marketplace SiliconPsycheLabs/gate
```

Claude Code asks for:

- **Gate key**: a gate-only key from splabs.io, Settings, API Keys, + Gate-only key (it starts with `psa_gate_` and
  works only on the gate). Kept in the system's secure store.
- **Mode**: `shadow` (start here: the gate decides and records, nothing is blocked) or `enforce`.
- **Allowed hosts**: hosts the agent may contact without asking.

`/config` changes them later. Needs Python 3 (macOS or Linux).

## What leaves your machine

Your prompts, each action and what it returned, cut to 100,000 characters. The gate reads them to know where a value
came from ("this address came from a web page, not from your request"). Each check is one gate decision on your
account.

## The agent cannot switch it off

The hook is run by Claude Code, not by the model. In enforce mode the rules refuse an agent's edits to Claude Code's
settings, hooks, MCP configuration and installed plugins, and to the gate's own files.

Guide: [splabs.io/manual/gate-claude-code](https://splabs.io/manual/gate-claude-code). Source and rules (Apache-2.0):
[github.com/SiliconPsycheLabs/gate](https://github.com/SiliconPsycheLabs/gate). The hook in `hooks/gate_hook.py` is a
copy of `src/gate/integrations/claude_code.py` from that repository.
