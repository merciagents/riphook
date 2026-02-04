# Riphook

Riphook is a security hook suite for Cursor, Claude Code, and OpenClaw. It blocks risky tool calls, detects secrets/PII, and runs static analysis on edited files to help keep agent runs safe by default.

## Why Hooks (Not Just Prompts)

Prompts, `SKILLS.md`, and MCP servers are helpful—but they are **advisory**. An agent can ignore or misinterpret them. Or not even choose to call them. Hooks are **deterministic enforcement**: they intercept tool calls, reads, and outputs and can block actions regardless of what the prompt says. That makes hooks a much more reliable control layer for safety.

Hooks are often overlooked because they live outside the prompt. They don't seem cool enough.  However, they are the most reliable control layer for safety. They run at the system boundary, where the agent actually executes tools.

## Features

- **Static analysis**: runs static analysis on edited files at stop (Cursor + Claude).
- **Secret detection**: scans prompts, tool params, file reads, and tool outputs.
- **PII detection**: credit cards, emails, SSNs, and phone-like patterns (OpenClaw + others).
- **Dangerous command blocking**: blocks dangerous shell/SQL patterns (rm -rf, drop table, etc).
- **Audit trail**: emits agent-trace records for prompts, tools, shells, and session lifecycle.

## Install

Riphook works with **pnpm** or **npm**.

```bash
pnpm install
```

If you don’t have pnpm:

```bash
npm install -g pnpm
```

Or use npm directly:

```bash
npm install
```

`postinstall` does the following:

- Writes `.cursor/hooks.json` and `~/.cursor/hooks.json` to point Cursor hooks at `dist/cursor/entry.js`.
- Writes `.claude/settings.json` and `~/.claude/settings.json` to point Claude hooks at `dist/claude/entry.js`.
- If `openclaw` is installed, registers the plugin locally and updates `~/.openclaw/config.json` (and `openclaw.json` if present).

Hook command:
- Hooks run as `node <entry>` for reliability.

## Logs & Artifacts

- **Agent traces**: `./.agent-trace/traces.jsonl` (created in the install directory)

## Manual hooks setup

Cursor:

```json
{
  "preToolUse": [{ "command": "node", "args": ["dist/cursor/entry.js"] }]
}
```

Claude Code:

```json
{
  "hooks": {
    "PreToolUse": [{ "command": "node", "args": ["dist/claude/entry.js"] }]
  }
}
```

OpenClaw:

```bash
openclaw plugins install -l .
```

Then add to `~/.openclaw/config.json`:

```json
{
  "plugins": {
    "entries": {
      "hooks-project": { "enabled": true, "config": {} }
    }
  }
}
```

## Development

```bash
npm run build
npm test
```
