# Riphook

Riphook is a security hook suite for Cursor, Claude Code, and OpenClaw. It blocks risky tool calls, detects secrets/PII, and runs static analysis on edited files to help keep agent runs safe by default. 

It also emits **Cursor agent-trace–compatible logs** (https://agent-trace.dev/), providing you a clear context-graph, so you can visualize agent behavior, human collaboration, tool usage, and points of failure.

## Why Hooks (Not Just Prompts)

Prompts, `SKILLS.md`, and MCP servers are helpful, but they are **advisory**. An agent can ignore or misinterpret them. Or not even choose to call them. Hooks are **deterministic enforcement**: they intercept tool calls, reads, and outputs and can block actions regardless of what the prompt says. That makes hooks a much more reliable control layer for safety.

Hooks are often overlooked because they live outside the prompt. They don't seem cool enough.  However, they are the most reliable control layer for safety. They run at the system boundary, where the agent actually executes tools.

## Features

- **Secure code generation**: static analysis runs on edited files and hooks enforce findings, ensuring agents comply with security detections (Cursor + Claude). As the static analysis is run everytime an agent completes execution, and its result fed back to the agent if an issue is detected, it ensures that the agent can not stop execution until the issue is resolved.
- **Secret detection**: scans prompts, tool params, file reads, and tool outputs.
- **PII detection**: credit cards, emails, SSNs, and phone-like patterns (OpenClaw + others).
- **Dangerous command blocking**: blocks dangerous shell/SQL patterns (rm -rf, drop table, etc).
- **Audit trail**: emits agent-trace records for prompts, tools, shells, and session lifecycle. Logs follow the Cursor agent-trace specification, enabling visualizations of agent flows, human+agent collaboration, and failure hotspots.

## Install

Riphook works with **pnpm** or **npm**.

```bash
# Clone the repository
git clone https://github.com/merciagents/riphook.git
cd riphook
# Install dependencies
pnpm install
```

This sets up the hooks for Cursor, Claude Code, and OpenClaw automatically.

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
- Existing user hooks are preserved; Riphook merges into your current hook lists.

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

## More to come

The current implementation of Riphook is a work in progress, and we are constantly improving it. Here are some of the known limitations that will be addressed soon in a better version of our tool:

- **Regex-based detections**: secret/PII detection uses regex and can miss or misclassify.
- **Static analysis limits**: Semgrep rules won’t catch every bug or vulnerability.
- **Agent/session failures**: if an agent crashes or is interrupted, some edits or stop-time scans may not run.

## We will be releasing an advanced version of our system soon - advance deterministic security, support for any general long running agent, dashboard for easy access to non developers, etc. stay tuned. 
