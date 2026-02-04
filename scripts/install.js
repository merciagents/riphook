import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distCursorEntry = path.join(repoRoot, "dist", "cursor", "entry.js");
const distClaudeEntry = path.join(repoRoot, "dist", "claude", "entry.js");
const homeDir = os.homedir();
const venvDir = path.join(repoRoot, ".venv");
function resolveHookCommand(entryPath) {
  return `${process.execPath} ${entryPath}`;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function ensureHookList(existing, hook) {
  if (!existing) return [hook];
  if (Array.isArray(existing)) {
    const already = existing.some(
      (entry) =>
        entry?.command === hook.command ||
        (entry?.command === hook.command &&
          Array.isArray(entry?.args) &&
          Array.isArray(hook?.args) &&
          entry.args.join(" ") === hook.args.join(" ")),
    );
    return already ? existing : [...existing, hook];
  }
  if (typeof existing === "object") {
    const same =
      existing.command === hook.command ||
      (existing.command === hook.command &&
        Array.isArray(existing.args) &&
        Array.isArray(hook?.args) &&
        existing.args.join(" ") === hook.args.join(" "));
    return same ? [existing] : [existing, hook];
  }
  return [hook];
}

function removeCursorHookEntries(entries, command, legacyCommand, legacyArgs) {
  if (!Array.isArray(entries)) return [];
  return entries.filter((entry) => {
    if (!entry || typeof entry !== "object") return true;
    if (entry.command === command) return false;
    if (
      legacyCommand &&
      entry.command === legacyCommand &&
      Array.isArray(entry.args) &&
      Array.isArray(legacyArgs) &&
      entry.args.join(" ") === legacyArgs.join(" ")
    ) {
      return false;
    }
    return true;
  });
}

function removeCommandHookEntries(entries, command, matcher) {
  if (!Array.isArray(entries)) return [];
  const cleaned = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") continue;
    const entryMatcher = entry.matcher;
    const hooks = Array.isArray(entry.hooks) ? entry.hooks : [];
    const filteredHooks = hooks.filter(
      (hook) => !(hook && hook.type === "command" && hook.command === command),
    );
    if (filteredHooks.length === 0) {
      // Drop empty entry
      continue;
    }
    cleaned.push({ ...entry, hooks: filteredHooks, ...(entryMatcher ? { matcher: entryMatcher } : {}) });
  }

  // If matcher-specific entry exists, don't add another identical matcher below.
  if (matcher === undefined) return cleaned;
  return cleaned;
}

function addClaudeCommandHook(entries, commandHook, matcher) {
  const base = removeCommandHookEntries(entries, commandHook.command, matcher);
  const newEntry = matcher ? { matcher, hooks: [commandHook] } : { hooks: [commandHook] };
  return [...base, newEntry];
}

function installCursorHooks() {
  const command = resolveHookCommand(distCursorEntry);
  const legacyCommand = process.execPath;
  const legacyArgs = [distCursorEntry];
  const hookEntry = { command };
  const events = [
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "beforeShellExecution",
    "afterShellExecution",
    "beforeReadFile",
    "afterFileEdit",
    "beforeSubmitPrompt",
    "beforeMCPExecution",
    "afterMCPExecution",
    "sessionStart",
    "sessionEnd",
    "subagentStart",
    "subagentStop",
    "afterAgentResponse",
    "afterAgentThought",
    "preCompact",
    "stop",
  ];

  const hookTargets = [
    path.join(repoRoot, ".cursor", "hooks.json"),
    path.join(homeDir, ".cursor", "hooks.json"),
  ];

  for (const hooksPath of hookTargets) {
    const raw = readJson(hooksPath, {});
    const hooksContainer = raw.hooks && typeof raw.hooks === "object" ? raw.hooks : raw;
    const version = typeof raw.version === "number" ? raw.version : 1;

    const mergedHooks = { ...hooksContainer };
    for (const event of events) {
      const cleaned = removeCursorHookEntries(
        mergedHooks[event],
        hookEntry.command,
        legacyCommand,
        legacyArgs,
      );
      mergedHooks[event] = ensureHookList(cleaned, hookEntry);
    }

    const nextConfig = { version, hooks: mergedHooks };
    writeJson(hooksPath, nextConfig);
  }
}

function installClaudeHooks() {
  const settingsTargets = [
    path.join(repoRoot, ".claude", "settings.json"),
    path.join(homeDir, ".claude", "settings.json"),
  ];

  const command = resolveHookCommand(distClaudeEntry);
  const commandHook = { type: "command", command };

  for (const settingsPath of settingsTargets) {
    const settings = readJson(settingsPath, {});
    const hooks = settings.hooks ?? {};

    hooks.PreToolUse = addClaudeCommandHook(hooks.PreToolUse, commandHook, ".*");
    hooks.PostToolUse = addClaudeCommandHook(hooks.PostToolUse, commandHook, ".*");
    hooks.UserPromptSubmit = addClaudeCommandHook(hooks.UserPromptSubmit, commandHook);
    hooks.Stop = addClaudeCommandHook(hooks.Stop, commandHook);
    hooks.SessionStart = addClaudeCommandHook(hooks.SessionStart, commandHook);
    hooks.SessionEnd = addClaudeCommandHook(hooks.SessionEnd, commandHook);
    hooks.PreCompact = addClaudeCommandHook(hooks.PreCompact, commandHook);
    hooks.SubagentStop = addClaudeCommandHook(hooks.SubagentStop, commandHook);
    hooks.Notification = addClaudeCommandHook(hooks.Notification, commandHook);
    hooks.PermissionRequest = removeCommandHookEntries(
      hooks.PermissionRequest,
      commandHook.command,
    );
    if (Array.isArray(hooks.PermissionRequest) && hooks.PermissionRequest.length === 0) {
      delete hooks.PermissionRequest;
    }

    settings.hooks = hooks;
    writeJson(settingsPath, settings);
  }
}

function installOpenClaw() {
  const openclawPath = spawnSync("which", ["openclaw"], { encoding: "utf8" });
  if (openclawPath.status !== 0) return;

  spawnSync("openclaw", ["plugins", "install", "-l", repoRoot], {
    stdio: "inherit",
  });

  const configCandidates = [
    process.env.OPENCLAW_CONFIG_PATH,
    path.join(homeDir, ".openclaw", "config.json"),
    path.join(homeDir, ".openclaw", "openclaw.json"),
  ].filter(Boolean);

  for (const configPath of configCandidates) {
    const config = readJson(configPath, { plugins: { entries: {} } });
    const entries = config.plugins?.entries ?? {};
    delete entries.clawsentinel;
    delete entries.clawguardian;
    entries["riphook"] = entries["riphook"] ?? { enabled: true, config: {} };
    config.plugins = config.plugins ?? {};
    config.plugins.entries = entries;
    writeJson(configPath, config);
  }
}

function ensureSemgrepVenv() {
  const pythonCandidates = [
    process.env.PYTHON,
    "python3",
    "python",
  ].filter(Boolean);

  let python = null;
  for (const candidate of pythonCandidates) {
    const check = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (check.status === 0) {
      python = candidate;
      break;
    }
  }

  if (!python) {
    process.stderr.write(
      "Warning: Python not found; cannot auto-install semgrep. Install it manually in .venv.\n",
    );
    return;
  }

  if (!fs.existsSync(venvDir)) {
    const venvResult = spawnSync(python, ["-m", "venv", venvDir], {
      encoding: "utf8",
    });
    if (venvResult.status !== 0) {
      process.stderr.write(
        `Warning: Failed to create venv at ${venvDir}: ${venvResult.stderr}\n`,
      );
      return;
    }
  }

  const venvBin = process.platform === "win32" ? "Scripts" : "bin";
  const venvPython = path.join(
    venvDir,
    venvBin,
    process.platform === "win32" ? "python.exe" : "python",
  );
  let pipOk = true;
  const pipCheck = spawnSync(venvPython, ["-m", "pip", "--version"], { encoding: "utf8" });
  if (pipCheck.status !== 0) {
    const ensure = spawnSync(venvPython, ["-m", "ensurepip", "--upgrade"], {
      encoding: "utf8",
    });
    if (ensure.status !== 0) {
      pipOk = false;
      process.stderr.write(
        `Warning: Failed to bootstrap pip in venv: ${ensure.stderr}\n`,
      );
    }
  }

  if (pipOk) {
    const pipResult = spawnSync(
      venvPython,
      ["-m", "pip", "install", "--upgrade", "pip"],
      { encoding: "utf8" },
    );
    if (pipResult.status !== 0) {
      process.stderr.write(
        `Warning: Failed to upgrade pip in venv: ${pipResult.stderr}\n`,
      );
    }

    const semgrepResult = spawnSync(
      venvPython,
      ["-m", "pip", "install", "semgrep"],
      { encoding: "utf8" },
    );
    if (semgrepResult.status !== 0) {
      process.stderr.write(
        `Warning: Failed to install semgrep in venv: ${semgrepResult.stderr}\n`,
      );
    }
  }
}

try {
  const pnpmCheck = spawnSync("pnpm", ["-v"], { encoding: "utf8" });
  const buildResult =
    pnpmCheck.status === 0
      ? spawnSync("pnpm", ["run", "build"], { encoding: "utf8", stdio: "inherit" })
      : spawnSync("npm", ["run", "build"], { encoding: "utf8", stdio: "inherit" });
  if (buildResult.status !== 0) {
    process.stderr.write("Warning: build failed; hooks may be outdated.\n");
  }
  ensureSemgrepVenv();
  installCursorHooks();
  installClaudeHooks();
  installOpenClaw();
} catch (error) {
  process.stderr.write(`Install script error: ${String(error)}\n`);
}
