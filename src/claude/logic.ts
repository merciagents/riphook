import {
  buildFindingsMessage,
  resolvePath,
  scanFile,
  scanText,
  SecretFinding,
} from "../core/secretScan.js";
import { extractShellReadPaths } from "../core/shellRead.js";
import { validateCommand, validateToolInput } from "../core/security.js";
import { logSecretDetection } from "../core/secretTrace.js";
import { appendEditedFilePath } from "../core/editedFilesCache.js";
import {
  appendTrace,
  createTrace,
  computeRangePositions,
  tryReadFile,
} from "../core/traceStore.js";
import { runClaudeStopScan } from "./stopScan.js";

function formatPreToolDecision(
  decision: "allow" | "deny" | "ask",
  reason?: string,
  systemMessage?: string,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
    },
  };

  if (reason) {
    (payload.hookSpecificOutput as Record<string, unknown>).permissionDecisionReason = reason;
  }

  if (systemMessage) payload.systemMessage = systemMessage;

  return payload;
}

function formatDecisionBlock(reason: string, eventName: string): Record<string, unknown> {
  return {
    decision: "block",
    reason,
    hookSpecificOutput: {
      hookEventName: eventName,
      additionalContext: reason,
    },
  };
}

function recordToolTrace(eventName: string, input: Record<string, unknown>): void {
  const toolName = (input.tool_name as string) ?? "";
  const toolInput = (input.tool_input as Record<string, unknown>) ?? {};

  if (eventName === "PreToolUse") {
    appendTrace(
      createTrace({
        contributorType: "ai",
        filePath: ".tool-usage",
        model: input.model as string | undefined,
        transcript: input.transcript_path as string | undefined,
        metadata: {
          event: "tool_use_attempt",
          tool_name: toolName,
          tool_use_id: input.tool_use_id,
          tool_input: toolInput,
          cwd: input.cwd,
        },
      }),
    );
    return;
  }

  if (eventName === "PostToolUse") {
    const isFileEdit = ["Write", "Edit", "search_replace", "Write"].includes(toolName);
    const isBash = ["Bash", "run_terminal_cmd", "Shell"].includes(toolName);
    const isRead = ["Read", "read_file"].includes(toolName);

    if (isFileEdit) {
      const filePath = String(toolInput.file_path ?? ".unknown");
      appendEditedFilePath(filePath);
      const rangePositions = toolInput.new_string
        ? computeRangePositions(
            [
              {
                old_string: toolInput.old_string ?? "",
                new_string: toolInput.new_string ?? "",
              },
            ],
            toolInput.file_path ? tryReadFile(String(toolInput.file_path)) : undefined,
          )
        : undefined;

      appendTrace(
        createTrace({
          contributorType: "ai",
          filePath,
          model: input.model as string | undefined,
          rangePositions,
          transcript: input.transcript_path as string | undefined,
          metadata: {
            event: "tool_use_completed",
            tool_name: toolName,
            tool_use_id: input.tool_use_id,
            duration_ms: input.duration,
          },
        }),
      );
      return;
    }

    const filePath = isBash
      ? ".shell-history"
      : isRead
        ? String(toolInput.file_path ?? ".file-reads")
        : ".tool-usage";

    appendTrace(
      createTrace({
        contributorType: "ai",
        filePath,
        model: input.model as string | undefined,
        transcript: input.transcript_path as string | undefined,
        metadata: {
          event: "tool_use_completed",
          tool_name: toolName,
          tool_use_id: input.tool_use_id,
          command: isBash ? toolInput.command : undefined,
          duration_ms: input.duration,
        },
      }),
    );
  }
}

function recordPromptTrace(input: Record<string, unknown>): void {
  const prompt = String(input.user_prompt ?? input.prompt ?? "");
  appendTrace(
    createTrace({
      contributorType: "human",
      filePath: ".prompts",
      model: input.model as string | undefined,
      transcript: input.transcript_path as string | undefined,
      metadata: {
        event: "prompt_submission_attempt",
        prompt_length: prompt.length,
      },
    }),
  );
}

function handlePreToolUse(input: Record<string, unknown>): Record<string, unknown> {
  const toolName = String(input.tool_name ?? "");
  const toolInput = (input.tool_input as Record<string, unknown>) ?? {};

  recordToolTrace("PreToolUse", input);

  const security = validateToolInput(toolName, toolInput);
  if (!security.isSafe || security.severity === "block") {
    return formatPreToolDecision("deny", security.reason, `BLOCKED: ${security.reason}`);
  }

  if (toolName === "Bash" || toolName === "Shell") {
    const command = String(toolInput.command ?? "");
    const findings = command.trim() ? scanText(command, "[shell command]") : [];
    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput: input,
        eventName: "PreToolUse",
        context: "secret_detected_in_command",
      });
      const message = buildFindingsMessage(
        findings,
        "SECRET DETECTED (command execution blocked)",
      );
      return formatPreToolDecision("deny", message, message);
    }

    const baseDir =
      typeof input.cwd === "string" && input.cwd.trim() ? String(input.cwd) : undefined;
    const readPaths = extractShellReadPaths(command, baseDir);
    const fileFindings: SecretFinding[] = [];
    for (const readPath of readPaths) {
      try {
        fileFindings.push(...scanFile(readPath));
      } catch {
        // ignore unreadable files
      }
    }
    if (fileFindings.length > 0) {
      logSecretDetection({
        findings: fileFindings,
        hookInput: input,
        eventName: "PreToolUse",
        context: "secret_detected_before_read",
      });
      const message = buildFindingsMessage(
        fileFindings,
        "SECRET DETECTED (file read blocked)",
      );
      return formatPreToolDecision("deny", message, message);
    }
  }

  if (["Read", "read_file", "ReadFile", "cat"].includes(toolName)) {
    const filePath = String(toolInput.file_path ?? toolInput.target_file ?? "");
    if (filePath) {
      try {
        const resolved = resolvePath(filePath, [String(input.cwd ?? "")]);
        const findings = scanFile(resolved);
        if (findings.length > 0) {
          logSecretDetection({
            findings,
            hookInput: input,
            eventName: "PreToolUse",
            context: "secret_detected_before_read",
          });
          const message = buildFindingsMessage(
            findings,
            "SECRET DETECTED (file read blocked)",
          );
          return formatPreToolDecision("deny", message, message);
        }
      } catch {
        // ignore
      }
    }
  }

  if (security.severity === "warn") {
    return formatPreToolDecision("allow", security.reason, `WARNING: ${security.reason}`);
  }

  return formatPreToolDecision("allow");
}

function handleUserPromptSubmit(input: Record<string, unknown>): Record<string, unknown> {
  recordPromptTrace(input);
  const prompt = String(input.user_prompt ?? input.prompt ?? "");
  if (!prompt.trim()) return {};

  const findings = scanText(prompt, "[prompt]");
  if (findings.length > 0) {
    logSecretDetection({
      findings,
      hookInput: input,
      eventName: "UserPromptSubmit",
      context: "secret_detected_in_prompt",
    });
    const message = buildFindingsMessage(findings, "SECRET DETECTED (submission blocked)");
    return formatDecisionBlock(message, "UserPromptSubmit");
  }

  return {};
}

function handlePostToolUse(input: Record<string, unknown>): Record<string, unknown> {
  recordToolTrace("PostToolUse", input);

  const toolName = String(input.tool_name ?? "");
  const toolInput = (input.tool_input as Record<string, unknown>) ?? {};
  const toolResponse = input.tool_response ?? input.tool_result ?? input.tool_output;

  const findings: SecretFinding[] = [];
  if (typeof toolResponse === "string") {
    findings.push(...scanText(toolResponse, "[tool output]"));
  } else if (toolResponse && typeof toolResponse === "object") {
    findings.push(...scanText(JSON.stringify(toolResponse), "[tool output]"));
  }

  if (toolName === "Bash" && toolInput.command) {
    findings.push(...scanText(String(toolInput.command), "[shell command]"));
  }

  if (findings.length > 0) {
    logSecretDetection({
      findings,
      hookInput: input,
      eventName: "PostToolUse",
      context: "secret_detected_in_output",
    });
    const message = buildFindingsMessage(findings, "SECRET DETECTED in recent output");
    return formatDecisionBlock(message, "PostToolUse");
  }

  return {};
}

function handleStop(input: Record<string, unknown>): Record<string, unknown> {
  return runClaudeStopScan(input);
}

function runClaudeHook(rawInput: string): string | null {
  const jsonInput = rawInput.trim();
  if (!jsonInput) return null;

  let hookInput: Record<string, unknown> = {};
  try {
    hookInput = JSON.parse(jsonInput) as Record<string, unknown>;
  } catch {
    return null;
  }

  const eventName = String(hookInput.hook_event_name ?? "");

  if (eventName === "PreToolUse") {
    const response = handlePreToolUse(hookInput);
    return JSON.stringify(response);
  }

  if (eventName === "UserPromptSubmit") {
    const response = handleUserPromptSubmit(hookInput);
    return Object.keys(response).length > 0 ? JSON.stringify(response) : null;
  }

  if (eventName === "PostToolUse") {
    const response = handlePostToolUse(hookInput);
    return Object.keys(response).length > 0 ? JSON.stringify(response) : null;
  }

  if (eventName === "Stop") {
    const response = handleStop(hookInput);
    return Object.keys(response).length > 0 ? JSON.stringify(response) : null;
  }

  if (
    eventName === "SessionStart" ||
    eventName === "SessionEnd" ||
    eventName === "PreCompact" ||
    eventName === "SubagentStop" ||
    eventName === "Notification"
  ) {
    appendTrace(
      createTrace({
        contributorType: "ai",
        filePath: ".claude-session",
        model: hookInput.model as string | undefined,
        transcript: hookInput.transcript_path as string | undefined,
        metadata: {
          event: eventName,
          reason: hookInput.reason,
          trigger: hookInput.trigger,
          notification: hookInput.notification,
        },
      }),
    );
  }

  return null;
}

export {
  formatPreToolDecision,
  formatDecisionBlock,
  handlePreToolUse,
  handleUserPromptSubmit,
  handlePostToolUse,
  handleStop,
  runClaudeHook,
};
