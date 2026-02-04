import {
  buildFindingsMessage,
  resolvePath,
  scanFile,
  scanText,
  SecretFinding,
} from "../core/secretScan.js";
import { extractShellReadPaths } from "../core/shellRead.js";
import { logSecretDetection } from "../core/secretTrace.js";
import { validateCommand, validateToolInput } from "../core/security.js";
import { runStopScan } from "./stopScan.js";
import * as traceHandlers from "./trace.js";

function formatCursorResponse(options: {
  action?: "allow" | "block" | "warn" | "ask";
  message?: string | null;
  eventName?: string | null;
  decision?: "allow" | "deny";
}): Record<string, unknown> {
  const eventName = options.eventName ?? "";
  const message = options.message ?? undefined;

  if (eventName === "beforeSubmitPrompt") {
    const payload: Record<string, unknown> = {
      continue: options.action !== "block",
    };
    if (message) payload.userMessage = message;
    return payload;
  }

  if (["beforeReadFile", "beforeShellExecution", "beforeMCPExecution"].includes(eventName)) {
    const permissionMap: Record<string, string> = {
      allow: "allow",
      block: "deny",
      warn: "allow",
      ask: "ask",
    };
    const payload: Record<string, unknown> = {
      permission: permissionMap[options.action ?? "allow"] ?? "allow",
    };
    if (message) payload.userMessage = message;
    return payload;
  }

  if (["afterFileEdit", "afterShellExecution", "afterMCPExecution"].includes(eventName)) {
    const payload: Record<string, unknown> = {};
    if (message) payload.message = message;
    return payload;
  }

  if (eventName === "preToolUse") {
    const decision = options.decision ?? "allow";
    const payload: Record<string, unknown> = { decision };
    if (message) payload.userMessage = message;
    return payload;
  }

  const payload: Record<string, unknown> = {};
  if (options.action) payload.permission = options.action === "block" ? "deny" : options.action;
  if (message) payload.userMessage = message;
  if (Object.keys(payload).length === 0) {
    payload.permission = "allow";
  }
  return payload;
}

function combineSecurityAndSecrets(
  security: { isSafe: boolean; severity: string; reason: string },
  findings: SecretFinding[],
  context: {
    eventName: string;
    hookInput: Record<string, unknown>;
    blockMessage: string;
    logContext: string;
  },
): { response: Record<string, unknown>; exitCode: number } {
  if (findings.length > 0) {
    logSecretDetection({
      findings,
      hookInput: context.hookInput,
      eventName: context.eventName,
      context: context.logContext,
    });
    const message = buildFindingsMessage(findings, context.blockMessage);
    return {
      response: formatCursorResponse({
        action: "block",
        message,
        eventName: context.eventName,
      }),
      exitCode: 2,
    };
  }

  if (!security.isSafe || security.severity === "block") {
    return {
      response: formatCursorResponse({
        action: "block",
        message: `BLOCKED: ${security.reason}`,
        eventName: context.eventName,
      }),
      exitCode: 2,
    };
  }

  if (security.severity === "warn") {
    return {
      response: formatCursorResponse({
        action: "warn",
        message: `WARNING: ${security.reason}`,
        eventName: context.eventName,
      }),
      exitCode: 0,
    };
  }

  return {
    response: formatCursorResponse({ action: "allow", eventName: context.eventName }),
    exitCode: 0,
  };
}

function handleSecretOnlyEvent(
  hookInput: Record<string, unknown>,
  eventName: string,
): { response: Record<string, unknown>; exitCode: number } {
  let findings: SecretFinding[] = [];

  if (eventName === "beforeReadFile") {
    const content = hookInput.content as string | undefined;
    const filePath = hookInput.file_path as string | undefined;
    if (content?.trim()) {
      findings = scanText(content, filePath || "[content]");
    } else if (filePath) {
      try {
        const resolved = resolvePath(filePath, hookInput.workspace_roots as string[]);
        findings = scanFile(resolved);
      } catch {
        findings = [];
      }
    }

    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_before_read",
      });
      const message = buildFindingsMessage(findings, "SECRET DETECTED (file read blocked)");
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }

    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  if (eventName === "beforeSubmitPrompt") {
    const prompt = String(hookInput.prompt ?? "");
    if (prompt.trim()) {
      findings = scanText(prompt, "[prompt]");
    }
    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_in_prompt",
      });
      const message = buildFindingsMessage(findings, "SECRET DETECTED (submission blocked)");
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }
    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  if (eventName === "beforeShellExecution") {
    const command = String(hookInput.command ?? "");
    if (command.trim()) findings = scanText(command, "[shell command]");
    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_in_command",
      });
      const message = buildFindingsMessage(
        findings,
        "SECRET DETECTED (command execution blocked)",
      );
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }
    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  if (eventName === "beforeMCPExecution") {
    const command = String(hookInput.command ?? "");
    if (command.trim()) findings = scanText(command, "[mcp command]");
    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_in_mcp_command",
      });
      const message = buildFindingsMessage(
        findings,
        "SECRET DETECTED (MCP execution blocked)",
      );
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }
    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  if (eventName === "afterFileEdit") {
    const filePath = hookInput.file_path as string | undefined;
    const edits = (hookInput.edits as Array<Record<string, unknown>>) ?? [];
    if (filePath) {
      try {
        findings.push(...scanFile(filePath));
      } catch {
        // ignore
      }
    }
    for (const edit of edits) {
      const newString = edit?.new_string as string | undefined;
      if (newString?.trim()) {
        findings.push(...scanText(newString, filePath || "[edit]"));
      }
    }

    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_after_edit",
      });
      const message = buildFindingsMessage(findings, "SECRET DETECTED in file edit");
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }

    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  if (eventName === "afterShellExecution" || eventName === "afterMCPExecution") {
    const payloads: Array<[string, string]> = [];
    if (eventName === "afterShellExecution") {
      if (typeof hookInput.stdout === "string" && hookInput.stdout.trim()) {
        payloads.push(["[shell stdout]", hookInput.stdout]);
      }
      if (typeof hookInput.stderr === "string" && hookInput.stderr.trim()) {
        payloads.push(["[shell stderr]", hookInput.stderr]);
      }
    }
    if (eventName === "afterMCPExecution") {
      const keys: Array<[string, string]> = [
        ["stdout", "[mcp stdout]"],
        ["stderr", "[mcp stderr]"],
        ["text", "[mcp output]"],
        ["message", "[mcp output]"],
      ];
      for (const [key, label] of keys) {
        const value = hookInput[key as keyof typeof hookInput];
        if (typeof value === "string" && value.trim()) {
          payloads.push([label, value]);
        }
      }
    }

    for (const [label, text] of payloads) {
      findings.push(...scanText(text, label));
    }

    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_in_output",
      });
      const message =
        buildFindingsMessage(findings, "SECRET DETECTED in recent output") +
        "\nBe careful with this sensitive data!";
      return {
        response: formatCursorResponse({ action: "block", message, eventName }),
        exitCode: 2,
      };
    }

    return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
  }

  return { response: formatCursorResponse({ action: "allow", eventName }), exitCode: 0 };
}

function runCursorHook(rawInput: string): { output: string; exitCode: number } {
  const jsonInput = rawInput.trim();
  if (!jsonInput) {
    return { output: JSON.stringify({ permission: "allow" }), exitCode: 0 };
  }

  let hookInput: Record<string, unknown> = {};
  try {
    hookInput = JSON.parse(jsonInput) as Record<string, unknown>;
  } catch (error) {
    return {
      output: JSON.stringify({ permission: "allow" }),
      exitCode: 0,
    };
  }

  const eventName = String(hookInput.hook_event_name ?? "");

  const traceMap: Record<string, (input: Record<string, unknown>) => void> = {
    sessionStart: traceHandlers.handleSessionStart,
    SessionStart: traceHandlers.handleSessionStart,
    sessionEnd: traceHandlers.handleSessionEnd,
    SessionEnd: traceHandlers.handleSessionEnd,
    afterFileEdit: traceHandlers.handleAfterFileEdit,
    afterTabFileEdit: traceHandlers.handleAfterTabFileEdit,
    beforeReadFile: traceHandlers.handleBeforeReadFile,
    preToolUse: traceHandlers.handlePreToolUse,
    postToolUse: traceHandlers.handlePostToolUse,
    PostToolUse: traceHandlers.handlePostToolUse,
    postToolUseFailure: traceHandlers.handlePostToolUseFailure,
    beforeShellExecution: traceHandlers.handleBeforeShellExecution,
    afterShellExecution: traceHandlers.handleAfterShellExecution,
    beforeMCPExecution: traceHandlers.handleBeforeMcpExecution,
    afterMCPExecution: traceHandlers.handleAfterMcpExecution,
    subagentStart: traceHandlers.handleSubagentStart,
    subagentStop: traceHandlers.handleSubagentStop,
    beforeSubmitPrompt: traceHandlers.handleBeforeSubmitPrompt,
    afterAgentResponse: traceHandlers.handleAfterAgentResponse,
    afterAgentThought: traceHandlers.handleAfterAgentThought,
    preCompact: traceHandlers.handlePreCompact,
  };

  if (traceMap[eventName]) {
    traceMap[eventName](hookInput);
  }

  if (eventName === "stop" || eventName === "Stop") {
    const response = runStopScan(hookInput);
    return { output: JSON.stringify(response), exitCode: 0 };
  }

  if (eventName === "preToolUse") {
    const toolName = String(hookInput.tool_name ?? "");
    const toolInput = (hookInput.tool_input as Record<string, unknown>) ?? {};
    const decision = validateToolInput(toolName, toolInput);

    let payload: Record<string, unknown>;
    if (!decision.isSafe || decision.severity === "block") {
      payload = formatCursorResponse({
        decision: "deny",
        message: `BLOCKED: ${toolName} - ${decision.reason}`,
        eventName: "preToolUse",
      });
      return { output: JSON.stringify(payload), exitCode: 2 };
    }

    if (decision.severity === "warn") {
      payload = formatCursorResponse({
        decision: "allow",
        message: `WARNING: ${toolName} - ${decision.reason}`,
        eventName: "preToolUse",
      });
      return { output: JSON.stringify(payload), exitCode: 0 };
    }

    payload = formatCursorResponse({ decision: "allow", eventName: "preToolUse" });
    return { output: JSON.stringify(payload), exitCode: 0 };
  }

  if (eventName === "beforeShellExecution") {
    const command = String(hookInput.command ?? "");
    const security = validateCommand(command);
    const findings = command.trim() ? scanText(command, "[shell command]") : [];
    const workspaceRoots = (hookInput.workspace_roots as string[]) ?? [];
    const baseDir =
      typeof hookInput.cwd === "string" && hookInput.cwd.trim()
        ? hookInput.cwd
        : undefined;
    const readPaths = extractShellReadPaths(command, baseDir, workspaceRoots);
    for (const readPath of readPaths) {
      try {
        findings.push(...scanFile(readPath));
      } catch {
        // ignore unreadable files
      }
    }
    if (findings.length > 0) {
      logSecretDetection({
        findings,
        hookInput,
        eventName,
        context: "secret_detected_before_read",
      });
      const message = buildFindingsMessage(findings, "SECRET DETECTED (file read blocked)");
      return {
        output: JSON.stringify(
          formatCursorResponse({ action: "block", message, eventName }),
        ),
        exitCode: 2,
      };
    }
    const result = combineSecurityAndSecrets(security, findings, {
      eventName,
      hookInput,
      blockMessage: "SECRET DETECTED (command execution blocked)",
      logContext: "secret_detected_in_command",
    });
    return { output: JSON.stringify(result.response), exitCode: result.exitCode };
  }

  if (
    [
      "beforeReadFile",
      "beforeSubmitPrompt",
      "beforeMCPExecution",
      "afterFileEdit",
      "afterShellExecution",
      "afterMCPExecution",
    ].includes(eventName)
  ) {
    const result = handleSecretOnlyEvent(hookInput, eventName);
    return { output: JSON.stringify(result.response), exitCode: result.exitCode };
  }

  return {
    output: JSON.stringify(formatCursorResponse({ action: "allow", eventName })),
    exitCode: 0,
  };
}

export { formatCursorResponse, combineSecurityAndSecrets, handleSecretOnlyEvent, runCursorHook };
