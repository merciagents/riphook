// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OpenClawPluginApi = any;

import { scanFile, scanText } from "../core/secretScan.js";
import { extractShellReadPaths } from "../core/shellRead.js";
import { logSecretDetection } from "../core/secretTrace.js";
import { validateCommand, validateToolInput } from "../core/security.js";
import { containsPii } from "../core/pii.js";

const PLUGIN_ID = "riphook";

function extractFilePath(params: Record<string, unknown>): string | undefined {
  return (
    (params.file_path as string | undefined) ||
    (params.path as string | undefined) ||
    (params.target_file as string | undefined)
  );
}

function scanParamsForSecrets(
  params: Record<string, unknown>,
  label: string,
): ReturnType<typeof scanText> {
  const serialized = JSON.stringify(params);
  return scanText(serialized, label);
}

export default {
  id: PLUGIN_ID,
  name: "HooksProject",
  description: "Security hooks for secrets and destructive commands",
  register(api: OpenClawPluginApi): void {
    api.on(
      "before_tool_call",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      async (event: any, ctx: any) => {
        const toolName = String(event.toolName ?? "");
        const params = (event.params ?? {}) as Record<string, unknown>;

        const securityDecision = validateToolInput(toolName, params);
        if (!securityDecision.isSafe || securityDecision.severity === "block") {
          return {
            block: true,
            blockReason: securityDecision.reason || "Blocked by HooksProject policy.",
          };
        }

        if (["exec", "bash", "shell"].includes(toolName)) {
          const command = String(params.command ?? params.cmd ?? "");
          const commandDecision = validateCommand(command);
          if (!commandDecision.isSafe || commandDecision.severity === "block") {
            return {
              block: true,
              blockReason: commandDecision.reason,
            };
          }
          const commandFindings = scanText(command, "[shell command]");
          if (commandFindings.length > 0) {
            logSecretDetection({
              findings: commandFindings,
              hookInput: { session_key: ctx?.sessionKey },
              eventName: "before_tool_call",
              context: "secret_detected_in_command",
              toolLabel: "riphook-openclaw",
            });
            return {
              block: true,
              blockReason: "Secret detected in command",
            };
          }
          if (containsPii(command)) {
            return {
              block: true,
              blockReason: "PII detected in command",
            };
          }

          const baseDir =
            typeof params.cwd === "string" && params.cwd.trim()
              ? String(params.cwd)
              : undefined;
          const readPaths = extractShellReadPaths(command, baseDir);
          const fileFindings = [];
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
              hookInput: { session_key: ctx?.sessionKey },
              eventName: "before_tool_call",
              context: "secret_detected_before_read",
              toolLabel: "riphook-openclaw",
            });
            return {
              block: true,
              blockReason: "Secret detected in file read",
            };
          }
        }

        const filePath = extractFilePath(params);
        if (filePath && ["read", "read_file", "ReadFile", "cat"].includes(toolName)) {
          try {
            const findings = scanFile(filePath);
            if (findings.length > 0) {
              logSecretDetection({
                findings,
                hookInput: { session_key: ctx?.sessionKey },
                eventName: "before_tool_call",
                context: "secret_detected_before_read",
                toolLabel: "riphook-openclaw",
              });
              return {
                block: true,
                blockReason: "Secret detected in file read",
              };
            }
          } catch {
            // ignore
          }
        }

        const paramFindings = scanParamsForSecrets(params, "[tool params]");
        if (paramFindings.length > 0) {
          logSecretDetection({
            findings: paramFindings,
            hookInput: { session_key: ctx?.sessionKey },
            eventName: "before_tool_call",
            context: "secret_detected_in_params",
            toolLabel: "riphook-openclaw",
          });
          return {
            block: true,
            blockReason: "Secret detected in tool parameters",
          };
        }

        if (containsPii(JSON.stringify(params))) {
          return {
            block: true,
            blockReason: "PII detected in tool parameters",
          };
        }

        return undefined;
      },
      { priority: 100 },
    );
  },
};
