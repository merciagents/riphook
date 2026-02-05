import fs from "node:fs";
import path from "node:path";
import { appendTrace, createTrace } from "../core/traceStore.js";
import {
  clearEditedFilePaths,
  loadEditedFilePaths,
} from "../core/editedFilesCache.js";
import {
  createTempFilesFromCodeContent,
  getSemgrepScanArgs,
  runSemgrepScan,
  validateLocalFiles,
} from "../core/semgrep.js";

function createStopTrace(
  hookInput: Record<string, unknown>,
  status: string,
  extra?: Record<string, unknown>,
): void {
  appendTrace(
    createTrace({
      contributorType: "ai",
      filePath: ".stop-hooks",
      model: hookInput.model as string | undefined,
      transcript: hookInput.transcript_path as string | undefined,
      metadata: {
        event: "stop_hook_executed",
        tool: "riphook",
        conversation_id: hookInput.conversation_id,
        generation_id: hookInput.generation_id,
        status,
        ...(extra ?? {}),
      },
    }),
  );
}

function runClaudeStopScan(
  hookInput: Record<string, unknown>,
): Record<string, unknown> {
  let tempDir: string | null = null;
  try {
    const editedFilePaths = loadEditedFilePaths();
    if (editedFilePaths.length === 0) {
      createStopTrace(hookInput, "no_files_to_scan");
      return {};
    }

    const validatedFiles = validateLocalFiles(
      editedFilePaths,
      String(hookInput.cwd ?? ""),
    );
    if (validatedFiles.length === 0) {
      createStopTrace(hookInput, "no_valid_files");
      return {};
    }

    tempDir = createTempFilesFromCodeContent(validatedFiles);
    const args = getSemgrepScanArgs(tempDir, null);
    const { returncode, stdout, stderr, semgrepPath } = runSemgrepScan(args);

    if (returncode !== 0) {
      const errorText = stderr || stdout || "Unknown semgrep error";
      createStopTrace(hookInput, "scan_failed", {
        error: errorText.slice(0, 500),
        semgrep_path: semgrepPath,
      });
      return {
        systemMessage: `Semgrep scan encountered errors: ${errorText.slice(0, 500)} (semgrep: ${semgrepPath})`,
      };
    }

    try {
      const scanResult = JSON.parse(stdout) as { results?: unknown[] };
      const results = scanResult.results ?? [];

      if (results.length > 0) {
        const findingsSummary = `Found ${results.length} security finding(s)`;
        const stopHookActive = Boolean(hookInput.stop_hook_active);

        const filesWithVulns = new Map<string, Record<string, unknown>[]>();
        for (const result of results) {
          if (!result || typeof result !== "object") continue;
          const record = result as Record<string, unknown>;
          let filePath: string | undefined;
          if (typeof record.path === "string") filePath = record.path;
          if (typeof record.path === "object" && record.path) {
            filePath = (record.path as Record<string, unknown>).value as string;
          }
          if (!filePath) {
            const target = record.target as Record<string, unknown> | undefined;
            filePath = (target?.path as string | undefined) ?? undefined;
          }

          if (filePath) {
            const baseName = path.basename(filePath);
            const original = editedFilePaths.find(
              (orig) => path.basename(orig) === baseName,
            );
            if (original) {
              const bucket = filesWithVulns.get(original) ?? [];
              bucket.push(record);
              filesWithVulns.set(original, bucket);
            }
          }
        }

        for (const [filePath, vulnResults] of filesWithVulns.entries()) {
          appendTrace(
            createTrace({
              contributorType: "ai",
              filePath,
              model: hookInput.model as string | undefined,
              rangePositions: vulnResults.map((vuln) => {
                const start = (vuln.start as Record<string, unknown> | undefined)?.line;
                const end = (vuln.end as Record<string, unknown> | undefined)?.line;
                const line = vuln.line as number | undefined;
                const endLine = (vuln.end_line as number | undefined) ?? line;
                return {
                  start_line: (typeof start === "number" ? start : line) ?? 1,
                  end_line: (typeof end === "number" ? end : endLine) ?? 1,
                };
              }),
              transcript: hookInput.transcript_path as string | undefined,
              metadata: {
                event: "vulnerability_detected",
                tool: "riphook",
                scanner: "semgrep",
                conversation_id: hookInput.conversation_id,
                generation_id: hookInput.generation_id,
                vulnerability_count: vulnResults.length,
              },
            }),
          );
        }

        createStopTrace(hookInput, "vulnerabilities_found", {
          total_vulnerabilities: results.length,
          files_scanned: editedFilePaths.length,
        });

        if (!stopHookActive) {
          const findingsJson = JSON.stringify(results);
          return {
            decision: "block",
            reason: `${findingsSummary}. Review the findings and address any security issues. ${findingsJson}`,
          };
        }

        return {
          systemMessage: `${findingsSummary}. Stop hook already active, allowing stop.`,
        };
      }

      createStopTrace(hookInput, "no_vulnerabilities", {
        files_scanned: editedFilePaths.length,
      });
      return {};
    } catch (error) {
      createStopTrace(hookInput, "parse_error", { error: String(error) });
      return {};
    }
  } finally {
    if (tempDir) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    clearEditedFilePaths();
  }
}

export { runClaudeStopScan };
