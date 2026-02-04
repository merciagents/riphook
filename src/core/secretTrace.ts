import { appendTrace, createTrace } from "./traceStore.js";
import type { SecretFinding } from "./secretScan.js";

function logSecretDetection(options: {
  findings: SecretFinding[];
  hookInput: Record<string, unknown>;
  eventName: string;
  context: string;
  toolLabel?: string;
}): void {
  const { findings, hookInput, eventName, context, toolLabel } = options;
  const model = hookInput.model as string | undefined;
  const transcriptPath = hookInput.transcript_path as string | undefined;
  const conversationId = hookInput.conversation_id as string | undefined;
  const generationId = hookInput.generation_id as string | undefined;

  const findingsByFile = new Map<string, SecretFinding[]>();
  for (const finding of findings) {
    const filePath = finding.file || "[unknown]";
    const bucket = findingsByFile.get(filePath) ?? [];
    bucket.push(finding);
    findingsByFile.set(filePath, bucket);
  }

  for (const [filePath, fileFindings] of findingsByFile.entries()) {
    const ranges = fileFindings.map((finding) => ({
      start_line: finding.line || 1,
      end_line: finding.line || 1,
    }));

    appendTrace(
      createTrace({
        contributorType: "ai",
        filePath,
        model,
        rangePositions: ranges,
        transcript: transcriptPath,
        metadata: {
          event: context,
          tool: toolLabel ?? "riphook",
          scanner: "secret-scan",
          hook_event: eventName,
          conversation_id: conversationId,
          generation_id: generationId,
          secret_count: fileFindings.length,
          secrets: fileFindings.map((finding) => ({
            type: finding.type,
            line: finding.line,
            match_preview:
              finding.match.length > 50
                ? `${finding.match.slice(0, 50)}...`
                : finding.match,
          })),
        },
      }),
    );
  }
}

export { logSecretDetection };
