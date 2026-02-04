import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const TRACE_PATH = ".agent-trace/traces.jsonl";
const VERSION = "1.0";

export type RangePosition = { start_line: number; end_line: number };
export type TraceMetadata = Record<string, unknown>;

function getWorkspaceRoot(): string {
  if (process.env.CURSOR_PROJECT_DIR) return process.env.CURSOR_PROJECT_DIR;
  if (process.env.CLAUDE_PROJECT_DIR) return process.env.CLAUDE_PROJECT_DIR;

  try {
    const output = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    });
    return output.trim();
  } catch {
    return process.cwd();
  }
}

function hasGitRoot(startDir: string): boolean {
  let current = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(current, ".git"))) return true;
    const parent = path.dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

function getToolInfo(): { name: string; version?: string } {
  if (process.env.CURSOR_VERSION) {
    return { name: "cursor", version: process.env.CURSOR_VERSION };
  }
  if (process.env.CLAUDE_PROJECT_DIR) {
    return { name: "claude-code" };
  }
  return { name: "riphook", version: "1.0.0" };
}

function getVcsInfo(cwd: string): { type: string; revision: string } | null {
  if (!hasGitRoot(cwd)) return null;
  try {
    const output = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd,
      encoding: "utf8",
    });
    return { type: "git", revision: output.trim() };
  } catch {
    return null;
  }
}

function toRelativePath(absolutePath: string, root: string): string {
  try {
    return path.relative(root, absolutePath);
  } catch {
    return absolutePath;
  }
}

function normalizeModelId(model?: string | null): string | undefined {
  if (!model) return undefined;
  if (model.includes("/")) return model;

  const prefixes: Record<string, string> = {
    "claude-": "anthropic",
    "gpt-": "openai",
    o1: "openai",
    o3: "openai",
    "gemini-": "google",
  };

  for (const [prefix, provider] of Object.entries(prefixes)) {
    if (model.startsWith(prefix)) return `${provider}/${model}`;
  }

  return model;
}

function computeRangePositions(
  edits: Array<Record<string, unknown>>,
  fileContent?: string | null,
): RangePosition[] {
  const ranges: RangePosition[] = [];

  for (const edit of edits) {
    const newString = typeof edit.new_string === "string" ? edit.new_string : "";
    if (!newString) continue;

    const rangeInfo = edit.range as Record<string, number> | undefined;
    if (rangeInfo && rangeInfo.start_line_number && rangeInfo.end_line_number) {
      ranges.push({
        start_line: rangeInfo.start_line_number,
        end_line: rangeInfo.end_line_number,
      });
      continue;
    }

    const lineCount = newString.split("\n").length;
    if (fileContent) {
      const index = fileContent.indexOf(newString);
      if (index !== -1) {
        const startLine = fileContent.slice(0, index).split("\n").length;
        ranges.push({ start_line: startLine, end_line: startLine + lineCount - 1 });
        continue;
      }
    }

    ranges.push({ start_line: 1, end_line: Math.max(1, lineCount) });
  }

  return ranges;
}

function tryReadFile(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function createTrace(options: {
  contributorType: "human" | "ai" | "mixed" | "unknown";
  filePath: string;
  model?: string | null;
  rangePositions?: RangePosition[] | null;
  transcript?: string | null;
  metadata?: TraceMetadata | null;
}): Record<string, unknown> {
  const root = getWorkspaceRoot();
  const modelId = normalizeModelId(options.model ?? undefined);
  const conversationUrl = options.transcript
    ? `file://${options.transcript}`
    : undefined;

  const ranges = (options.rangePositions ?? []).length
    ? options.rangePositions
    : [{ start_line: 1, end_line: 1 }];

  const contributor: Record<string, unknown> = {
    type: options.contributorType,
  };
  if (modelId) contributor.model_id = modelId;

  const conversation: Record<string, unknown> = {
    contributor,
    ranges,
  };
  if (conversationUrl) conversation.url = conversationUrl;

  const trace: Record<string, unknown> = {
    version: VERSION,
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    files: [
      {
        path: toRelativePath(options.filePath, root),
        conversations: [conversation],
      },
    ],
  };

  const vcsInfo = getVcsInfo(root);
  if (vcsInfo) trace.vcs = vcsInfo;

  const toolInfo = getToolInfo();
  if (toolInfo) trace.tool = toolInfo;

  if (options.metadata && Object.keys(options.metadata).length > 0) {
    trace.metadata = options.metadata;
  }

  return trace;
}

function appendTrace(trace: Record<string, unknown>): void {
  const root = getWorkspaceRoot();
  const traceDir = path.join(root, ".agent-trace");
  const traceFile = path.join(root, TRACE_PATH);

  fs.mkdirSync(traceDir, { recursive: true });
  fs.appendFileSync(traceFile, `${JSON.stringify(trace)}${os.EOL}`, "utf8");
}

export {
  TRACE_PATH,
  VERSION,
  getWorkspaceRoot,
  getToolInfo,
  getVcsInfo,
  normalizeModelId,
  computeRangePositions,
  tryReadFile,
  createTrace,
  appendTrace,
};
