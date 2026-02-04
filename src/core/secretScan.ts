import fs from "node:fs";
import path from "node:path";
import { SECRET_PATTERNS } from "./secretPatterns.js";

const MAX_SCAN_BYTES = 5 * 1024 * 1024;
const SAMPLE_BYTES = 4096;

export type SecretFinding = {
  file: string;
  line: number;
  type: string;
  match: string;
};

function isProbablyBinary(block: Buffer): boolean {
  if (block.includes(0)) return true;
  const textChars = new Set<number>();
  for (let i = 32; i < 127; i += 1) textChars.add(i);
  [10, 13, 9, 8].forEach((code) => textChars.add(code));
  let nonText = 0;
  for (const byte of block) {
    if (!textChars.has(byte)) nonText += 1;
  }
  return nonText / Math.max(1, block.length) > 0.3;
}

function shouldScanFile(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(Math.min(SAMPLE_BYTES, fs.statSync(filePath).size));
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    if (buffer.length === 0) return true;
    return !isProbablyBinary(buffer);
  } catch {
    return false;
  }
}

function scanText(text: string, label: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") lineStarts.push(i + 1);
  }

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    // eslint-disable-next-line no-cond-assign
    while ((match = pattern.regex.exec(text)) !== null) {
      const index = match.index ?? 0;
      let line = 1;
      for (let i = 0; i < lineStarts.length; i += 1) {
        if (lineStarts[i] <= index) line = i + 1;
        else break;
      }
      findings.push({
        file: label,
        line,
        type: pattern.name,
        match: match[0] ?? "",
      });
    }
  }

  return findings;
}

function scanFile(filePath: string): SecretFinding[] {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File does not exist: ${filePath}`);
  }

  if (!shouldScanFile(filePath)) return [];

  const size = fs.statSync(filePath).size;
  if (size > MAX_SCAN_BYTES) {
    throw new Error(`File size ${size} bytes exceeds scan limit of ${MAX_SCAN_BYTES}`);
  }

  const blob = fs.readFileSync(filePath);
  if (isProbablyBinary(blob)) return [];

  return scanText(blob.toString("utf8"), filePath);
}

function buildFindingsMessage(
  findings: SecretFinding[],
  heading: string,
  limit = 5,
): string {
  if (findings.length === 0) return heading;

  const grouped = new Map<string, SecretFinding[]>();
  for (const finding of findings) {
    const label = finding.file || "[unknown]";
    const entries = grouped.get(label) ?? [];
    entries.push(finding);
    grouped.set(label, entries);
  }

  const lines: string[] = [];
  for (const [label, entries] of grouped.entries()) {
    const types = Array.from(new Set(entries.map((entry) => entry.type))).sort();
    const nums = entries.slice(0, limit).map((entry) => entry.line).join(", ");
    let line = `${label}: ${types.slice(0, 3).join(", ")}`;
    if (nums) line += ` (lines ${nums})`;
    if (entries.length > limit) line += ` (+${entries.length - limit} more)`;
    lines.push(line);
  }

  const message = lines.slice(0, limit).map((line) => ` - ${line}`).join("\n");
  const total = findings.length;
  let output = `${heading}\n${message}`;
  if (total > limit) output += `\nShowing first ${limit} of ${total} findings.`;

  return output;
}

function resolvePath(filePath: string, workspaceRoots: string[] = []): string {
  if (!filePath) return filePath;
  if (path.isAbsolute(filePath)) return filePath;
  const root = workspaceRoots[0] || process.env.CURSOR_PROJECT_DIR || process.cwd();
  return path.join(root, filePath.replace(/^\//, ""));
}

export {
  MAX_SCAN_BYTES,
  SAMPLE_BYTES,
  isProbablyBinary,
  shouldScanFile,
  scanText,
  scanFile,
  buildFindingsMessage,
  resolvePath,
};
