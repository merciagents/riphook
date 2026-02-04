import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const READ_COMMANDS = new Set([
  "cat",
  "grep",
  "rg",
  "ripgrep",
  "sed",
  "awk",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "cut",
  "sort",
  "uniq",
  "tr",
  "nl",
  "wc",
]);

const SEPARATORS = new Set(["|", "||", "&&", ";"]);
const REDIRECTORS = new Set(["<", "<<"]);

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  let buf = "";
  let i = 0;
  let mode: "none" | "single" | "double" = "none";

  const pushBuf = () => {
    if (buf.length > 0) {
      tokens.push(buf);
      buf = "";
    }
  };

  while (i < command.length) {
    const ch = command[i];
    if (mode === "single") {
      if (ch === "'") {
        mode = "none";
      } else {
        buf += ch;
      }
      i += 1;
      continue;
    }

    if (mode === "double") {
      if (ch === "\"") {
        mode = "none";
      } else if (ch === "\\" && i + 1 < command.length) {
        buf += command[i + 1];
        i += 2;
        continue;
      } else {
        buf += ch;
      }
      i += 1;
      continue;
    }

    if (ch === "'") {
      mode = "single";
      i += 1;
      continue;
    }
    if (ch === "\"") {
      mode = "double";
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      pushBuf();
      i += 1;
      continue;
    }

    if (ch === "|" || ch === "&") {
      pushBuf();
      const next = command[i + 1];
      if (next === ch) {
        tokens.push(ch + next);
        i += 2;
      } else {
        tokens.push(ch);
        i += 1;
      }
      continue;
    }

    if (ch === ";" || ch === "<" || ch === ">") {
      pushBuf();
      const next = command[i + 1];
      if ((ch === "<" || ch === ">") && next === ch) {
        tokens.push(ch + next);
        i += 2;
      } else {
        tokens.push(ch);
        i += 1;
      }
      continue;
    }

    if (ch === "\\" && i + 1 < command.length) {
      buf += command[i + 1];
      i += 2;
      continue;
    }

    buf += ch;
    i += 1;
  }

  pushBuf();
  return tokens;
}

function isEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function looksLikePath(token: string): boolean {
  if (!token) return false;
  if (token === "-" || token.startsWith("-")) return false;
  if (token.includes("*") || token.includes("?") || token.includes("[")) return false;
  return token.includes("/") || token.startsWith(".") || token.startsWith("~");
}

function looksLikeBareFilename(token: string): boolean {
  if (!token) return false;
  if (token.startsWith("-")) return false;
  if (token.includes("/") || token.includes("\\")) return false;
  if (!token.includes(".")) return false;
  if (token.length > 255) return false;
  return /^[A-Za-z0-9._-]+$/.test(token);
}

function expandHome(inputPath: string): string {
  if (inputPath === "~") return os.homedir();
  if (inputPath.startsWith("~/")) return path.join(os.homedir(), inputPath.slice(2));
  return inputPath;
}

function resolveCandidatePath(
  token: string,
  baseDir?: string,
  workspaceRoots: string[] = [],
): string {
  const expanded = expandHome(token);
  if (path.isAbsolute(expanded)) return expanded;
  const root = baseDir || workspaceRoots[0] || process.cwd();
  return path.resolve(root, expanded);
}

function isFilePath(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function sanitizeCandidate(raw: string): string {
  let candidate = raw.trim();
  while (candidate.length > 0 && "\"'({[<".includes(candidate[0])) {
    candidate = candidate.slice(1);
  }
  while (candidate.length > 0 && "\"')}]>,;:".includes(candidate[candidate.length - 1])) {
    candidate = candidate.slice(0, -1);
  }
  return candidate;
}

function extractPathsFromString(
  command: string,
  baseDir?: string,
  workspaceRoots: string[] = [],
): string[] {
  const paths: string[] = [];
  const pathRegex = /(?:~\/|\.\.?\/|\/)[^\s"'`<>|;&]+/g;
  const bareRegex = /\b[A-Za-z0-9._-]+\.[A-Za-z0-9._-]{1,10}\b/g;

  const candidates = new Set<string>();
  for (const match of command.matchAll(pathRegex)) {
    candidates.add(sanitizeCandidate(match[0]));
  }
  for (const match of command.matchAll(bareRegex)) {
    candidates.add(sanitizeCandidate(match[0]));
  }

  for (const candidate of candidates) {
    if (!candidate) continue;
    if (!looksLikePath(candidate) && !looksLikeBareFilename(candidate)) continue;
    const resolved = resolveCandidatePath(candidate, baseDir, workspaceRoots);
    if (isFilePath(resolved)) paths.push(resolved);
  }

  return paths;
}

function extractReadPathsFromTokens(
  tokens: string[],
  baseDir?: string,
  workspaceRoots: string[] = [],
): string[] {
  const paths: string[] = [];
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (SEPARATORS.has(token)) {
      i += 1;
      continue;
    }

    let commandIndex = i;
    while (commandIndex < tokens.length && isEnvAssignment(tokens[commandIndex])) {
      commandIndex += 1;
    }

    let command = tokens[commandIndex] ?? "";
    if (command === "sudo") {
      commandIndex += 1;
      command = tokens[commandIndex] ?? "";
    }

    if (!command) {
      i = commandIndex + 1;
      continue;
    }

    const lowerCommand = command.toLowerCase();
    const isReadCommand = READ_COMMANDS.has(lowerCommand);
    let start = commandIndex + 1;
    if (!isReadCommand) {
      i = start;
      continue;
    }

    let skippedPattern = false;
    while (start < tokens.length && !SEPARATORS.has(tokens[start])) {
      const arg = tokens[start];
      if (REDIRECTORS.has(arg)) {
        const next = tokens[start + 1];
        if (next && looksLikePath(next)) {
          const resolved = resolveCandidatePath(next, baseDir, workspaceRoots);
          if (isFilePath(resolved)) paths.push(resolved);
        }
        start += 2;
        continue;
      }

      if (arg.startsWith("-")) {
        start += 1;
        continue;
      }

      if (["grep", "rg", "ripgrep"].includes(lowerCommand) && !skippedPattern) {
        if (!looksLikePath(arg)) {
          skippedPattern = true;
          start += 1;
          continue;
        }
      }

      if (looksLikePath(arg)) {
        const resolved = resolveCandidatePath(arg, baseDir, workspaceRoots);
        if (isFilePath(resolved)) paths.push(resolved);
      }
      start += 1;
    }

    i = start;
  }

  return Array.from(new Set(paths));
}

function extractShellReadPaths(
  command: string,
  baseDir?: string,
  workspaceRoots: string[] = [],
): string[] {
  if (!command.trim()) return [];
  const tokens = tokenizeCommand(command);
  const tokenPaths = extractReadPathsFromTokens(tokens, baseDir, workspaceRoots);
  const regexPaths = extractPathsFromString(command, baseDir, workspaceRoots);
  return Array.from(new Set([...tokenPaths, ...regexPaths]));
}

export { extractShellReadPaths };
