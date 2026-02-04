import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

function getSemgrepPath(): string | null {
  const repoRoot = path.resolve(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", ".."),
  );
  const venvBin = process.platform === "win32" ? "Scripts" : "bin";
  const venvSemgrep = path.join(repoRoot, ".venv", venvBin, process.platform === "win32" ? "semgrep.exe" : "semgrep");

  const candidates = [
    venvSemgrep,
    process.env.SEMGREP_PATH,
    path.join(process.cwd(), "node_modules", ".bin", "semgrep"),
    path.join(os.homedir(), ".local", "bin", "semgrep"),
    "/usr/local/bin/semgrep",
    "/opt/homebrew/bin/semgrep",
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }

  const pathEntries = (process.env.PATH ?? "").split(path.delimiter);
  for (const entry of pathEntries) {
    const target = path.join(entry, "semgrep");
    if (fs.existsSync(target)) return target;
  }

  return null;
}

function getSemgrepScanArgs(tempDir: string, config?: string | null): string[] {
  const args = ["scan", "--json"];
  if (config) args.push("--config", config);
  args.push(tempDir);
  return args;
}

function runSemgrepScan(args: string[]): {
  returncode: number;
  stdout: string;
  stderr: string;
} {
  const semgrepPath = getSemgrepPath();
  if (!semgrepPath) throw new Error("Failed to find semgrep binary");

  const env = { ...process.env, SEMGREP_LOG_SRCS: "hooks-project" };
  const result = spawnSync(semgrepPath, args, {
    encoding: "utf8",
    env,
  });

  return {
    returncode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function safeJoin(baseDir: string, untrustedPath: string): string {
  const basePath = path.resolve(baseDir);
  if (!untrustedPath || untrustedPath === "." || untrustedPath.replace(/\//g, "") === "") {
    return basePath;
  }
  if (path.isAbsolute(untrustedPath)) {
    throw new Error("Untrusted path must be relative");
  }
  const fullPath = path.resolve(basePath, untrustedPath);
  if (!fullPath.startsWith(basePath)) {
    throw new Error(`Untrusted path escapes the base directory!: ${untrustedPath}`);
  }
  return fullPath;
}

function createTempFilesFromCodeContent(
  codeFiles: Array<{ path: string; content: string }>,
): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "semgrep_scan_"));
  try {
    for (const fileInfo of codeFiles) {
      const filename = fileInfo.path;
      if (!filename) continue;
      const tempFilePath = safeJoin(tempDir, filename);
      fs.mkdirSync(path.dirname(tempFilePath), { recursive: true });
      fs.writeFileSync(tempFilePath, fileInfo.content ?? "", "utf8");
    }
    return tempDir;
  } catch (error) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

function validateLocalFiles(
  filePaths: string[],
  baseDir?: string,
): Array<{ path: string; content: string }> {
  if (!filePaths.length) throw new Error("filePaths must be a non-empty list");

  const validated: Array<{ path: string; content: string }> = [];
  for (const filePath of filePaths) {
    const resolvedPath = path.isAbsolute(filePath)
      ? filePath
      : baseDir
        ? path.join(baseDir, filePath)
        : filePath;
    if (!path.isAbsolute(resolvedPath)) {
      throw new Error(`File path must be absolute: ${filePath}`);
    }
    if (!fs.existsSync(resolvedPath)) continue;
    try {
      const content = fs.readFileSync(resolvedPath, "utf8");
      validated.push({ path: path.basename(resolvedPath), content });
    } catch {
      continue;
    }
  }
  return validated;
}

export {
  getSemgrepPath,
  getSemgrepScanArgs,
  runSemgrepScan,
  safeJoin,
  createTempFilesFromCodeContent,
  validateLocalFiles,
};
