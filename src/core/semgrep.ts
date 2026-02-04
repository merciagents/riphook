import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

function findRepoRoot(startDir: string): string | null {
  let current = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(current, "package.json")) || fs.existsSync(path.join(current, ".git"))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function getSemgrepPath(): string | null {
  const venvBin = process.platform === "win32" ? "Scripts" : "bin";
  const semgrepExe = process.platform === "win32" ? "semgrep.exe" : "semgrep";
  const cwd = process.cwd();
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRootFromScript = findRepoRoot(scriptDir) ?? path.resolve(scriptDir, "..", "..");
  const repoRootFromCwd = findRepoRoot(cwd);

  const candidates: string[] = [];
  const addCandidate = (candidate?: string | null) => {
    if (!candidate) return;
    if (!candidates.includes(candidate)) candidates.push(candidate);
  };

  addCandidate(process.env.SEMGREP_PATH);

  const envVenvs = [
    process.env.VIRTUAL_ENV,
    process.env.CONDA_PREFIX,
    process.env.PYENV_VIRTUAL_ENV,
  ].filter(Boolean) as string[];

  for (const envVenv of envVenvs) {
    addCandidate(path.join(envVenv, venvBin, semgrepExe));
  }

  addCandidate(path.join(cwd, ".venv", venvBin, semgrepExe));

  const workspaceRoots = [
    process.env.CURSOR_PROJECT_DIR,
    process.env.CLAUDE_PROJECT_DIR,
  ].filter(Boolean) as string[];
  for (const root of workspaceRoots) {
    addCandidate(path.join(root, ".venv", venvBin, semgrepExe));
  }

  if (repoRootFromCwd) {
    addCandidate(path.join(repoRootFromCwd, ".venv", venvBin, semgrepExe));
    addCandidate(path.join(repoRootFromCwd, "node_modules", ".bin", semgrepExe));
  }

  if (repoRootFromScript) {
    addCandidate(path.join(repoRootFromScript, ".venv", venvBin, semgrepExe));
    addCandidate(path.join(repoRootFromScript, "node_modules", ".bin", semgrepExe));
  }

  addCandidate(path.join(cwd, "node_modules", ".bin", semgrepExe));
  addCandidate(path.join(os.homedir(), ".local", "bin", semgrepExe));
  addCandidate("/usr/local/bin/semgrep");
  addCandidate("/opt/homebrew/bin/semgrep");

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }

  const pathEntries = (process.env.PATH ?? "").split(path.delimiter);
  for (const entry of pathEntries) {
    const target = path.join(entry, semgrepExe);
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

function getVenvPythonFromSemgrepPath(semgrepPath: string): string | null {
  const venvBin = process.platform === "win32" ? "Scripts" : "bin";
  const pythonExe = process.platform === "win32" ? "python.exe" : "python";
  const parts = semgrepPath.split(path.sep);
  const venvIndex = parts.lastIndexOf(".venv");
  if (venvIndex === -1) return null;
  const venvRoot = parts.slice(0, venvIndex + 1).join(path.sep);
  const pythonPath = path.join(venvRoot, venvBin, pythonExe);
  return fs.existsSync(pythonPath) ? pythonPath : null;
}

function getVenvBinFromSemgrepPath(semgrepPath: string): string | null {
  const parts = semgrepPath.split(path.sep);
  const venvIndex = parts.lastIndexOf(".venv");
  if (venvIndex === -1) return null;
  const venvRoot = parts.slice(0, venvIndex + 1).join(path.sep);
  const venvBin = process.platform === "win32" ? "Scripts" : "bin";
  const binPath = path.join(venvRoot, venvBin);
  return fs.existsSync(binPath) ? binPath : null;
}

function repairSemgrepShebang(semgrepPath: string, venvPython: string): boolean {
  if (process.platform === "win32") return false;
  try {
    const stat = fs.statSync(semgrepPath);
    const original = fs.readFileSync(semgrepPath, "utf8");
    const lines = original.split("\n");
    if (lines.length === 0) return false;
    if (!lines[0].startsWith("#!")) return false;
    lines[0] = `#!${venvPython}`;
    fs.writeFileSync(semgrepPath, lines.join("\n"), "utf8");
    fs.chmodSync(semgrepPath, stat.mode);
    return true;
  } catch {
    return false;
  }
}

function repairPySemgrepShebang(semgrepPath: string, venvPython: string): boolean {
  if (process.platform === "win32") return false;
  try {
    const venvBin = getVenvBinFromSemgrepPath(semgrepPath);
    if (!venvBin) return false;
    const pysemgrepPath = path.join(venvBin, "pysemgrep");
    if (!fs.existsSync(pysemgrepPath)) return false;
    const stat = fs.statSync(pysemgrepPath);
    const original = fs.readFileSync(pysemgrepPath, "utf8");
    const lines = original.split("\n");
    if (lines.length === 0) return false;
    if (!lines[0].startsWith("#!")) return false;
    lines[0] = `#!${venvPython}`;
    fs.writeFileSync(pysemgrepPath, lines.join("\n"), "utf8");
    fs.chmodSync(pysemgrepPath, stat.mode);
    return true;
  } catch {
    return false;
  }
}

function runSemgrepScan(args: string[]): {
  returncode: number;
  stdout: string;
  stderr: string;
  semgrepPath: string;
} {
  const semgrepPath = getSemgrepPath();
  if (!semgrepPath) throw new Error("Failed to find semgrep binary");

  const env: NodeJS.ProcessEnv = { ...process.env, SEMGREP_LOG_SRCS: "riphook" };
  const venvBin = getVenvBinFromSemgrepPath(semgrepPath);
  if (venvBin) {
    const existingPath = env.PATH ?? "";
    env.PATH = `${venvBin}${path.delimiter}${existingPath}`;
  }

  const venvPython = getVenvPythonFromSemgrepPath(semgrepPath);
  if (venvPython) {
    repairSemgrepShebang(semgrepPath, venvPython);
    repairPySemgrepShebang(semgrepPath, venvPython);
  }
  let result = spawnSync(semgrepPath, args, {
    encoding: "utf8",
    env,
  });

  const spawnError = result.error as NodeJS.ErrnoException | undefined;
  if (
    result.status !== 0 &&
    (result.stderr?.includes("bad interpreter") ||
      result.stderr?.includes("execvp pysemgrep") ||
      spawnError?.code === "ENOENT")
  ) {
    if (venvPython) {
      repairSemgrepShebang(semgrepPath, venvPython);
      repairPySemgrepShebang(semgrepPath, venvPython);
      result = spawnSync(semgrepPath, args, {
        encoding: "utf8",
        env,
      });
    }
  }

  return {
    returncode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    semgrepPath,
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
