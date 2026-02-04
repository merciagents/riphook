import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const CACHE_FILE = path.join(os.tmpdir(), "saved", "edited-files.json");
const FILE_EDIT_LIMIT = 500;

function loadEditedFilePaths(): string[] {
  if (!fs.existsSync(CACHE_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(CACHE_FILE, "utf8")) as string[];
  } catch {
    return [];
  }
}

function appendEditedFilePath(filePath: string): void {
  const edited = loadEditedFilePaths();
  if (edited.length >= FILE_EDIT_LIMIT) return;
  if (edited.includes(filePath)) return;
  edited.push(filePath);
  fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
  fs.writeFileSync(CACHE_FILE, JSON.stringify(edited), "utf8");
}

function clearEditedFilePaths(): void {
  try {
    fs.rmSync(CACHE_FILE, { force: true });
  } catch {
    return;
  }
}

export { CACHE_FILE, FILE_EDIT_LIMIT, loadEditedFilePaths, appendEditedFilePath, clearEditedFilePaths };
