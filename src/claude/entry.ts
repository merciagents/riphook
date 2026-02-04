import fs from "node:fs";
import { runClaudeHook } from "./logic.js";

function readStdin(): string {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function main(): void {
  const output = runClaudeHook(readStdin());
  if (output) process.stdout.write(output);
}

main();
