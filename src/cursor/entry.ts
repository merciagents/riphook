import fs from "node:fs";
import { runCursorHook } from "./logic.js";

function readStdin(): string {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function main(): void {
  const { output, exitCode } = runCursorHook(readStdin());
  if (output) process.stdout.write(output);
  process.exitCode = exitCode;
}

main();
