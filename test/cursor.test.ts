import { describe, it, expect } from "vitest";
import { runCursorHook } from "../src/cursor/logic.js";

describe("cursor hook", () => {
  it("denies dangerous preToolUse", () => {
    const input = JSON.stringify({
      hook_event_name: "preToolUse",
      tool_name: "Bash",
      tool_input: { command: "rm -rf /" },
    });

    const { output, exitCode } = runCursorHook(input);
    const parsed = JSON.parse(output);
    expect(parsed.decision).toBe("deny");
    expect(exitCode).toBe(2);
  });

  it("blocks secrets in beforeReadFile content", () => {
    const input = JSON.stringify({
      hook_event_name: "beforeReadFile",
      file_path: "config.txt",
      content: "sk-ant-api1234567890abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890",
    });

    const { output, exitCode } = runCursorHook(input);
    const parsed = JSON.parse(output);
    expect(parsed.permission).toBe("deny");
    expect(exitCode).toBe(2);
  });
});
