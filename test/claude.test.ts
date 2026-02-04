import { describe, it, expect } from "vitest";
import { runClaudeHook } from "../src/claude/logic.js";

describe("claude hook", () => {
  it("denies dangerous PreToolUse", () => {
    const input = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "rm -rf /" },
    });
    const output = runClaudeHook(input);
    expect(output).toBeTruthy();
    const parsed = JSON.parse(output as string);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("blocks secrets in UserPromptSubmit", () => {
    const input = JSON.stringify({
      hook_event_name: "UserPromptSubmit",
      user_prompt: "my key is sk-ant-api1234567890abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890",
    });
    const output = runClaudeHook(input);
    expect(output).toBeTruthy();
    const parsed = JSON.parse(output as string);
    expect(parsed.decision).toBe("block");
  });
});
