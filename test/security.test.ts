import { describe, it, expect } from "vitest";
import { validateCommand, validateToolInput } from "../src/core/security.js";

describe("security validation", () => {
  it("blocks dangerous commands", () => {
    const result = validateCommand("rm -rf /");
    expect(result.isSafe).toBe(false);
    expect(result.severity).toBe("block");
  });

  it("warns on sensitive file patterns", () => {
    const result = validateCommand("cat ~/.ssh/id_rsa");
    expect(result.isSafe).toBe(true);
    expect(result.severity).toBe("warn");
  });

  it("blocks protected file writes", () => {
    const result = validateToolInput("Write", { file_path: "/etc/passwd" });
    expect(result.severity).toBe("block");
  });
});
