import { describe, it, expect } from "vitest";
import plugin from "../src/openclaw/plugin.js";

describe("openclaw plugin", () => {
  it("blocks secret in tool params", async () => {
    let handler: ((event: unknown, ctx: unknown) => unknown) | undefined;
    const api = {
      on: (event, fn) => {
        if (event === "before_tool_call") handler = fn;
      },
    };

    plugin.register(api);
    expect(handler).toBeTypeOf("function");

    const result = await handler(
      {
        toolName: "read",
        params: {
          token: "sk-ant-api1234567890abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890",
        },
      },
      { sessionKey: "sess-1" },
    );

    expect(result?.block).toBe(true);
  });

  it("blocks PII in tool params", async () => {
    let handler: ((event: unknown, ctx: unknown) => unknown) | undefined;
    const api = {
      on: (event, fn) => {
        if (event === "before_tool_call") handler = fn;
      },
    };

    plugin.register(api);
    expect(handler).toBeTypeOf("function");

    const result = await handler(
      {
        toolName: "exec",
        params: {
          command: "echo '4358 9100 8899 4843'",
        },
      },
      { sessionKey: "sess-1" },
    );

    expect(result?.block).toBe(true);
  });
});
