import { describe, expect, it } from "vitest";
import { McpManager } from "../src/index.js";

describe("MCP manager", () => {
  it("validates the local session pool and exposes non-secret health state", () => {
    const manager = new McpManager({ maxSessions: 3, connectRetries: 0 });
    expect(manager.status()).toEqual({ active: 0, waiting: 0, maxSessions: 3, closed: false });
    expect(() => new McpManager({ maxSessions: 0 })).toThrow("mcp_policy_invalid:maxSessions");
  });
});
