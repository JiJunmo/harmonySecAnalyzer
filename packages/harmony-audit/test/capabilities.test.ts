import { describe, expect, it } from "vitest";
import { listCapabilities, resolveCapabilities } from "../src/capabilities.js";

describe("capability registry", () => {
  it("expands an empty filter to every enabled capability", async () => {
    const capabilities = await resolveCapabilities([]);
    expect(capabilities).toContain("CAP-INJ-001");
    expect(capabilities).toContain("CAP-DOS-001");
    expect(capabilities).toContain("CAP-NATIVE-DEP-001");
    expect(capabilities).toHaveLength(21);
  });
  it("has no remaining planned/deferred entries and rejects unknown capabilities", async () => {
    expect((await listCapabilities()).filter((item) => item.status !== "enabled")).toEqual([]);
    await expect(resolveCapabilities(["CAP-UNKNOWN-001"])).rejects.toThrow("capability_not_enabled");
  });
});
