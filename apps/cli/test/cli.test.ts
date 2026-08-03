import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../src/main.js";

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "generic-cli-"));
  await writeFile(join(root, "plugin.mjs"), `
const snapshot={run:{id:'cli-run-1'},status:'succeeded',createdAt:'2026-01-01T00:00:00.000Z',updatedAt:'2026-01-01T00:00:00.000Z',details:{ok:true}};
let current=snapshot;
const runtime={
  operation:async op=>op.payload,
  createRun:async request=>(current={...snapshot,details:request.payload}),
  adoptRun:async()=>current,getRun:async()=>current,
  events:async function*(){},action:async()=>current,artifacts:async()=>[],
  openArtifact:async()=>{throw new Error('not_found')},dispose:async()=>{}
};
export const plugin={
  manifest:{apiVersion:'1',id:'cli-fixture',version:'1.0.0',displayName:'CLI Fixture',contributes:['runs','cli']},
  cli:[
    {name:'echo',description:'echo',usage:'echo <value>',invoke:args=>({kind:'operation',operation:{name:'echo',payload:{value:args[0]}}})},
    {name:'execute',description:'execute',usage:'execute',invoke:()=>({kind:'run',payload:{started:true}})}
  ],
  activate:()=>runtime
};
`);
  const config = join(root, "agent-platform.json");
  await writeFile(config, JSON.stringify({ plugins: { modules: ["./plugin.mjs"] } }));
  return config;
}

describe("generic plugin CLI", () => {
  it("discovers commands and delegates operations and terminal runs", async () => {
    const config = await fixture();
    expect(await runCli(["plugins", "--config", config])).toMatchObject({ plugins: [{ id: "cli-fixture" }] });
    expect(await runCli(["echo", "hello", "--config", config])).toEqual({ value: "hello" });
    expect(await runCli(["cli-fixture:echo", "qualified", "--config", config])).toEqual({ value: "qualified" });
    expect(await runCli(["execute", "--config", config])).toMatchObject({
      pluginId: "cli-fixture", status: "succeeded", snapshot: { details: { started: true } },
    });
  });

  it("uses stable usage errors without domain command branches", async () => {
    const config = await fixture();
    await expect(runCli(["unknown", "--config", config])).rejects.toThrow("usage:unknown_command:unknown");
    await expect(runCli([])).rejects.toThrow("usage:missing_command");
  });
});
