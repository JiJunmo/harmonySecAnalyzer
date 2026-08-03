import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Type, fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import { defineTool } from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it } from "vitest";
import { PiSessionFactory } from "../src/index.js";

const sessions: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
  await Promise.all(sessions.splice(0).map((session) => session.dispose()));
  delete process.env.TEST_PI_SESSION_KEY;
});

async function factory() {
  process.env.TEST_PI_SESSION_KEY = "runtime-only";
  const instance = await PiSessionFactory.create({
    models: {
      default: "general",
      tasks: { validate: "worker" },
      providers: {
        test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_PI_SESSION_KEY" },
      },
      catalog: {
        general: { provider: "test", id: "general-model", maxTokens: 2048 },
        worker: { provider: "test", id: "worker-model", maxTokens: 1024 },
      },
    },
  });
  const faux = fauxProvider({
    provider: "test",
    api: "faux",
    models: [{ id: "general-model" }, { id: "worker-model" }],
  });
  instance.models.runtime.registerNativeProvider(faux.provider);
  return { instance, faux };
}

describe("PiSessionFactory", () => {
  it("loads Pi official settings.json and models.json without a platform model schema", async () => {
    process.env.TEST_PI_SESSION_KEY = "runtime-only";
    const agentDir = await mkdtemp(join(tmpdir(), "pi-official-config-"));
    await writeFile(join(agentDir, "settings.json"), JSON.stringify({ defaultProvider: "official", defaultModel: "official-model", enabledModels: ["official/official-model"] }));
    await writeFile(join(agentDir, "models.json"), JSON.stringify({ providers: { official: {
      baseUrl: "http://unused.invalid/v1", api: "openai-completions", apiKey: "$TEST_PI_SESSION_KEY", models: [{ id: "official-model" }],
    } } }));

    const instance = await PiSessionFactory.create({ agentDir, cwd: agentDir });
    expect(instance.models.defaultAlias).toBe("official/official-model");
    expect(instance.models.aliases).toContain("official/official-model");
    expect(instance.models.resolve().id).toBe("official-model");
  });

  it("lists and toggles skills through Pi official settings.json", async () => {
    process.env.TEST_PI_SESSION_KEY = "runtime-only";
    const agentDir = await mkdtemp(join(tmpdir(), "pi-resource-config-"));
    const skillDir = join(agentDir, "skills", "example");
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "---\nname: example\ndescription: Example skill\n---\nUse the example capability.\n");
    await writeFile(join(agentDir, "settings.json"), JSON.stringify({ defaultProvider: "official", defaultModel: "official-model", skills: [skillDir] }));
    await writeFile(join(agentDir, "models.json"), JSON.stringify({ providers: { official: {
      baseUrl: "http://unused.invalid/v1", api: "openai-completions", apiKey: "$TEST_PI_SESSION_KEY", models: [{ id: "official-model" }],
    } } }));
    const instance = await PiSessionFactory.create({ agentDir, cwd: agentDir });
    const before = await instance.resources(agentDir);
    const skill = before.resources.find((resource) => resource.kind === "skill" && resource.name === "example");
    expect(skill).toMatchObject({ enabled: true, loaded: true });
    const after = await instance.setResourceEnabled(agentDir, "skill", skill!.id, false);
    expect(after.resources).toContainEqual(expect.objectContaining({ kind: "skill", id: skill!.id, name: "example", enabled: false, loaded: false }));
    expect(JSON.parse(await readFile(join(agentDir, "settings.json"), "utf8"))).toMatchObject({ skills: expect.arrayContaining([`-${skill!.id}`]) });
  });

  it("runs a domain-neutral interactive assistant with Pi defaults and events", async () => {
    const { instance, faux } = await factory();
    faux.setResponses([fauxAssistantMessage("Hello from the general assistant")]);
    const cwd = await mkdtemp(join(tmpdir(), "pi-interactive-"));
    const session = await instance.createSession({ profile: "interactive", cwd });
    sessions.push(session);

    expect(session.activeTools).toEqual(["read", "bash", "edit", "write"]);
    const events: string[] = [];
    const unsubscribe = session.subscribe((event) => events.push(event.type));
    await session.prompt("Say hello");
    unsubscribe();

    expect(events).toContain("agent_start");
    expect(events).toContain("message_end");
    expect(events).toContain("agent_settled");
    expect(session.sessionFile).toBeUndefined();
    expect(faux.getPendingResponseCount()).toBe(0);
  });

  it("creates a workflow worker that selects a task model and exposes custom tools without built-ins", async () => {
    const { instance } = await factory();
    const cwd = await mkdtemp(join(tmpdir(), "pi-worker-"));
    const submit = defineTool({
      name: "submit_result",
      label: "Submit result",
      description: "Submit structured workflow output",
      parameters: Type.Object({ result: Type.String() }),
      async execute(_id, params) {
        return { content: [{ type: "text" as const, text: params.result }], details: params, terminate: true };
      },
    });
    const session = await instance.createSession({
      profile: "workflow-worker",
      cwd,
      taskKind: "validate",
      customTools: [submit],
    });
    sessions.push(session);

    expect(session.activeTools).toEqual(["submit_result"]);
    expect(session.sessionFile).toBeUndefined();
    expect(instance.models.resolveFor("validate").id).toBe("worker-model");
  });

  it("runs schema-validated structured workflow submissions through Pi AgentSession", async () => {
    const { instance, faux } = await factory();
    faux.setResponses([fauxAssistantMessage(fauxToolCall("submit_result", { result: "accepted" }), { stopReason: "toolUse" })]);
    const cwd = await mkdtemp(join(tmpdir(), "pi-structured-"));
    const trace: { type: string; payload?: unknown }[] = [];
    const result = await instance.runStructured<{ result: string }>({
      cwd,
      systemPrompt: "Return a structured result",
      task: { value: 42 },
      tools: [],
      outputSchema: Type.Object({ result: Type.String() }),
      taskKind: "validate",
      trace: (event) => { trace.push(event); },
    });

    expect(result).toEqual({ result: "accepted" });
    expect(trace.map((event) => event.type)).toEqual(expect.arrayContaining([
      "agent_started", "tool_call_started", "submission_started", "submission_accepted", "tool_call_completed", "agent_completed",
    ]));
    expect(faux.getPendingResponseCount()).toBe(0);
  });
});
