import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  createAgentSession,
  defineTool,
} from "@earendil-works/pi-coding-agent";
import {
  InMemoryCredentialStore,
  Type,
  fauxAssistantMessage,
  fauxProvider,
  fauxToolCall,
} from "@earendil-works/pi-ai";
import { describe, expect, it } from "vitest";

async function isolatedLoader(cwd: string, additionalSkillPaths: string[] = []) {
  const settingsManager = SettingsManager.inMemory({ compaction: { enabled: false } });
  const loader = new DefaultResourceLoader({
    cwd,
    agentDir: join(cwd, ".pi-test"),
    settingsManager,
    additionalSkillPaths,
    noExtensions: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPrompt: "Compatibility probe",
    skillsOverride: (base) => ({
      skills: base.skills.filter((skill) =>
        additionalSkillPaths.some((allowedPath) => skill.filePath.startsWith(allowedPath)),
      ),
      diagnostics: [],
    }),
  });
  await loader.reload();
  return { loader, settingsManager };
}

describe("pi-coding-agent compatibility boundary", () => {
  it("supports a fully in-memory model/auth runtime", async () => {
    const credentials = new InMemoryCredentialStore();
    const faux = fauxProvider({ provider: "compat-provider" });
    const runtime = await ModelRuntime.create({
      credentials,
      modelsPath: null,
      allowModelNetwork: false,
    });
    runtime.registerNativeProvider(faux.provider);

    await runtime.setRuntimeApiKey("compat-provider", "probe-secret");

    expect(runtime.hasConfiguredAuth("compat-provider")).toBe(true);
    expect(JSON.stringify(runtime.getProviders())).not.toContain("probe-secret");
    expect(await credentials.read("compat-provider")).toBeUndefined();
  });

  it("discovers only explicitly supplied skills when defaults are isolated", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-coding-skill-"));
    const skillDir = join(cwd, "explicit-skill");
    await mkdir(skillDir);
    await writeFile(
      join(skillDir, "SKILL.md"),
      "---\nname: explicit-audit\ndescription: Explicit compatibility skill\n---\n\n# Instructions\n\nRun only when selected.\n",
    );

    const { loader } = await isolatedLoader(cwd, [skillDir]);
    const loaded = loader.getSkills();

    expect(loaded.diagnostics).toEqual([]);
    expect(loaded.skills.map((skill) => skill.name)).toEqual(["explicit-audit"]);
    expect(loader.getAgentsFiles().agentsFiles).toEqual([]);
    expect(loader.getExtensions().extensions).toEqual([]);
  });

  it("runs an isolated session with only an allowlisted terminating tool", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-coding-session-"));
    const { loader, settingsManager } = await isolatedLoader(cwd);
    const faux = fauxProvider({
      provider: "compat-faux",
      models: [{ id: "compat-model", contextWindow: 8_192, maxTokens: 1_024 }],
    });
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("submit_result", { result: "compatibility-ok" }), {
        stopReason: "toolUse",
      }),
    ]);

    const modelRuntime = await ModelRuntime.create({
      credentials: new InMemoryCredentialStore(),
      modelsPath: null,
      allowModelNetwork: false,
    });
    modelRuntime.registerNativeProvider(faux.provider);
    await modelRuntime.setRuntimeApiKey("compat-faux", "runtime-only-key");

    const submitResult = defineTool({
      name: "submit_result",
      label: "Submit result",
      description: "Return the final structured result",
      parameters: Type.Object({ result: Type.String() }),
      async execute(_toolCallId, params) {
        return {
          content: [{ type: "text" as const, text: params.result }],
          details: { result: params.result },
          terminate: true,
        };
      },
    });

    const { session } = await createAgentSession({
      cwd,
      model: faux.getModel(),
      modelRuntime,
      resourceLoader: loader,
      sessionManager: SessionManager.inMemory(cwd),
      settingsManager,
      tools: ["submit_result"],
      customTools: [submitResult],
    });

    expect(session.getActiveToolNames()).toEqual(["submit_result"]);
    expect(session.getAllTools().map((tool) => tool.name)).toEqual(["submit_result"]);
    expect(session.sessionFile).toBeUndefined();
    expect(settingsManager.getCompactionEnabled()).toBe(false);

    const eventTypes: string[] = [];
    const unsubscribe = session.subscribe((event) => eventTypes.push(event.type));
    await session.prompt("reply once");

    expect(eventTypes).toContain("agent_start");
    expect(eventTypes).toContain("message_end");
    expect(eventTypes).toContain("tool_execution_end");
    expect(eventTypes).toContain("agent_settled");
    expect(session.messages.at(-1)?.role).toBe("toolResult");
    expect(faux.getPendingResponseCount()).toBe(0);

    unsubscribe();
    await session.abort();
    session.dispose();
  });
});
