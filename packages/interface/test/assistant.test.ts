import { access, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiSessionFactory } from "@agent-platform/core";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { AssistantSessionService } from "../src/index.js";

const services: AssistantSessionService[] = [];
afterEach(async () => {
  await Promise.all(services.splice(0).map((service) => service.dispose()));
  delete process.env.TEST_ASSISTANT_KEY;
});

describe("domain-neutral AssistantSessionService", () => {
  it("lets the parent assistant delegate work to an isolated subagent", async () => {
    process.env.TEST_ASSISTANT_KEY = "runtime-only";
    const sessions = await PiSessionFactory.create({ models: {
      default: "general",
      providers: { test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_ASSISTANT_KEY" } },
      catalog: { general: { provider: "test", id: "general-model" } },
    } });
    const faux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    sessions.models.runtime.registerNativeProvider(faux.provider);
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("delegate_task", { task: "inspect independently" }), { stopReason: "toolUse" }),
      fauxAssistantMessage("child finding"),
      fauxAssistantMessage("parent used child finding"),
    ]);
    const service = await AssistantSessionService.create({ sessions, cwd: await mkdtemp(join(tmpdir(), "assistant-delegate-")) });
    services.push(service);
    const created = await service.createSession();
    const settled = new Promise<void>((resolve) => {
      const unsubscribe = service.subscribe((event) => {
        if (event.session.id === created.id && event.cause === "prompt_settled") { unsubscribe(); resolve(); }
      });
    });
    service.prompt(created.id, "delegate this task");
    await settled;

    expect(service.listSubagents(created.id)).toEqual([
      expect.objectContaining({ parentSessionId: created.id, task: "inspect independently", status: "succeeded", result: "child finding" }),
    ]);
    expect(service.get(created.id).messages.at(-1)).toMatchObject({ role: "assistant", content: [{ text: "parent used child finding" }] });
  });

  it("creates, streams and deletes an interactive Pi session without plugins", async () => {
    process.env.TEST_ASSISTANT_KEY = "runtime-only";
    const sessions = await PiSessionFactory.create({ models: {
      default: "general",
      providers: { test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_ASSISTANT_KEY" } },
      catalog: { general: { provider: "test", id: "general-model" } },
    } });
    const faux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    sessions.models.runtime.registerNativeProvider(faux.provider);
    faux.setResponses([fauxAssistantMessage("通用助手响应")]);
    const service = await AssistantSessionService.create({ sessions, cwd: await mkdtemp(join(tmpdir(), "assistant-service-")) });
    services.push(service);

    expect(service.capabilities()).toMatchObject({ models: ["general"], defaultModel: "general", mcpTools: [], subagents: true });
    const created = await service.createSession();
    expect(created.activeTools).toEqual(["read", "bash", "edit", "write", "delegate_task"]);

    const settled = new Promise<void>((resolve) => {
      const unsubscribe = service.subscribe((event) => {
        if (event.session.id === created.id && event.cause === "prompt_settled") { unsubscribe(); resolve(); }
      });
    });
    expect(service.prompt(created.id, "你好")).toMatchObject({ status: "running", title: "你好" });
    await settled;
    expect(service.get(created.id)).toMatchObject({
      status: "idle",
      messages: [
        { role: "user", content: [{ type: "text", text: "你好" }] },
        { role: "assistant", content: [{ type: "text", text: "通用助手响应" }] },
      ],
    });
    await service.delete(created.id);
    expect(service.list()).toEqual([]);
  });

  it("restores Pi JSONL sessions after the assistant service restarts", async () => {
    process.env.TEST_ASSISTANT_KEY = "runtime-only";
    const root = await mkdtemp(join(tmpdir(), "assistant-recovery-"));
    const agentDir = join(root, "pi-agent");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(agentDir);
    await writeFile(join(agentDir, "settings.json"), JSON.stringify({
      defaultProvider: "test", defaultModel: "general-model", sessionDir: join(root, "sessions"),
    }));
    await writeFile(join(agentDir, "models.json"), JSON.stringify({ providers: { test: {
      baseUrl: "http://unused.invalid/v1", api: "faux", apiKey: "$TEST_ASSISTANT_KEY", models: [{ id: "general-model" }],
    } } }));
    await writeFile(join(agentDir, "auth.json"), JSON.stringify({ test: { type: "api_key", key: "runtime-only" } }));

    const firstFactory = await PiSessionFactory.create({ agentDir, cwd: root });
    const firstFaux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    firstFactory.models.runtime.registerNativeProvider(firstFaux.provider);
    await firstFactory.models.runtime.setRuntimeApiKey("test", "runtime-only");
    firstFaux.setResponses([fauxAssistantMessage("持久化回答")]);
    const first = await AssistantSessionService.create({ sessions: firstFactory, cwd: root });
    const created = await first.createSession();
    const settled = new Promise<void>((resolve) => {
      const unsubscribe = first.subscribe((event) => {
        if (event.session.id === created.id && event.cause === "prompt_settled") { unsubscribe(); resolve(); }
      });
    });
    first.prompt(created.id, "需要恢复的对话");
    await settled;
    first.rename(created.id, "恢复测试");
    await first.dispose();

    const secondFactory = await PiSessionFactory.create({ agentDir, cwd: root });
    const secondFaux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    secondFactory.models.runtime.registerNativeProvider(secondFaux.provider);
    await secondFactory.models.runtime.setRuntimeApiKey("test", "runtime-only");
    const second = await AssistantSessionService.create({ sessions: secondFactory, cwd: root });
    services.push(second);
    expect(second.list()).toHaveLength(1);
    expect(second.list()[0]).toMatchObject({
      id: created.id,
      title: "恢复测试",
      model: "test/general-model",
      messages: [{ role: "user" }, { role: "assistant", content: [{ text: "持久化回答" }] }],
    });
    secondFaux.setResponses([fauxAssistantMessage("恢复后继续回答")]);
    const continued = new Promise<void>((resolve) => {
      const unsubscribe = second.subscribe((event) => {
        if (event.session.id === created.id && event.cause === "prompt_settled") { unsubscribe(); resolve(); }
      });
    });
    second.prompt(created.id, "继续");
    await continued;
    expect(second.get(created.id).messages).toHaveLength(4);
    const [{ path }] = await secondFactory.listSessions(root);
    await second.delete(created.id);
    await expect(access(path!)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
