import { randomUUID } from "node:crypto";
import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { sanitizeAgentTraceValue, type AgentTraceEventType } from "./agent-trace.js";
import { PiSessionFactory, type PlatformAgentSession } from "./pi-session.js";

export type SubagentRunStatus = "queued" | "running" | "succeeded" | "failed" | "aborted";
export type SubagentTraceEventType = AgentTraceEventType | "run_queued" | "run_started" | "run_aborted";

export interface SubagentTraceEvent {
  readonly sequence: number;
  readonly type: SubagentTraceEventType;
  readonly timestamp: string;
  readonly payload?: unknown;
}

export interface SubagentRunView {
  readonly id: string;
  readonly parentSessionId: string;
  readonly task: string;
  readonly status: SubagentRunStatus;
  readonly model: string;
  readonly tools: readonly string[];
  readonly result?: string;
  readonly error?: string;
  readonly createdAt: string;
  readonly startedAt?: string;
  readonly finishedAt?: string;
  /** Full provider-visible execution trace. Present on get(), omitted from list(). */
  readonly trace?: readonly SubagentTraceEvent[];
}

export interface SubagentRuntimeOptions {
  readonly sessions: PiSessionFactory;
  readonly cwd: string;
  readonly model?: string;
  readonly tools?: readonly string[];
  readonly skillPaths?: readonly string[];
  readonly customTools?: () => readonly ToolDefinition[];
  readonly maxConcurrent?: number;
  readonly maxRetained?: number;
  readonly maxTraceEvents?: number;
  readonly systemPrompt?: string;
  readonly restoredRuns?: readonly SubagentRunView[];
  readonly persistRun?: (run: SubagentRunView) => void;
}

interface MutableSubagentRun {
  id: string;
  parentSessionId: string;
  task: string;
  status: SubagentRunStatus;
  model: string;
  tools: readonly string[];
  result?: string | undefined;
  error?: string | undefined;
  createdAt: string;
  startedAt?: string | undefined;
  finishedAt?: string | undefined;
  session?: PlatformAgentSession | undefined;
  releaseQueue?: (() => void) | undefined;
  trace: SubagentTraceEvent[];
  nextTraceSequence: number;
}

const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

function finalText(messages: readonly unknown[]): string {
  for (let index = messages.length - 1; index >= 0; index--) {
    const message = messages[index] as { role?: unknown; content?: unknown };
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    const text = message.content
      .map((block) => block && typeof block === "object" && (block as { type?: unknown }).type === "text" ? (block as { text?: unknown }).text : undefined)
      .filter((value): value is string => typeof value === "string")
      .join("\n")
      .trim();
    if (text) return text;
  }
  return "";
}

export class SubagentRuntime {
  readonly #options: SubagentRuntimeOptions;
  readonly #runs = new Map<string, MutableSubagentRun>();
  readonly #listeners = new Set<(run: SubagentRunView) => void>();
  readonly #queue: MutableSubagentRun[] = [];
  readonly #maxConcurrent: number;
  readonly #maxRetained: number;
  readonly #maxTraceEvents: number;
  #active = 0;
  #disposed = false;

  constructor(options: SubagentRuntimeOptions) {
    this.#options = options;
    this.#maxConcurrent = options.maxConcurrent ?? 4;
    this.#maxRetained = options.maxRetained ?? 100;
    this.#maxTraceEvents = options.maxTraceEvents ?? 500;
    if (!Number.isInteger(this.#maxConcurrent) || this.#maxConcurrent < 1) throw new Error("subagent_max_concurrent_invalid");
    if (!Number.isInteger(this.#maxRetained) || this.#maxRetained < 1) throw new Error("subagent_max_retained_invalid");
    if (!Number.isInteger(this.#maxTraceEvents) || this.#maxTraceEvents < 1) throw new Error("subagent_max_trace_events_invalid");
    for (const restored of options.restoredRuns ?? []) {
      const trace = [...(restored.trace ?? [])].map((event) => ({ ...event }));
      const interrupted = restored.status === "queued" || restored.status === "running";
      const stamp = new Date().toISOString();
      const run: MutableSubagentRun = {
        id: restored.id, parentSessionId: restored.parentSessionId, task: restored.task,
        status: interrupted ? "aborted" : restored.status, model: restored.model, tools: Object.freeze([...restored.tools]),
        ...(restored.result ? { result: restored.result } : {}),
        ...(interrupted ? { error: "gateway_restarted" } : restored.error ? { error: restored.error } : {}),
        createdAt: restored.createdAt, ...(restored.startedAt ? { startedAt: restored.startedAt } : {}),
        ...(interrupted ? { finishedAt: stamp } : restored.finishedAt ? { finishedAt: restored.finishedAt } : {}),
        trace, nextTraceSequence: Math.max(0, ...trace.map((event) => event.sequence)) + 1,
      };
      if (interrupted) this.#appendTrace(run, "run_aborted", { error: "gateway_restarted" });
      this.#runs.set(run.id, run);
      this.#persist(run);
    }
    this.#trim();
  }

  list(parentSessionId?: string): readonly SubagentRunView[] {
    this.#assertActive();
    return Object.freeze([...this.#runs.values()]
      .filter((run) => !parentSessionId || run.parentSessionId === parentSessionId)
      .map((run) => this.#view(run))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  }

  get(id: string): SubagentRunView {
    this.#assertActive();
    return this.#view(this.#required(id), true);
  }

  subscribe(listener: (run: SubagentRunView) => void): () => void {
    this.#assertActive();
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  delegationTool(parentSessionId: () => string): ToolDefinition {
    const runtime = this;
    return defineTool({
      name: "delegate_task",
      label: "Delegate task",
      description: "Delegate one independent task to an isolated subagent and wait for its final result. Use this for bounded work that benefits from a separate context.",
      parameters: Type.Object({
        task: Type.String({ description: "A complete, self-contained task for the subagent." }),
        model: Type.Optional(Type.String({ description: "Optional configured model alias. Omit to use the subagent default." })),
      }),
      async execute(_id, params, signal) {
        const request = params as { task: string; model?: string };
        const run = await runtime.run(parentSessionId(), request.task, request.model, signal);
        if (run.status !== "succeeded") throw new Error(run.error ?? `subagent_${run.status}:${run.id}`);
        return {
          content: [{ type: "text" as const, text: run.result ?? "" }],
          details: run,
        };
      },
    });
  }

  async run(parentSessionId: string, task: string, model?: string, signal?: AbortSignal): Promise<SubagentRunView> {
    this.#assertActive();
    const delegatedTask = task.trim();
    if (!delegatedTask) throw new Error("subagent_task_required");
    const selectedModel = model ?? this.#options.model ?? this.#options.sessions.models.defaultAlias;
    this.#options.sessions.models.resolve(selectedModel);
    const stamp = new Date().toISOString();
    const run: MutableSubagentRun = {
      id: `SUBAGENT-${randomUUID()}`,
      parentSessionId: parentSessionId || "unbound",
      task: delegatedTask,
      status: "queued",
      model: selectedModel,
      tools: Object.freeze([...(this.#options.tools ?? ["read", "bash"])]),
      createdAt: stamp,
      trace: [],
      nextTraceSequence: 1,
    };
    this.#appendTrace(run, "run_queued", { parentSessionId: run.parentSessionId, model: run.model, tools: run.tools });
    this.#runs.set(run.id, run);
    this.#trim();
    this.#emit(run);
    const abort = () => { void this.abort(run.id); };
    signal?.addEventListener("abort", abort, { once: true });
    let acquired = false;
    let unsubscribe: (() => void) | undefined;
    try {
      acquired = await this.#acquire(run);
      if (!acquired) return this.#view(run);
      run.status = "running";
      run.startedAt = new Date().toISOString();
      this.#appendTrace(run, "run_started", { model: run.model, tools: run.tools });
      this.#emit(run);
      const customTools = [...(this.#options.customTools?.() ?? [])];
      const toolNames = [...run.tools, ...customTools.map((tool) => tool.name)];
      const skillPaths = this.#options.skillPaths ?? (await this.#options.sessions.resources(this.#options.cwd)).resources
        .filter((resource) => resource.kind === "skill" && resource.enabled && resource.loaded)
        .map((resource) => resource.id);
      run.session = await this.#options.sessions.createSession({
        profile: "workflow-worker",
        cwd: this.#options.cwd,
        model: selectedModel,
        systemPrompt: this.#options.systemPrompt ?? "You are an isolated subagent. Complete only the delegated task, use tools when useful, and return a concise final answer to the parent assistant.",
        tools: toolNames,
        ...(customTools.length ? { customTools } : {}),
        ...(skillPaths.length ? { skillPaths } : {}),
      });
      unsubscribe = run.session.subscribe((event) => {
        if (event.type === "agent_start") this.#appendTrace(run, "agent_started", { model: run.session?.modelReference, tools: run.session?.activeTools });
        if (event.type === "tool_execution_start") this.#appendTrace(run, "tool_call_started", { callId: event.toolCallId, tool: event.toolName, arguments: event.args });
        if (event.type === "tool_execution_end") this.#appendTrace(run, "tool_call_completed", {
          callId: event.toolCallId, tool: event.toolName, isError: event.isError, result: event.result,
        });
        if (event.type === "message_end") {
          const message = event.message as unknown as Record<string, unknown>;
          if (message.role !== "assistant") return;
          const content = Array.isArray(message.content)
            ? message.content.filter((block) => block && typeof block === "object" && ["text", "thinking"].includes(String((block as Record<string, unknown>).type)))
            : message.content;
          if ((Array.isArray(content) && content.length) || (!Array.isArray(content) && content)) {
            this.#appendTrace(run, "assistant_message", { content, stopReason: message.stopReason, errorMessage: message.errorMessage });
          } else if (message.errorMessage) {
            this.#appendTrace(run, "assistant_message", { errorMessage: message.errorMessage, stopReason: message.stopReason });
          }
        }
      });
      if (signal?.aborted || (run.status as SubagentRunStatus) === "aborted") await run.session.abort();
      else await run.session.prompt(delegatedTask);
      unsubscribe();
      unsubscribe = undefined;
      if ((run.status as SubagentRunStatus) !== "aborted") {
        run.result = finalText(run.session.messages);
        if (!run.result) throw new Error("subagent_result_missing");
        run.status = "succeeded";
        this.#appendTrace(run, "agent_completed", { result: run.result });
      }
    } catch (error) {
      if (run.status !== "aborted") {
        run.status = "failed";
        run.error = errorMessage(error);
        this.#appendTrace(run, "agent_failed", { error: run.error });
      }
    } finally {
      signal?.removeEventListener("abort", abort);
      unsubscribe?.();
      if (run.session) {
        await run.session.dispose().catch(() => undefined);
        run.session = undefined;
      }
      if (!run.finishedAt) run.finishedAt = new Date().toISOString();
      if (acquired) this.#release();
      this.#emit(run);
    }
    return this.#view(run);
  }

  async abort(id: string): Promise<SubagentRunView> {
    this.#assertActive();
    const run = this.#required(id);
    if (["succeeded", "failed", "aborted"].includes(run.status)) return this.#view(run);
    run.status = "aborted";
    run.error = "subagent_aborted";
    run.finishedAt = new Date().toISOString();
    this.#appendTrace(run, "run_aborted", { error: run.error });
    if (run.releaseQueue) {
      const index = this.#queue.indexOf(run);
      if (index >= 0) this.#queue.splice(index, 1);
      const release = run.releaseQueue;
      run.releaseQueue = undefined;
      release();
    }
    await run.session?.abort();
    this.#emit(run);
    return this.#view(run);
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    for (const run of [...this.#runs.values()]) {
      if (run.status === "queued" || run.status === "running") await this.abort(run.id);
    }
    this.#disposed = true;
    this.#listeners.clear();
  }

  async #acquire(run: MutableSubagentRun): Promise<boolean> {
    if (this.#active < this.#maxConcurrent) {
      this.#active += 1;
      return true;
    }
    await new Promise<void>((resolve) => {
      run.releaseQueue = resolve;
      this.#queue.push(run);
    });
    run.releaseQueue = undefined;
    return run.status !== "aborted";
  }

  #release(): void {
    this.#active = Math.max(0, this.#active - 1);
    const next = this.#queue.shift();
    if (next) {
      this.#active += 1;
      next.releaseQueue?.();
    }
  }

  #trim(): void {
    if (this.#runs.size <= this.#maxRetained) return;
    const terminal = [...this.#runs.values()]
      .filter((run) => ["succeeded", "failed", "aborted"].includes(run.status))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    while (this.#runs.size > this.#maxRetained && terminal.length) this.#runs.delete(terminal.shift()!.id);
  }

  #required(id: string): MutableSubagentRun {
    const run = this.#runs.get(id);
    if (!run) throw new Error(`subagent_not_found:${id}`);
    return run;
  }

  #view(run: MutableSubagentRun, includeTrace = false): SubagentRunView {
    return Object.freeze({
      id: run.id, parentSessionId: run.parentSessionId, task: run.task, status: run.status,
      model: run.model, tools: Object.freeze([...run.tools]),
      ...(run.result ? { result: run.result } : {}), ...(run.error ? { error: run.error } : {}),
      createdAt: run.createdAt, ...(run.startedAt ? { startedAt: run.startedAt } : {}), ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
      ...(includeTrace ? { trace: Object.freeze(run.trace.map((event) => Object.freeze({
        ...event,
        ...(event.payload === undefined ? {} : { payload: structuredClone(event.payload) }),
      }))) } : {}),
    });
  }

  #appendTrace(run: MutableSubagentRun, type: SubagentTraceEventType, payload?: unknown): void {
    run.trace.push(Object.freeze({
      sequence: run.nextTraceSequence++,
      type,
      timestamp: new Date().toISOString(),
      ...(payload === undefined ? {} : { payload: sanitizeAgentTraceValue(payload) }),
    }));
    if (run.trace.length > this.#maxTraceEvents) run.trace.splice(0, run.trace.length - this.#maxTraceEvents);
    this.#persist(run);
  }

  #emit(run: MutableSubagentRun): void {
    const view = this.#view(run);
    this.#options.persistRun?.(this.#view(run, true));
    for (const listener of this.#listeners) listener(view);
  }

  #persist(run: MutableSubagentRun): void { this.#options.persistRun?.(this.#view(run, true)); }

  #assertActive(): void {
    if (this.#disposed) throw new Error("subagent_runtime_disposed");
  }
}
