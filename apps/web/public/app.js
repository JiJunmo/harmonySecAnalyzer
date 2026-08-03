const state = {
  token: localStorage.getItem("agent-platform-token") || "",
  capabilities: null,
  sessions: [],
  selectedSession: null,
  contributions: [],
  selectedContribution: null,
  source: null,
  mode: "catalog",
  managedCapabilities: [],
  subagents: [],
  selectedSubagentId: null,
  selectedSubagent: null,
  subagentTimer: null,
};
const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const headers = { ...(options.body ? { "content-type": "application/json" } : {}), ...(state.token ? { authorization: `Bearer ${state.token}` } : {}), ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const value = await response.json().catch(() => ({}));
    throw new Error(value.error || `HTTP ${response.status}`);
  }
  if (response.status === 204) return undefined;
  return response.json();
}

function toast(text) {
  const node = $("#toast");
  node.textContent = text;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 2800);
}

function hideViews() {
  for (const selector of ["#catalog-view", "#assistant-view", "#plugin-view", "#capabilities-view", "#subagents-view"]) $(selector).classList.add("hidden");
  for (const selector of ["#catalog-nav", "#assistant-nav", "#capabilities-nav", "#subagents-nav"]) $(selector).classList.remove("active");
  document.querySelectorAll("#contributions button").forEach((button) => button.classList.remove("active"));
  $("#session-section").classList.add("hidden");
}

function showCatalog() {
  state.mode = "catalog";
  state.source?.close();
  hideViews();
  $("#catalog-view").classList.remove("hidden");
  $("#catalog-nav").classList.add("active");
}

function showAssistant() {
  state.mode = "assistant";
  hideViews();
  $("#assistant-view").classList.remove("hidden");
  $("#assistant-nav").classList.add("active");
  $("#session-section").classList.remove("hidden");
  if (state.selectedSession) connectSession(state.selectedSession.id);
}

function showPlugin(contribution) {
  state.mode = "plugin";
  state.selectedContribution = contribution;
  state.source?.close();
  hideViews();
  $("#plugin-view").classList.remove("hidden");
  document.querySelectorAll("#contributions button").forEach((button) => button.classList.toggle("active", button.dataset.key === `${contribution.pluginId}/${contribution.id}`));
  $("#workspace").src = `/plugins/${encodeURIComponent(contribution.pluginId)}/${encodeURIComponent(contribution.id)}/${contribution.entry.split("/").map(encodeURIComponent).join("/")}`;
}

function renderCapabilities() {
  const root = $("#capability-groups"); root.replaceChildren();
  const labels = { mcp: "MCP Servers", skill: "Skills", extension: "Extensions", package: "Pi Packages" };
  for (const kind of ["mcp", "skill", "extension", "package"]) {
    const values = state.managedCapabilities.filter((item) => item.kind === kind);
    const section = document.createElement("section"); section.className = "capability-group";
    const heading = document.createElement("h2"); heading.textContent = labels[kind]; section.append(heading);
    if (!values.length) { const empty = document.createElement("p"); empty.className = "empty-capability"; empty.textContent = "未配置"; section.append(empty); root.append(section); continue; }
    for (const item of values) {
      const row = document.createElement("div"); row.className = "capability-row";
      const stateDot = document.createElement("i"); stateDot.className = item.loaded ? "loaded" : item.error ? "failed" : "";
      const description = document.createElement("div");
      const title = document.createElement("strong"); title.textContent = item.name;
      const meta = document.createElement("small"); meta.textContent = item.error || `${item.source}${item.details?.length ? ` · ${item.details.join(", ")}` : ""}`;
      description.append(title, meta);
      const label = document.createElement("label"); label.className = "switch";
      const input = document.createElement("input"); input.type = "checkbox"; input.checked = item.enabled;
      input.setAttribute("aria-label", `${item.enabled ? "停用" : "启用"} ${item.name}`);
      const slider = document.createElement("span"); label.append(input, slider);
      input.addEventListener("change", async () => {
        input.disabled = true;
        try {
          const result = await api("/api/assistant/capabilities", { method: "POST", body: JSON.stringify({ kind: item.kind, id: item.id, enabled: input.checked }) });
          state.managedCapabilities = result.capabilities || []; renderCapabilities(); toast("能力配置已更新，新会话生效");
        } catch (error) { input.checked = !input.checked; input.disabled = false; toast(error.message); }
      });
      row.append(stateDot, description, label); section.append(row);
    }
    root.append(section);
  }
}

async function showCapabilities() {
  state.mode = "capabilities"; state.source?.close();
  hideViews(); $("#capabilities-view").classList.remove("hidden"); $("#capabilities-nav").classList.add("active");
  try { const result = await api("/api/assistant/capabilities"); state.managedCapabilities = result.capabilities || []; renderCapabilities(); } catch (error) { toast(error.message); }
}

const subagentStatus = { queued: "排队中", running: "运行中", succeeded: "已完成", failed: "失败", aborted: "已取消" };
const subagentTraceLabels = {
  run_queued: "进入队列", run_started: "开始执行", agent_started: "Agent 启动",
  assistant_message: "模型消息", tool_call_started: "调用工具", tool_call_completed: "工具返回",
  submission_started: "提交结果", submission_accepted: "结果已接受", submission_rejected: "结果被拒绝",
  agent_completed: "执行完成", agent_failed: "执行失败", run_aborted: "任务已取消",
};

function subagentTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

function traceText(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function renderSubagentDetail() {
  const root = $("#subagent-detail"); root.replaceChildren();
  const run = state.selectedSubagent;
  if (!run) { const empty = document.createElement("p"); empty.className = "subagent-empty"; empty.textContent = "选择一个任务查看完整过程。"; root.append(empty); return; }
  const header = document.createElement("header");
  const heading = document.createElement("div");
  const eyebrow = document.createElement("small"); eyebrow.textContent = `${subagentStatus[run.status] || run.status} · ${run.model}`;
  const title = document.createElement("h2"); title.textContent = run.task;
  const meta = document.createElement("p"); meta.textContent = `创建 ${subagentTime(run.createdAt)} · 开始 ${subagentTime(run.startedAt)} · 完成 ${subagentTime(run.finishedAt)}`;
  heading.append(eyebrow, title, meta); header.append(heading); root.append(header);

  const timeline = document.createElement("div"); timeline.className = "subagent-timeline";
  for (const event of run.trace || []) {
    const item = document.createElement("article"); item.className = `trace-event trace-${event.type}`;
    const marker = document.createElement("i");
    const content = document.createElement("div");
    const eventHeader = document.createElement("header");
    const label = document.createElement("strong"); label.textContent = subagentTraceLabels[event.type] || event.type;
    const time = document.createElement("time"); time.textContent = subagentTime(event.timestamp); eventHeader.append(label, time); content.append(eventHeader);
    const payload = event.payload || {};
    if (event.type === "assistant_message" && Array.isArray(payload.content)) {
      for (const block of payload.content) {
        if (!block || typeof block !== "object") continue;
        const blockNode = document.createElement("div"); blockNode.className = `trace-message trace-message-${block.type || "text"}`;
        if (block.type === "thinking") { const caption = document.createElement("small"); caption.textContent = "模型可见思考内容"; blockNode.append(caption); }
        const text = document.createElement("pre"); text.textContent = traceText(block.text ?? block.thinking ?? block); blockNode.append(text); content.append(blockNode);
      }
    } else if (["tool_call_started", "tool_call_completed"].includes(event.type)) {
      const tool = document.createElement("p"); tool.className = "trace-tool"; tool.textContent = `${payload.tool || "tool"}${payload.isError ? " · ERROR" : ""}`; content.append(tool);
      const detail = event.type === "tool_call_started" ? payload.arguments : payload.result;
      if (detail !== undefined) { const pre = document.createElement("pre"); pre.textContent = traceText(detail); content.append(pre); }
    } else if (event.type === "agent_completed" && payload.result) {
      const pre = document.createElement("pre"); pre.textContent = traceText(payload.result); content.append(pre);
    } else if (Object.keys(payload).length) {
      const pre = document.createElement("pre"); pre.textContent = traceText(payload); content.append(pre);
    }
    item.append(marker, content); timeline.append(item);
  }
  if (!(run.trace || []).length) { const empty = document.createElement("p"); empty.className = "subagent-empty"; empty.textContent = "任务尚未产生过程事件。"; timeline.append(empty); }
  root.append(timeline);
}

async function selectSubagent(id) {
  state.selectedSubagentId = id;
  renderSubagents();
  try {
    state.selectedSubagent = await api(`/api/assistant/subagents/${encodeURIComponent(id)}`);
    renderSubagentDetail();
  } catch (error) { toast(error.message); }
}

function renderSubagents() {
  const summary = $("#subagent-summary"); summary.replaceChildren();
  for (const status of ["running", "queued", "succeeded", "failed", "aborted"]) {
    const count = state.subagents.filter((run) => run.status === status).length;
    if (!count && ["failed", "aborted"].includes(status)) continue;
    const badge = document.createElement("span"); badge.className = "subagent-count"; badge.textContent = `${subagentStatus[status]} ${count}`; summary.append(badge);
  }
  const root = $("#subagent-list"); root.className = "subagent-list"; root.replaceChildren();
  if (!state.subagents.length) {
    const empty = document.createElement("p"); empty.className = "subagent-empty"; empty.textContent = "尚无委派任务。主助手调用 delegate_task 后会在这里显示。"; root.append(empty); return;
  }
  for (const run of state.subagents) {
    const card = document.createElement("article"); card.className = `subagent-card${run.id === state.selectedSubagentId ? " selected" : ""}`; card.tabIndex = 0;
    const dot = document.createElement("i"); dot.className = run.status;
    const content = document.createElement("div");
    const title = document.createElement("strong"); title.textContent = run.task;
    const meta = document.createElement("small"); meta.textContent = `${subagentStatus[run.status] || run.status} · ${run.model} · ${run.tools.join(", ")} · ${run.id}`;
    content.append(title, meta);
    if (run.result || run.error) { const result = document.createElement("p"); result.className = "subagent-result"; result.textContent = run.result || run.error; content.append(result); }
    const open = () => { void selectSubagent(run.id); };
    card.addEventListener("click", open);
    card.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); } });
    card.append(dot, content);
    if (["queued", "running"].includes(run.status)) {
      const stop = document.createElement("button"); stop.type = "button"; stop.textContent = "取消"; stop.setAttribute("aria-label", `取消 ${run.task}`);
      stop.addEventListener("click", async (event) => { event.stopPropagation(); try { await api(`/api/assistant/subagents/${encodeURIComponent(run.id)}/actions/abort`, { method: "POST", body: "{}" }); await loadSubagents(); } catch (error) { toast(error.message); } });
      card.append(stop);
    }
    root.append(card);
  }
}

async function loadSubagents() {
  const result = await api("/api/assistant/subagents"); state.subagents = result.subagents || [];
  if (state.selectedSubagentId && !state.subagents.some((run) => run.id === state.selectedSubagentId)) { state.selectedSubagentId = null; state.selectedSubagent = null; }
  if (!state.selectedSubagentId && state.subagents.length) state.selectedSubagentId = state.subagents[0].id;
  renderSubagents();
  if (state.selectedSubagentId) {
    state.selectedSubagent = await api(`/api/assistant/subagents/${encodeURIComponent(state.selectedSubagentId)}`);
  }
  renderSubagentDetail();
}

async function showSubagents() {
  state.mode = "subagents"; state.source?.close();
  hideViews(); $("#subagents-view").classList.remove("hidden"); $("#subagents-nav").classList.add("active");
  clearTimeout(state.subagentTimer);
  try { await loadSubagents(); } catch (error) { toast(error.message); }
  const poll = async () => { if (state.mode !== "subagents") return; try { await loadSubagents(); } catch {} state.subagentTimer = setTimeout(poll, 1500); };
  state.subagentTimer = setTimeout(poll, 1500);
}

function renderModels() {
  const select = $("#model-select");
  select.replaceChildren();
  for (const model of state.capabilities?.models || []) {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = model;
    option.selected = model === (state.selectedSession?.model || state.capabilities.defaultModel);
    select.append(option);
  }
  select.disabled = !!state.selectedSession;
  const mcp = state.capabilities?.mcpTools || [];
  const delegated = state.capabilities?.subagents ? " · 子 Agent 委派" : "";
  $("#tool-summary").textContent = mcp.length ? `Pi 内置工具 · ${mcp.length} 个 MCP 工具${delegated}` : `Pi 内置工具已启用${delegated}`;
}

function renderSessions() {
  const nav = $("#sessions");
  nav.replaceChildren();
  if (!state.sessions.length) {
    const empty = document.createElement("p"); empty.className = "muted"; empty.textContent = "暂无对话"; nav.append(empty); return;
  }
  for (const session of state.sessions) {
    const button = document.createElement("button");
    button.type = "button";
    button.classList.toggle("active", session.id === state.selectedSession?.id && state.mode === "assistant");
    const title = document.createElement("span"); title.textContent = session.title;
    const meta = document.createElement("small"); meta.textContent = `${session.model} · ${session.status === "running" ? "生成中" : "空闲"}`;
    button.append(title, meta);
    button.addEventListener("click", () => selectSession(session.id));
    nav.append(button);
  }
}

function blockText(block) {
  if (block.type === "text") return block.text || "";
  if (block.type === "thinking") return block.text ? `思考：${block.text}` : "";
  if (block.type === "toolCall") return `调用工具 ${block.name || "unknown"}`;
  return block.text || "";
}

function renderMessages() {
  const container = $("#messages");
  const values = state.selectedSession?.messages || [];
  container.replaceChildren();
  if (!values.length) {
    const empty = document.createElement("div");
    empty.className = "empty-chat";
    empty.innerHTML = "<div>✦</div><h2>今天想一起完成什么？</h2><p>这是通用 AI 助手。它可以使用已启用的模型、MCP 工具和 Skills；安全审计等领域能力由插件提供。</p>";
    container.append(empty); return;
  }
  for (const item of values) {
    const text = (item.content || []).map(blockText).filter(Boolean).join("\n");
    if (!text && item.role !== "toolResult") continue;
    const article = document.createElement("article");
    article.className = `message ${item.role}`;
    const label = document.createElement("small");
    label.textContent = item.role === "user" ? "你" : item.role === "assistant" ? "助手" : item.toolName || "工具";
    const body = document.createElement("div");
    body.textContent = text || (item.isError ? "工具执行失败" : "工具执行完成");
    article.append(label, body); container.append(article);
  }
  if (state.selectedSession?.status === "running") {
    const typing = document.createElement("div"); typing.className = "typing"; typing.innerHTML = "<i></i><i></i><i></i>"; container.append(typing);
  }
  container.scrollTop = container.scrollHeight;
}

function renderSession() {
  const session = state.selectedSession;
  $("#chat-title").textContent = session?.title || "新对话";
  $("#chat-meta").textContent = session ? `${session.model} · ${session.activeTools.length} 个可用工具 · ${session.status === "running" ? "正在生成" : "已就绪"}` : "选择模型并开始交谈";
  $("#delete-chat").disabled = !session;
  $("#rename-chat").disabled = !session;
  $("#abort-chat").classList.toggle("hidden", session?.status !== "running");
  $("#send").disabled = session?.status === "running";
  $("#prompt").disabled = session?.status === "running";
  renderModels(); renderSessions(); renderMessages();
}

function renderPlugins() {
  const nav = $("#contributions"); const cards = $("#plugin-cards"); nav.replaceChildren(); cards.replaceChildren();
  if (!state.contributions.length) {
    const empty = document.createElement("p"); empty.className = "muted"; empty.textContent = "暂无领域插件"; nav.append(empty); cards.append(empty.cloneNode(true)); return;
  }
  for (const contribution of state.contributions) {
    const button = document.createElement("button"); button.type = "button"; button.dataset.key = `${contribution.pluginId}/${contribution.id}`;
    const title = document.createElement("span"); title.textContent = contribution.title;
    const plugin = document.createElement("small"); plugin.textContent = contribution.pluginId;
    button.append(title, plugin); button.addEventListener("click", () => showPlugin(contribution)); nav.append(button);
    const card = document.createElement("button"); card.className = "app-card"; card.type = "button";
    const mark = document.createElement("span"); mark.className = "app-mark"; mark.textContent = "HA";
    const copy = document.createElement("span"); copy.className = "app-copy";
    const kind = document.createElement("small"); kind.textContent = "领域插件";
    const name = document.createElement("strong"); name.textContent = contribution.title;
    const description = document.createElement("span"); description.textContent = "项目解析、路径发现、六维验证与审计报告。";
    const open = document.createElement("em"); open.textContent = "打开应用 →";
    copy.append(kind, name, description, open); card.append(mark, copy); card.addEventListener("click", () => showPlugin(contribution)); cards.append(card);
  }
}

function replaceSession(session) {
  state.selectedSession = session;
  const index = state.sessions.findIndex((item) => item.id === session.id);
  if (index >= 0) state.sessions[index] = session; else state.sessions.unshift(session);
  state.sessions.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  renderSession();
}

function connectSession(id) {
  state.source?.close();
  const token = state.token ? `?token=${encodeURIComponent(state.token)}` : "";
  const source = new EventSource(`/api/assistant/sessions/${encodeURIComponent(id)}/events${token}`);
  source.addEventListener("snapshot", (event) => replaceSession(JSON.parse(event.data)));
  source.addEventListener("session_event", (event) => replaceSession(JSON.parse(event.data).session));
  source.addEventListener("error", () => { if (state.selectedSession?.status === "running") $("#chat-meta").textContent = "事件连接正在恢复…"; });
  state.source = source;
}

async function selectSession(id) {
  try {
    showAssistant();
    replaceSession(await api(`/api/assistant/sessions/${encodeURIComponent(id)}`));
    connectSession(id);
  } catch (error) { toast(error.message); }
}

async function createSession() {
  const model = $("#model-select").value || state.capabilities?.defaultModel;
  const session = await api("/api/assistant/sessions", { method: "POST", body: JSON.stringify({ model }) });
  replaceSession(session); connectSession(session.id); showAssistant(); return session;
}

async function boot() {
  try {
    const [health, contributions] = await Promise.all([api("/api/health"), api("/api/web-contributions")]);
    state.contributions = contributions.contributions || [];
    renderPlugins();
    if (health.assistant) {
      const [capabilities, sessions] = await Promise.all([api("/api/assistant"), api("/api/assistant/sessions")]);
      state.capabilities = capabilities; state.sessions = sessions.sessions || [];
      renderSession();
    } else {
      $("#prompt").disabled = true; $("#send").disabled = true; $("#chat-meta").textContent = "请先在配置文件中设置模型";
    }
    $("#health-dot").classList.add("ok");
    $("#health-text").textContent = `服务正常 · ${health.pluginCount} 插件`;
    $("#catalog-health").textContent = `${health.pluginCount + 1} 个应用可用`;
    $(".catalog-status i").classList.add("ok");
    showCatalog();
  } catch (error) {
    $("#health-text").textContent = error.message === "unauthorized" ? "需要访问 Token" : "服务不可用";
    toast(error.message);
  }
}

$("#catalog-nav").addEventListener("click", showCatalog);
$("#assistant-nav").addEventListener("click", showAssistant);
$("#assistant-card").addEventListener("click", showAssistant);
$("#capabilities-nav").addEventListener("click", showCapabilities);
$("#subagents-nav").addEventListener("click", showSubagents);
$("#reload-capabilities").addEventListener("click", showCapabilities);
$("#reload-subagents").addEventListener("click", loadSubagents);
$("#new-chat").addEventListener("click", async () => {
  try { state.selectedSession = null; state.source?.close(); showAssistant(); renderSession(); $("#prompt").focus(); } catch (error) { toast(error.message); }
});
$("#composer").addEventListener("submit", async (event) => {
  event.preventDefault(); const prompt = $("#prompt").value.trim(); if (!prompt) return;
  try {
    const session = state.selectedSession || await createSession();
    $("#prompt").value = "";
    replaceSession(await api(`/api/assistant/sessions/${encodeURIComponent(session.id)}/messages`, { method: "POST", body: JSON.stringify({ content: prompt }) }));
  } catch (error) { toast(error.message); }
});
$("#prompt").addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); $("#composer").requestSubmit(); } });
$("#abort-chat").addEventListener("click", async () => { try { replaceSession(await api(`/api/assistant/sessions/${encodeURIComponent(state.selectedSession.id)}/actions/abort`, { method: "POST", body: "{}" })); } catch (error) { toast(error.message); } });
$("#rename-chat").addEventListener("click", async () => {
  if (!state.selectedSession) return;
  const name = prompt("对话名称", state.selectedSession.title);
  if (!name?.trim()) return;
  try { replaceSession(await api(`/api/assistant/sessions/${encodeURIComponent(state.selectedSession.id)}/actions/rename`, { method: "POST", body: JSON.stringify({ name }) })); } catch (error) { toast(error.message); }
});
$("#delete-chat").addEventListener("click", async () => {
  if (!state.selectedSession || !confirm("删除当前对话？")) return;
  try {
    const id = state.selectedSession.id; await api(`/api/assistant/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
    state.source?.close(); state.sessions = state.sessions.filter((item) => item.id !== id); state.selectedSession = null; renderSession();
  } catch (error) { toast(error.message); }
});
$("#settings").addEventListener("click", () => { $("#token").value = state.token; $("#token-dialog").showModal(); });
$("#save-token").addEventListener("click", () => { localStorage.setItem("agent-platform-token", $("#token").value); location.reload(); });
boot();
