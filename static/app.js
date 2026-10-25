const PASTEL = { mint: "#B9E4A1", coral: "#F2A58B", butter: "#F9D56E", lavender: "#C3B1F5", sky: "#A8CCF4" };
const STATUS = { healthy: ["Healthy", "bg-mint"], watching: ["Watching", "bg-butter"], restricted: ["Restricted", "bg-coral"], quarantined: ["Quarantined", "bg-danger text-white"] };
const DECISION = { allowed: "bg-mint", held: "bg-butter", blocked: "bg-coral", quarantined: "bg-danger text-white" };
const LINE = ["#6E56D9", "#D64545", "#3B82C4", "#2F8F4E", "#C27A12", "#17151F"];
let S = null, selected = null, chart = null, formsBuilt = false, blastAgent = null;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const riskColor = (r) => (r >= 80 ? "#D64545" : r >= 60 ? "#F2A58B" : r >= 40 ? "#F9D56E" : "#B9E4A1");
const list = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);
const checks = (name, items, on = []) => items.map((t) => `<label class="check"><input type="checkbox" name="${name}" value="${t}" ${on.includes(t) ? "checked" : ""}> ${t}</label>`).join("");
const picked = (form, name) => [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((i) => i.value);

async function api(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && url.startsWith("/api/")) location.href = "/login";
  if (!r.ok) throw new Error(data.detail || "Request failed");
  refresh();
  return data;
}

async function refresh() {
  const r = await fetch("/api/state");
  if (r.status === 401) { location.href = "/login"; return; }
  S = await r.json();
  if (!formsBuilt) buildForms();
  render();
}

function tab(name) {
  document.querySelectorAll("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== name));
  document.querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("tab-on", b.dataset.tab === name));
  try { localStorage.setItem("tab", name); } catch {}
}

function render() {
  $("llm").className = "badge " + (S.llm.available ? "bg-mint border-2 border-ink" : "bg-coral");
  $("llm").textContent = S.llm.available ? "● " + S.llm.label : "No LLM key";
  $("avatar").textContent = (S.me.name || "?").trim()[0].toUpperCase();
  $("org").textContent = S.me.org + " · " + S.me.email;
  $("empty").classList.toggle("hidden", S.agents.length > 0);
  renderKpis(); renderAgents(); renderFeed(); renderDetail(); renderChart(); renderGraph(); renderLog();
  renderAgentList(); renderSelects(); renderDocs(); renderGovernance(); renderApi();
  if (blastAgent) loadBlast();
}

function openBlast(id) { blastAgent = id; loadBlast(); setTimeout(() => $("blast").scrollIntoView({ behavior: "smooth", block: "start" }), 150); }

async function loadBlast() {
  const b = await (await fetch(`/api/agents/${blastAgent}/blast`)).json();
  const box = $("blast"); box.classList.remove("hidden");
  const items = (arr, f) => arr.length ? arr.map(f).join("") : `<span class="text-sm text-muted">none</span>`;
  const chip = (t, cls = "") => `<span class="chip !text-xs ${cls}">${t}</span>`;
  if (!b.incident) { box.innerHTML = `<div class="flex justify-between"><h3 class="font-display font-extrabold text-2xl">Blast radius · ${esc(blastAgent)}</h3>
    <button class="btn-secondary !py-1 !px-3 text-xs" onclick="blastAgent=null;$('blast').classList.add('hidden')">Close</button></div><p class="mt-2">No incident on record for this agent.</p>`; return; }
  box.innerHTML = `<div class="flex flex-wrap items-start justify-between gap-3">
      <div><p class="eyebrow !text-danger">Incident since ${new Date(b.since * 1000).toLocaleTimeString()}</p>
        <h3 class="font-display font-extrabold text-3xl mt-1">Blast radius · ${esc(blastAgent)}</h3>
        <p class="text-sm mt-1">Everything this compromise touched, so you can contain it precisely.</p></div>
      <div class="flex gap-2">${b.remediated ? `<span class="badge bg-mint border-2 border-ink">✓ Contained</span>`
        : `<button class="btn-primary" onclick="remediate('${esc(blastAgent)}')">🛡 Contain &amp; roll back</button>`}
        <button class="btn-secondary !py-2 !px-4 text-sm" onclick="blastAgent=null;$('blast').classList.add('hidden')">Close</button></div></div>
    <div class="grid md:grid-cols-3 gap-4 mt-5">
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">1 · Entry point</div><div class="flex flex-wrap gap-1 mt-2">${items(b.sources, (s) => chip(`☣ ${esc(s.label)}${s.score ? " · " + s.score : ""}`, "!bg-coral"))}</div></div>
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">2 · Data it reached</div><div class="flex flex-wrap gap-1 mt-2">${items(b.data_accessed, (d) => chip(`${esc(d.label)} · ${esc(d.domain)}`, "!bg-butter"))}</div></div>
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">3 · Data that left</div><div class="flex flex-wrap gap-1 mt-2">${items(b.outbound, (o) => chip(`↗ ${esc(o.label)}`, "!bg-coral"))}</div></div>
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">4 · Actions it completed</div><div class="flex flex-col gap-1 mt-2">${items(b.completed, (p) =>
        `<div class="text-sm"><b class="${p.status !== "open" ? "line-through" : ""}">${esc(p.id)}</b> ${esc(p.supplier || "")} × ${esc(p.quantity || "")} <span class="badge ${p.status === "open" ? "bg-butter" : "bg-mint"}">${esc(p.status)}</span></div>`)}</div></div>
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">5 · Attempts stopped</div><div class="flex flex-wrap gap-1 mt-2">${items(b.blocked, (x) => chip(`✕ ${esc(x.label)} · ${x.score}`, "!bg-[#FDECEC]"))}</div></div>
      <div class="bg-white rounded-input p-4 border-2 border-ink"><div class="eyebrow">6 · Downstream agents</div><div class="flex flex-wrap gap-1 mt-2">${items(b.downstream, (d) => chip(esc(d), "!bg-lavender"))}</div></div>
    </div>`;
}

async function remediate(id) {
  if (!confirm(`Contain ${id}? This quarantines it, rotates its token and cancels actions completed inside the compromised sessions.`)) return;
  await api(`/api/agents/${id}/remediate`);
}

function renderKpis() {
  const k = S.kpi, sent = S.external.filter((x) => x.delivered).length;
  $("kpis").innerHTML = [["Agents", k.agents, "sky"], ["Actions checked", k.actions, "mint"], ["Alerts", k.alerts, "coral"], ["Restricted now", k.restricted, "butter"]]
    .map(([l, n, c]) => `<div class="card !p-5" style="background:${PASTEL[c]}"><div class="font-display font-extrabold text-5xl">${n}</div><div class="font-semibold mt-1">${l}</div></div>`).join("") +
    `<div class="col-span-2 text-sm text-muted">Outbound attempts to unlisted hosts: <b class="text-ink">${S.external.length}</b> · actually delivered: <b class="text-ink">${sent}</b></div>`;
}

function renderAgents() {
  $("agent-grid").innerHTML = S.agents.map((a) => {
    const [label, cls] = STATUS[a.status];
    const busy = S.running.includes(a.id);
    return `<div class="card relative flex flex-col gap-3 ${a.status === "quarantined" ? "!border-danger" : ""}">
      ${a.cold_start ? `<div class="sticker !bg-sky text-xs" style="right:auto;left:46%;top:-22px">Learning</div>` : ""}
      <div class="flex items-start justify-between gap-2"><div><h3 class="font-display font-extrabold text-xl leading-tight">${esc(a.name)}</h3>
        <span class="mono">${esc(a.id)}</span> <span class="mono">role v${a.version}</span></div>
        <span class="badge ${busy ? "bg-sky border-2 border-ink" : cls}">${busy ? "Working…" : label}</span></div>
      <p class="text-sm text-muted">${esc(a.purpose)}</p>
      <div class="flex items-end gap-3"><div class="font-display font-extrabold text-4xl">${a.risk}</div>
        <div class="flex-1 pb-2"><div class="text-xs text-muted mb-1">risk</div><div class="bar"><div style="width:${a.risk}%;background:${riskColor(a.risk)}"></div></div></div></div>
      <div class="text-xs text-muted">Baseline: ${a.cold_start ? "manifest + cohort while learning (" + a.baseline_n + "/20 own actions)" : a.baseline_n + " own actions"} · drift ${a.cusum}/35</div>
      ${a.revoked.length ? `<div class="flex flex-wrap gap-1">${a.revoked.map((r) => `<span class="badge bg-[#FDECEC] text-danger border-2 border-danger">✕ ${esc(r)}</span>`).join("")}</div>` : ""}
      ${a.note ? `<div class="text-sm font-semibold text-danger">${esc(a.note)}</div>` : ""}
      <div class="flex flex-wrap gap-2">${a.risk >= 40 || a.status !== "healthy" ? `<button class="btn-primary !py-1.5 text-sm" onclick="openBlast('${a.id}')">◎ Blast radius</button>` : ""}
      ${a.status === "restricted" || a.status === "quarantined" ? `<button class="btn-secondary !py-1.5 text-sm" onclick="api('/api/agents/${a.id}/release')">Release after review</button>` : ""}</div>
    </div>`;
  }).join("");
}

const argSummary = (e) => { const a = e.args || {}; return a.name || a.url || a.to || a.agent || a.item || a.supplier || a.department || ""; };

function renderFeed() {
  const evs = [...S.events].reverse();
  $("feed").innerHTML = evs.length ? evs.map((e) => `
    <div class="row ${selected === e.id ? "sel" : ""} ${e.score >= 60 ? "bad" : ""}" onclick="selected=${e.id};renderFeed();renderDetail()">
      <div class="tile" style="background:${riskColor(e.score)}">${e.score}</div>
      <div class="min-w-0 flex-1"><div class="text-xs text-muted">${new Date(e.ts * 1000).toLocaleTimeString()} · ${esc(e.agent)}</div>
        <div class="font-semibold truncate">${esc(e.tool)} <span class="font-normal text-muted">${esc(argSummary(e))}</span></div></div>
      <span class="badge ${DECISION[e.decision]}">${e.decision}</span></div>`).join("") : `<p class="text-muted px-2">No actions yet.</p>`;
}

function renderDetail() {
  let e = S.events.find((x) => x.id === selected) || [...S.events].reverse().find((x) => x.score >= 40) || S.events[S.events.length - 1];
  if (!e) { $("detail").innerHTML = `<h3 class="font-display font-extrabold text-xl">Alert detail</h3><p class="text-muted mt-2">When an agent acts, each call and its score appear here.</p>`; return; }
  const sigs = e.signals.length ? e.signals.map((s) => `<div class="flex items-center gap-3 py-2 border-b-2 border-dashed border-ink/10 last:border-0">
      <span class="badge bg-butter border-2 border-ink w-14 text-center">+${s.points}</span>
      <div class="min-w-0"><div class="text-xs eyebrow !tracking-wider">${esc(s.layer)}</div><div class="text-sm">${esc(s.detail)}</div></div></div>`).join("")
    : `<p class="text-sm text-muted">No signals: consistent with role and baseline.</p>`;
  const chain = (e.chain || []).map((c) => `<span class="chip !text-xs ${c.role === "source" ? "!bg-coral" : c.role === "sink" ? "!bg-lavender" : ""}"><b class="uppercase">${c.role}</b> ${esc(c.label)}</span>`).join(`<span class="font-extrabold">→</span>`);
  $("detail").innerHTML = `${e.decision === "quarantined" ? `<div class="sticker">Zap!</div>` : ""}
    <p class="eyebrow">Action #${e.id} · ${esc(e.agent)} · ${esc(e.client || "")}</p>
    <div class="flex flex-wrap items-end gap-4 mt-2"><div class="font-display font-extrabold text-6xl leading-none" style="color:${e.score >= 60 ? "#D64545" : "#17151F"}">${e.score}</div>
      <div class="pb-1"><div class="font-display font-extrabold text-2xl">${esc(e.tool)}</div><div class="text-sm text-muted">${esc(argSummary(e))}</div></div>
      <span class="badge ${DECISION[e.decision]} ml-auto">${e.decision}</span></div>
    <div class="flex flex-wrap gap-2 mt-4"><span class="badge bg-mint border-2 border-ink">IAM ✓ token valid, tool in scope</span>
      <span class="chip !text-xs">domain: ${esc(e.domain)}</span>${e.host ? `<span class="chip !text-xs">dest: ${esc(e.host)}</span>` : ""}
      ${e.parent ? `<span class="chip !text-xs">delegated by ${esc(e.parent)}</span>` : ""}${e.injection_score != null ? `<span class="chip !text-xs">injection ${e.injection_score}</span>` : ""}
      ${e.sanitized ? `<span class="badge bg-mint border-2 border-ink">✂ ${e.sanitized} line(s) sanitized</span>` : ""}</div>
    ${e.reason ? `<div class="mt-4 rounded-input bg-[#FDECEC] border-2 border-danger px-4 py-3 text-sm font-semibold text-danger">${esc(e.reason)}</div>` : ""}
    <h4 class="font-display font-extrabold text-lg mt-5">Why this score</h4><div class="mt-1">${sigs}</div>
    ${chain ? `<h4 class="font-display font-extrabold text-lg mt-5">Evidence chain</h4><div class="flex flex-wrap items-center gap-2 mt-2">${chain}</div>` : ""}
    ${e.result ? `<div class="mt-4 text-xs text-muted">Result: <span class="font-mono">${esc(e.result)}</span></div>` : ""}
    ${e.ai_summary ? `<div class="mt-5 rounded-input bg-lavender border-2 border-ink p-4 text-sm"><b>✦ Analyst summary</b><div class="mt-1 whitespace-pre-line">${esc(e.ai_summary)}</div></div>` : ""}
    <div class="flex flex-wrap gap-2 mt-5">${e.score >= 25 && !e.ai_summary ? `<button class="btn-primary !py-1.5 text-sm" onclick="explain(${e.id}, this)">✦ Explain with AI</button>` : ""}
      <button class="btn-secondary !py-1.5 text-sm" onclick="report(${e.id})">⬇ Incident report</button></div>`;
}

async function explain(id, btn) {
  btn.disabled = true; btn.textContent = "Writing summary…";
  try { await api(`/api/events/${id}/explain`); } catch (err) { btn.textContent = err.message; }
}

function report(id) {
  const e = S.events.find((x) => x.id === id), a = S.agents.find((x) => x.id === e.agent) || {};
  const doc = { generated: new Date().toISOString(), workspace: S.me.org, reviewer: S.me.email,
    agent: { id: a.id, name: a.name, purpose: a.purpose, role_version: a.version, declared_tools: a.tools, declared_domains: a.domains, status: a.status },
    action: { id: e.id, time: new Date(e.ts * 1000).toISOString(), tool: e.tool, args: e.args, domain: e.domain, destination: e.host, client: e.client, session: e.session, delegated_by: e.parent },
    iam: "token valid, tool in scope", risk_score: e.score, decision: e.decision, enforcement: e.reason, signals: e.signals, evidence_chain: e.chain, analyst_summary: e.ai_summary || null };
  const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }));
  Object.assign(document.createElement("a"), { href: url, download: `driftguard-incident-${e.id}.json` }).click();
  URL.revokeObjectURL(url);
}

function renderChart() {
  const datasets = Object.keys(S.risk_history).map((id, i) => ({ label: id, data: S.risk_history[id].map(([x, y]) => ({ x, y })),
    borderColor: LINE[i % LINE.length], backgroundColor: LINE[i % LINE.length], borderWidth: 3, tension: 0.25, pointRadius: 3 }));
  if (!chart) chart = new Chart($("chart"), { type: "line", data: { datasets }, options: { animation: false, maintainAspectRatio: false, parsing: false,
    scales: { x: { type: "linear", title: { display: true, text: "seconds since workspace start" }, grid: { display: false } }, y: { min: 0, max: 100, grid: { color: "#17151F14" } } },
    plugins: { legend: { labels: { font: { family: "Outfit", weight: 600 }, usePointStyle: true } } } } });
  else { chart.data.datasets = datasets; chart.update(); }
}

function renderGraph() {
  const A = S.agents, n = A.length;
  if (!n) { $("graph").innerHTML = `<p class="text-sm text-muted">Agents and their delegation links appear here.</p>`; return; }
  const w = 420, h = 230, pos = {};
  A.forEach((a, i) => { const t = (i / n) * 2 * Math.PI - Math.PI / 2; pos[a.id] = n === 1 ? [w / 2, h / 2] : [w / 2 + 150 * Math.cos(t), h / 2 + 80 * Math.sin(t)]; });
  const used = new Set(S.events.filter((e) => e.parent).map((e) => e.parent + ">" + e.agent));
  const fill = { healthy: "#B9E4A1", watching: "#F9D56E", restricted: "#F2A58B", quarantined: "#D64545" };
  const edges = [];
  A.forEach((a) => a.can_delegate.forEach((b) => pos[b] && edges.push([a.id, b])));
  used.forEach((k) => { const [a, b] = k.split(">"); if (pos[a] && pos[b] && !edges.some((e) => e[0] === a && e[1] === b)) edges.push([a, b]); });
  $("graph").innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="w-full">${edges.map(([a, b]) => { const hot = used.has(a + ">" + b);
      return `<line x1="${pos[a][0]}" y1="${pos[a][1]}" x2="${pos[b][0]}" y2="${pos[b][1]}" stroke="${hot ? "#D64545" : "#17151F"}" stroke-width="${hot ? 4 : 2}" stroke-dasharray="${hot ? 0 : "6 6"}"/>`; }).join("")}
    ${A.map((a) => `<rect x="${pos[a.id][0] - 56}" y="${pos[a.id][1] - 20}" width="112" height="40" rx="20" fill="${fill[a.status]}" stroke="#17151F" stroke-width="3"/>
      <text x="${pos[a.id][0]}" y="${pos[a.id][1] + 5}" text-anchor="middle" font-family="Outfit" font-weight="700" font-size="13" fill="${a.status === "quarantined" ? "#fff" : "#17151F"}">${esc(a.id.slice(0, 14))}</text>`).join("")}</svg>
    <p class="text-xs text-muted mt-2">Dashed = allowed delegation · solid red = delegation that happened. Risk flows both ways.</p>`;
}

function renderLog() { $("log").innerHTML = S.log.length ? S.log.slice().reverse().map((l) => `<div>${esc(l)}</div>`).join("") : `<div class="text-ink/60">Nothing yet.</div>`; }

function renderAgentList() {
  $("agent-list").innerHTML = S.agents.length ? S.agents.map((a) => `<div class="row !cursor-default"><div class="tile" style="background:${riskColor(a.risk)}">${a.risk}</div>
    <div class="flex-1 min-w-0"><div class="font-semibold">${esc(a.name)}</div><div class="text-xs text-muted truncate">${esc(a.tools.join(", "))}</div>
    <div class="text-xs"><span class="mono">${esc(a.token)}</span> ${a.client ? `<span class="text-muted">pinned: ${esc(a.client)}</span>` : ""}</div></div>
    <button class="btn-secondary !px-3 !py-1 text-xs" onclick="rotate('${a.id}')">New token</button></div>`).join("") : `<p class="text-sm text-muted">None yet.</p>`;
}

function setOptions(sel, items) {
  const keep = sel.value, html = items.map((a) => `<option value="${a.id}">${esc(a.name)} (${esc(a.id)})</option>`).join("");
  if (sel.dataset.h !== html) { sel.innerHTML = html; sel.dataset.h = html; if (items.some((a) => a.id === keep)) sel.value = keep; }
}
function renderSelects() { setOptions($("task-agent"), S.agents); setOptions($("change-agent"), S.agents); }

function renderDocs() {
  $("doc-list").innerHTML = S.documents.map((d) => `<div class="row !cursor-default"><div class="tile ${d.folder === "hr" ? "bg-coral" : d.folder === "finance" ? "bg-butter" : "bg-sky"}">${d.folder[0].toUpperCase()}</div>
    <div class="flex-1 min-w-0"><div class="font-semibold truncate">${esc(d.name)} ${S.canaries.includes(d.name) ? `<span class="badge bg-butter border-2 border-ink">canary</span>` : ""}</div><div class="text-xs text-muted">${esc(d.folder)} · ${d.size} chars</div></div></div>`).join("");
}

function renderGovernance() {
  $("approvals").innerHTML = S.approvals.length ? S.approvals.slice().reverse().map((a) => `<div class="row !cursor-default"><div class="tile bg-butter">${a.score}</div>
    <div class="flex-1 min-w-0"><div class="text-xs text-muted">${esc(a.agent)}</div><div class="font-semibold truncate">${esc(a.tool)} ${esc(JSON.stringify(a.args)).slice(0, 60)}</div></div>
    ${a.status === "pending" ? `<div class="flex flex-col gap-1"><button class="btn-primary !px-3 !py-1 text-xs" onclick="api('/api/approval/${a.id}/approve')">Approve once</button>
      <button class="btn-primary !px-3 !py-1 text-xs" title="Approve and add this capability to the agent's role" onclick="api('/api/approval/${a.id}/learn')">Approve + add to role</button>
      <button class="btn-secondary !px-3 !py-1 text-xs" onclick="api('/api/approval/${a.id}/deny')">Deny</button></div>`
      : `<span class="badge ${a.status.startsWith("approved") ? "bg-mint" : "bg-coral"}">${a.status}</span>`}</div>`).join("") : `<p class="text-sm text-muted">Nothing waiting. Actions scoring 40–59 land here.</p>`;
  $("changes").innerHTML = S.changes.slice().reverse().map((c) => `<div class="row !cursor-default"><div class="tile bg-mint">${c.version ? "v" + c.version : "?"}</div>
    <div class="flex-1 min-w-0"><div class="text-xs text-muted truncate">${esc(c.agent)} · ${esc(c.reason)}</div><div class="font-semibold truncate">+ ${esc([...c.tools, ...c.domains, ...(c.egress || [])].join(", "))}</div></div>
    ${c.status === "pending" ? `<button type="button" class="btn-primary !px-3 !py-1 text-xs" onclick="api('/api/changes/${c.id}/approve')">Approve</button>` : `<span class="badge bg-mint">${c.status}</span>`}</div>`).join("");
  $("plugins").innerHTML = S.plugins.slice().reverse().map((p) => `<div class="row !cursor-default ${p.verdict === "block" ? "bad" : ""}"><div class="tile ${p.verdict === "block" ? "bg-coral" : "bg-mint"}">${Math.round(p.risk * 100)}</div>
    <div class="flex-1 min-w-0"><div class="font-semibold ${p.verdict === "block" ? "line-through" : ""}">${esc(p.name)} ${p.vendor ? `<span class="mono">${esc(p.vendor)}</span>` : ""}</div>
    <div class="text-xs text-muted truncate">${p.verdict === "block" ? esc(p.categories.join(", ")) + " · " + esc(p.reason) : esc(p.description)}</div></div>
    <span class="badge ${p.verdict === "block" ? "bg-danger text-white" : "bg-mint"}">${p.verdict === "block" ? "Rejected" : "Approved"}</span></div>`).join("");
  $("external").innerHTML = S.external.length ? S.external.slice().reverse().map((x) => `<div class="row !cursor-default ${x.delivered ? "bad" : ""}"><div class="tile ${x.delivered ? "bg-coral" : "bg-sky"}">${x.delivered ? "!" : "↗"}</div>
    <div class="flex-1 min-w-0"><div class="font-semibold truncate">${esc(x.to)}</div><div class="text-xs text-muted">${esc(x.channel)} · ${x.bytes} bytes · ${x.delivered ? "delivered" : "allowed by policy, sandboxed"}</div></div></div>`).join("")
    : `<div class="row !cursor-default"><div class="tile bg-mint">0</div><div class="font-semibold">No traffic has left the company to unlisted hosts.</div></div>`;
}

function renderApi() {
  const host = location.origin, a = S.agents[0];
  const tokenNote = a ? `Use the token shown when you registered <b>${esc(a.name)}</b> (or press <b>New token</b> on the Agents tab).` : "Register an agent first to get a token.";
  const code = (s) => `<pre class="bg-ink text-cream rounded-input p-4 text-[13px] overflow-x-auto font-mono">${esc(s)}</pre>`;
  $("api-body").innerHTML = `<p class="text-sm">${tokenNote}</p>
    <div><h4 class="font-display font-extrabold text-lg">1. Open a session for a task</h4>${code(`curl -X POST ${host}/v1/sessions -H "Authorization: Bearer <AGENT_TOKEN>" -H "Content-Type: application/json" -d "{\\"task\\": \\"Buy 500 hex nuts\\"}"`)}</div>
    <div><h4 class="font-display font-extrabold text-lg">2. Call a tool inside that session</h4>${code(`curl -X POST ${host}/v1/tools/search_suppliers -H "Authorization: Bearer <AGENT_TOKEN>" -H "X-Session: <SESSION_ID>" -H "Content-Type: application/json" -d "{\\"item\\": \\"hex nuts\\"}"`)}</div>
    <div><h4 class="font-display font-extrabold text-lg">What a stolen token looks like</h4><p class="text-sm text-muted mb-2">The same token, used with no session from a new client. Try it.</p>${code(`curl -X POST ${host}/v1/tools/read_hr_file -H "Authorization: Bearer <AGENT_TOKEN>" -H "Content-Type: application/json" -d "{\\"name\\": \\"salaries_2026.csv\\"}"`)}</div>
    <div><h4 class="font-display font-extrabold text-lg">Tools</h4><p class="text-sm">${S.all_tools.map((t) => `<span class="mono mr-1">${t}</span>`).join("")} · schemas at <span class="mono">GET /v1/tools</span></p></div>`;
}

async function rotate(id) {
  if (!confirm("Issue a new token? The old one stops working immediately.")) return;
  showToken(await api(`/api/agents/${id}/rotate`));
}

function showToken(r) {
  const box = $("token-box");
  box.classList.remove("hidden");
  box.innerHTML = `<p class="eyebrow !text-ink">Agent token · shown once</p><h3 class="font-display font-extrabold text-xl mt-1">${esc(r.id)}</h3>
    <div class="mono !text-[13px] !rounded-input !p-3 mt-3 break-all">${esc(r.token)}</div>
    <button class="btn-primary !py-1.5 text-sm mt-3" onclick="navigator.clipboard.writeText('${esc(r.token)}');this.textContent='Copied'">Copy token</button>`;
}

function buildForms() {
  formsBuilt = true;
  const t = $("template");
  t.innerHTML = `<option value="">Custom role</option>` + Object.entries(S.templates).map(([k, v]) => `<option value="${k}">${esc(v.name)}</option>`).join("");
  const fill = () => {
    const v = S.templates[t.value] || { tools: [], domains: [], egress: [], can_delegate: [] }, f = $("agent-form");
    if (v.name) { f.name.value = v.name; f.id.value = t.value; f.purpose.value = v.purpose; }
    f.egress.value = v.egress.filter((e) => e !== "mockcorp.internal").join(", ");
    f.can_delegate.value = v.can_delegate.join(", ");
    $("f-tools").innerHTML = checks("tools", S.all_tools, v.tools);
    $("f-domains").innerHTML = checks("domains", S.all_domains, v.domains);
  };
  t.addEventListener("change", fill); fill();
  $("c-tools").innerHTML = checks("tools", S.all_tools);
  $("c-domains").innerHTML = checks("domains", S.all_domains);

  $("agent-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target;
    try {
      showToken(await api("/api/agents", { template: f.template.value, name: f.name.value, id: f.id.value, purpose: f.purpose.value,
        tools: picked(f, "tools"), domains: picked(f, "domains"), egress: list(f.egress.value), can_delegate: list(f.can_delegate.value) }));
      $("agent-err").classList.add("hidden");
    } catch (err) { $("agent-err").textContent = err.message; $("agent-err").classList.remove("hidden"); }
  });
  $("task-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target, m = $("task-msg");
    try { await api("/api/tasks", { agent: f.agent.value, task: f.task.value, untrusted: f.untrusted.checked });
      m.className = "text-sm font-semibold"; m.textContent = "Started. Watch it on the Overview tab."; setTimeout(() => tab("overview"), 700);
    } catch (err) { m.className = "text-sm font-semibold text-danger"; m.textContent = err.message; }
  });
  $("doc-file").addEventListener("change", async (e) => {
    const file = e.target.files[0]; if (!file) return;
    $("doc-form").name.value = file.name; $("doc-form").text.value = await file.text();
  });
  $("doc-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target, m = $("doc-msg");
    try { await api("/api/documents", { name: f.name.value, folder: f.folder.value, text: f.text.value, canary: f.canary.checked }); m.className = "text-sm font-semibold"; m.textContent = "Uploaded."; f.reset(); }
    catch (err) { m.className = "text-sm font-semibold text-danger"; m.textContent = err.message; }
  });
  $("change-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target;
    try { await api("/api/changes", { agent: f.agent.value, tools: picked(f, "tools"), domains: picked(f, "domains"), egress: list(f.egress.value), reason: f.reason.value }); f.reset(); }
    catch (err) { alert(err.message); }
  });
  const sf = $("settings-form");
  sf.sanitize.checked = !!S.settings.sanitize; sf.intent.checked = S.settings.intent !== false; sf.webhook.value = S.settings.webhook || "";
  sf.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await api("/api/settings", { sanitize: sf.sanitize.checked, intent: sf.intent.checked, webhook: sf.webhook.value }); $("settings-msg").textContent = "Saved."; }
    catch (err) { $("settings-msg").textContent = err.message; }
  });
  $("plugin-form").addEventListener("submit", async (e) => {
    e.preventDefault(); const f = e.target;
    try { await api("/api/plugins", { name: f.name.value, vendor: f.vendor.value, description: f.description.value, source: f.source.value }); f.reset(); }
    catch (err) { alert(err.message); }
  });
}

document.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => tab(b.dataset.tab)));
$("logout").addEventListener("click", async () => { await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login"; });
let start = "overview"; try { start = localStorage.getItem("tab") || start; } catch {}
tab(start);
refresh();
setInterval(refresh, 1500);
