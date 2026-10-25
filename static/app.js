const PASTEL = { mint: "#B9E4A1", coral: "#F2A58B", butter: "#F9D56E", lavender: "#C3B1F5", sky: "#A8CCF4" };
const STATUS = {
  healthy: ["Healthy", "bg-mint"], watching: ["Watching", "bg-butter"],
  restricted: ["Restricted", "bg-coral"], quarantined: ["Quarantined", "bg-danger text-white"],
};
const DECISION = { allowed: "bg-mint", held: "bg-butter", blocked: "bg-coral", quarantined: "bg-danger text-white" };
const LINE = ["#6E56D9", "#D64545", "#3B82C4", "#2F8F4E", "#C27A12", "#17151F"];
let S = null, mode = localGet("mode") || "live", selected = null, chart = null;

function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem(k, v); } catch {} }
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const $ = (id) => document.getElementById(id);
const riskColor = (r) => (r >= 80 ? "#D64545" : r >= 60 ? "#F2A58B" : r >= 40 ? "#F9D56E" : "#B9E4A1");
const post = (url) => fetch(url, { method: "POST" }).then(refresh);

async function refresh() {
  try { S = await (await fetch("/api/state")).json(); render(); } catch (e) { /* engine restarting */ }
}

function render() {
  renderNav(); renderKpis(); renderBanner(); renderScenarios(); renderAgents();
  renderFeed(); renderDetail(); renderChart(); renderGraph(); renderLog(); renderGovernance();
}

function renderNav() {
  const l = $("llm");
  l.className = "badge " + (S.llm.available ? "bg-mint border-2 border-ink" : "bg-coral");
  l.textContent = S.llm.available ? "● " + S.llm.label : "No API key: replay only";
  document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("on", b.dataset.mode === mode));
}

function renderKpis() {
  const k = S.kpi, ext = S.external.reduce((a, x) => a + x.bytes, 0);
  const tiles = [["Agents monitored", k.agents, "sky"], ["Actions checked", k.actions, "mint"],
    ["Alerts raised", k.alerts, "coral"], ["Restricted now", k.restricted, "butter"]];
  $("kpis").innerHTML = tiles.map(([label, n, c]) => `
    <div class="card !p-5" style="background:${PASTEL[c]}">
      <div class="font-display font-extrabold text-5xl">${n}</div>
      <div class="font-semibold mt-1">${label}</div></div>`).join("") +
    `<div class="col-span-2 text-sm text-muted">Data that actually left MockCorp: <b class="text-ink">${ext} bytes</b></div>`;
}

function renderBanner() {
  const r = S.running, last = S.log[S.log.length - 1];
  $("banner").innerHTML = r
    ? `<span class="text-xl">⏳</span><b>Running: ${esc(r.title)}</b><span class="mono">${esc(r.mode)}</span>
       <span class="text-muted text-sm ml-auto truncate max-w-[60%]">${esc(last || "")}</span>`
    : `<span class="text-xl">🏷️</span><b>Pick a scenario below.</b><span class="mono">${mode === "live" && S.llm.available ? "live LLM agents" : "replay"}</span>
       <span class="text-muted text-sm ml-auto">Live runs are recorded; Replay re-sends them through the real gateway.</span>`;
}

function renderScenarios() {
  $("scenario-grid").innerHTML = S.scenarios.map((s) => {
    const rec = S.recorded.includes(s.id);
    const tag = s.scripted ? "scripted attacker" : rec ? "recorded run" : "LLM agents";
    return `<div class="card !p-5 flex flex-col gap-3" style="background:${PASTEL[s.color]}">
      <span class="chip self-start !text-xs font-semibold">${tag}</span>
      <h3 class="font-display font-extrabold text-xl leading-tight">${esc(s.title)}</h3>
      <p class="text-sm flex-1">${esc(s.desc)}</p>
      <div class="text-xs font-semibold">Expect: ${esc(s.expect)}</div>
      <button class="btn-primary !py-2 text-sm" ${S.running ? "disabled" : ""} onclick="run('${s.id}')">▶ Run</button></div>`;
  }).join("");
}

function renderAgents() {
  $("agent-grid").innerHTML = S.agents.map((a) => {
    const [label, cls] = STATUS[a.status];
    const revoked = a.revoked.map((r) => `<span class="badge bg-[#FDECEC] text-danger border-2 border-danger">✕ ${esc(r)}</span>`).join(" ");
    return `<div class="card relative flex flex-col gap-3 ${a.status === "quarantined" ? "!border-danger" : ""}">
      ${a.cold_start ? `<div class="sticker !bg-sky text-xs">Cold start</div>` : ""}
      <div class="flex items-start justify-between gap-2">
        <div><h3 class="font-display font-extrabold text-xl leading-tight">${esc(a.name)}</h3>
          <span class="mono">${esc(a.token)}</span> <span class="mono">role v${a.version}</span></div>
        <span class="badge ${cls}">${label}</span></div>
      <p class="text-sm text-muted">${esc(a.purpose)}</p>
      <div class="flex items-end gap-3"><div class="font-display font-extrabold text-4xl">${a.risk}</div>
        <div class="flex-1 pb-2"><div class="text-xs text-muted mb-1">risk</div>
        <div class="bar"><div style="width:${a.risk}%;background:${riskColor(a.risk)}"></div></div></div></div>
      <div class="flex flex-wrap gap-1">${a.tools.map((t) => `<span class="chip !text-xs">${esc(t)}</span>`).join("")}</div>
      <div class="text-xs text-muted">Baseline: ${a.cold_start ? "role cohort (" + a.baseline_n + " own actions)" : a.baseline_n + " own actions"} · drift ${a.cusum}/35</div>
      ${revoked ? `<div class="flex flex-wrap gap-1">${revoked}</div>` : ""}
      ${a.note ? `<div class="text-sm font-semibold text-danger">${esc(a.note)}</div>` : ""}
      ${a.status === "restricted" || a.status === "quarantined" ? `<button class="btn-secondary !py-1.5 text-sm self-start" onclick="post('/api/agent/${a.id}/release')">Release after review</button>` : ""}
    </div>`;
  }).join("");
}

function renderFeed() {
  const evs = [...S.events].reverse();
  if (!evs.length) { $("feed").innerHTML = `<p class="text-muted px-2">No actions yet.</p>`; return; }
  $("feed").innerHTML = evs.map((e) => `
    <div class="row ${selected === e.id ? "sel" : ""} ${e.score >= 60 ? "bad" : ""}" onclick="select(${e.id})">
      <div class="tile" style="background:${riskColor(e.score)}">${e.score}</div>
      <div class="min-w-0 flex-1"><div class="text-xs text-muted">${e.t}s · ${esc(e.agent)}</div>
        <div class="font-semibold truncate">${esc(e.tool)} <span class="font-normal text-muted">${esc(argSummary(e))}</span></div></div>
      <span class="badge ${DECISION[e.decision]}">${e.decision}</span></div>`).join("");
}

function argSummary(e) {
  const a = e.args || {};
  return a.name || a.url || a.to || a.agent || a.item || a.supplier || a.department || "";
}

function renderDetail() {
  const evs = S.events;
  let e = evs.find((x) => x.id === selected);
  if (!e) e = [...evs].reverse().find((x) => x.score >= 40) || evs[evs.length - 1];
  if (!e) { $("detail").innerHTML = `<h3 class="font-display font-extrabold text-xl">Alert detail</h3><p class="text-muted mt-2">Run a scenario to see how each action is scored.</p>`; return; }
  const sigs = e.signals.length ? e.signals.map((s) => `
    <div class="flex items-center gap-3 py-2 border-b-2 border-dashed border-ink/10 last:border-0">
      <span class="badge bg-butter border-2 border-ink w-14 text-center">+${s.points}</span>
      <div class="min-w-0"><div class="text-xs eyebrow !tracking-wider">${esc(s.layer)}</div><div class="text-sm">${esc(s.detail)}</div></div></div>`).join("")
    : `<p class="text-sm text-muted">No signals: consistent with role and baseline.</p>`;
  const chain = (e.chain || []).map((c) => `<span class="chip !text-xs ${c.role === "source" ? "!bg-coral" : c.role === "sink" ? "!bg-lavender" : ""}">
      <b class="uppercase">${c.role}</b> ${esc(c.label)}</span>`).join(`<span class="font-extrabold">→</span>`);
  $("detail").innerHTML = `
    ${e.decision === "quarantined" ? `<div class="sticker">Zap!</div>` : ""}
    <p class="eyebrow">Action #${e.id} · ${esc(e.agent)}</p>
    <div class="flex flex-wrap items-end gap-4 mt-2">
      <div class="font-display font-extrabold text-6xl leading-none" style="color:${e.score >= 60 ? "#D64545" : "#17151F"}">${e.score}</div>
      <div class="pb-1"><div class="font-display font-extrabold text-2xl">${esc(e.tool)}</div><div class="text-sm text-muted">${esc(argSummary(e))}</div></div>
      <span class="badge ${DECISION[e.decision]} ml-auto">${e.decision}</span></div>
    <div class="flex flex-wrap gap-2 mt-4">
      <span class="badge bg-mint border-2 border-ink">IAM ✓ token valid, tool in scope</span>
      <span class="chip !text-xs">domain: ${esc(e.domain)}</span>${e.host ? `<span class="chip !text-xs">dest: ${esc(e.host)}</span>` : ""}
      ${e.parent ? `<span class="chip !text-xs">delegated by ${esc(e.parent)}</span>` : ""}
      ${e.injection_score != null ? `<span class="chip !text-xs">injection ${e.injection_score}</span>` : ""}</div>
    ${e.reason ? `<div class="mt-4 rounded-input bg-[#FDECEC] border-2 border-danger px-4 py-3 text-sm font-semibold text-danger">${esc(e.reason)}</div>` : ""}
    <h4 class="font-display font-extrabold text-lg mt-5">Why this score</h4><div class="mt-1">${sigs}</div>
    ${chain ? `<h4 class="font-display font-extrabold text-lg mt-5">Evidence chain</h4><div class="flex flex-wrap items-center gap-2 mt-2">${chain}</div>` : ""}
    ${e.result ? `<div class="mt-4 text-xs text-muted">Result: <span class="font-mono">${esc(e.result)}</span></div>` : ""}`;
}

function renderChart() {
  const ids = Object.keys(S.risk_history);
  const datasets = ids.map((id, i) => ({ label: id, data: S.risk_history[id].map(([x, y]) => ({ x, y })), borderColor: LINE[i % LINE.length],
    backgroundColor: LINE[i % LINE.length], borderWidth: 3, tension: 0.25, pointRadius: 3, stepped: false }));
  if (!chart) {
    chart = new Chart($("chart"), { type: "line", data: { datasets }, options: {
      animation: false, maintainAspectRatio: false, parsing: false,
      scales: { x: { type: "linear", title: { display: true, text: "seconds" }, grid: { display: false } },
                y: { min: 0, max: 100, grid: { color: "#17151F14", borderDash: [4, 4] } } },
      plugins: { legend: { labels: { font: { family: "Outfit", weight: 600 }, usePointStyle: true } } } } });
  } else { chart.data.datasets = datasets; chart.update(); }
}

function renderGraph() {
  const by = Object.fromEntries(S.agents.map((a) => [a.id, a]));
  const fill = (id) => ({ healthy: "#B9E4A1", watching: "#F9D56E", restricted: "#F2A58B", quarantined: "#D64545" }[by[id]?.status] || "#fff");
  const children = S.agents.filter((a) => a.id !== "orchestrator");
  const w = 420, step = w / children.length;
  const used = new Set(S.events.filter((e) => e.parent).map((e) => e.parent + ">" + e.agent));
  const nodes = children.map((a, i) => ({ id: a.id, x: step * i + step / 2, y: 170 }));
  const node = (id, x, y) => `<g><rect x="${x - 58}" y="${y - 22}" width="116" height="44" rx="22" fill="${fill(id)}" stroke="#17151F" stroke-width="3"/>
    <text x="${x}" y="${y + 5}" text-anchor="middle" font-family="Outfit" font-weight="700" font-size="13" fill="${by[id]?.status === "quarantined" ? "#fff" : "#17151F"}">${esc(id)}</text></g>`;
  $("graph").innerHTML = `<svg viewBox="0 0 ${w} 210" class="w-full">
    ${nodes.map((n) => `<line x1="${w / 2}" y1="52" x2="${n.x}" y2="${n.y - 22}" stroke="${used.has("orchestrator>" + n.id) ? "#D64545" : "#17151F"}"
      stroke-width="${used.has("orchestrator>" + n.id) ? 4 : 2}" stroke-dasharray="${used.has("orchestrator>" + n.id) ? "0" : "6 6"}"/>`).join("")}
    ${node("orchestrator", w / 2, 30)}${nodes.map((n) => node(n.id, n.x, n.y)).join("")}</svg>
    <p class="text-xs text-muted mt-2">Solid red edge = a delegation that happened in this run. Risk flows both ways along it.</p>`;
}

function renderLog() {
  $("log").innerHTML = S.log.length ? S.log.map((l) => `<div>${esc(l)}</div>`).join("") : `<div class="text-ink/60">Agent messages appear here.</div>`;
}

function renderGovernance() {
  $("approvals").innerHTML = S.approvals.length ? S.approvals.slice().reverse().map((a) => `
    <div class="row !cursor-default"><div class="tile bg-butter">${a.score}</div>
      <div class="flex-1 min-w-0"><div class="text-xs text-muted">${esc(a.agent)}</div><div class="font-semibold truncate">${esc(a.tool)} ${esc(JSON.stringify(a.args)).slice(0, 60)}</div></div>
      ${a.status === "pending" ? `<button class="btn-primary !px-3 !py-1 text-xs" onclick="post('/api/approval/${a.id}/approve')">Approve</button>
        <button class="btn-secondary !px-3 !py-1 text-xs" onclick="post('/api/approval/${a.id}/deny')">Deny</button>`
        : `<span class="badge ${a.status === "approved" ? "bg-mint" : "bg-coral"}">${a.status}</span>`}</div>`).join("")
    : `<p class="text-sm text-muted">Nothing waiting. Actions scoring 40–59 land here.</p>`;
  $("changes").innerHTML = S.changes.length ? S.changes.map((c) => `
    <div class="row !cursor-default"><div class="tile bg-mint">v${c.version || "?"}</div>
      <div class="flex-1"><div class="text-xs text-muted">${esc(c.agent)} · ${esc(c.reason)}</div>
      <div class="font-semibold">+ ${esc(c.tools.join(", "))} · ${esc(c.domains.join(", "))}</div></div>
      ${c.status === "pending" ? `<button class="btn-primary !px-3 !py-1 text-xs" onclick="post('/api/change/${c.id}/approve')">Approve</button>` : `<span class="badge bg-mint">${c.status}</span>`}</div>`).join("")
    : `<p class="text-sm text-muted">No declared changes. Undeclared new behavior is scored as drift.</p>`;
  $("plugins").innerHTML = S.plugins.map((p) => `
    <div class="row !cursor-default ${p.verdict === "block" ? "bad" : ""}"><div class="tile ${p.verdict === "block" ? "bg-coral" : "bg-mint"}">${Math.round(p.risk * 100)}</div>
      <div class="flex-1 min-w-0"><div class="font-semibold ${p.verdict === "block" ? "line-through" : ""}">${esc(p.name)} <span class="mono">${esc(p.vendor)}</span></div>
      <div class="text-xs text-muted truncate">${p.verdict === "block" ? esc(p.categories.join(", ")) + " · rejected from registry" : esc(p.description)}</div></div>
      <span class="badge ${p.verdict === "block" ? "bg-danger text-white" : "bg-mint"}">${p.verdict === "block" ? "Rejected" : "Allowed"}</span></div>`).join("");
  $("external").innerHTML = S.external.length ? S.external.map((x) => `
    <div class="row !cursor-default bad"><div class="tile bg-coral">!</div><div class="flex-1"><div class="font-semibold">${esc(x.to)}</div>
      <div class="text-xs text-muted">${esc(x.channel)} · ${x.bytes} bytes</div></div></div>`).join("")
    : `<div class="row !cursor-default"><div class="tile bg-mint">0</div><div class="font-semibold">Nothing left the company to an external host.</div></div>`;
}

function run(id) { selected = null; fetch(`/api/scenario/${id}?mode=${mode}`, { method: "POST" }).then(refresh); }
function select(id) { selected = id; renderFeed(); renderDetail(); }

document.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => { mode = b.dataset.mode; localSet("mode", mode); render(); }));
$("reset").addEventListener("click", () => { selected = null; post("/api/reset"); });
refresh();
setInterval(refresh, 1000);
