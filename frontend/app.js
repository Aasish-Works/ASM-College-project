const state = {
  apiBase: localStorage.getItem("asm_api_base") || "http://127.0.0.1:8000",
  view: "overview",
  system: null,
  runtime: null,
  dashboard: null,
  targets: [],
  jobs: [],
  automations: [],
  notifications: [],
  threatIntel: [],
  portfolio: null,
  exposures: [],
  assetsByUrl: [],
  recentReports: [],
  selectedTargetId: null,
  selectedTargetReport: null,
  selectedTargetMonitoring: [],
  selectedJobId: null,
  selectedJobReport: null,
  toolExecution: null,
  lastRefresh: null,
  loading: false,
};

const viewMeta = {
  overview: ["Overview", "Mission summary, scanning posture, and attack-surface drift in one place."],
  inventory: ["Inventory", "Search registered scope, open a target, and inspect graph-linked attack surface evidence."],
  jobs: ["Scan Jobs", "Track queue state, inspect live pipeline progress, and open detailed scan reports."],
  reporting: ["Reporting", "Portfolio reporting, exposure feeds, asset evidence, and workflow activity."],
  tools: ["Tool Lab", "Run scanner adapters directly and inspect native versus fallback execution behavior."],
  settings: ["Settings", "Runtime health, node state, automation, notifications, and destructive maintenance actions."],
};

const el = {
  navButtons: [...document.querySelectorAll(".nav-button")],
  viewTitle: document.getElementById("viewTitle"),
  viewSubtitle: document.getElementById("viewSubtitle"),
  sidebarStatus: document.getElementById("sidebarStatus"),
  runtimeMode: document.getElementById("runtimeMode"),
  lastRefresh: document.getElementById("lastRefresh"),
  apiBaseInput: document.getElementById("apiBaseInput"),
  saveApiBase: document.getElementById("saveApiBase"),
  refreshAll: document.getElementById("refreshAll"),
  quickScan: document.getElementById("quickScan"),
  resetData: document.getElementById("resetData"),
  recoverJobs: document.getElementById("recoverJobs"),
  cleanupJobs: document.getElementById("cleanupJobs"),
  scanInput: document.getElementById("scanInput"),
  scanScope: document.getElementById("scanScope"),
  scanTargetType: document.getElementById("scanTargetType"),
  scanKind: document.getElementById("scanKind"),
  scanCriticality: document.getElementById("scanCriticality"),
  scanPriority: document.getElementById("scanPriority"),
  scanCreate: document.getElementById("scanCreate"),
  useSelectedTarget: document.getElementById("useSelectedTarget"),
  scanHint: document.getElementById("scanHint"),
  overviewCards: document.getElementById("overviewCards"),
  heroTrend: document.getElementById("heroTrend"),
  riskHeatmap: document.getElementById("riskHeatmap"),
  recentTargets: document.getElementById("recentTargets"),
  recentJobs: document.getElementById("recentJobs"),
  topAssets: document.getElementById("topAssets"),
  threatIntelList: document.getElementById("threatIntelList"),
  targetSearch: document.getElementById("targetSearch"),
  targetSearchBtn: document.getElementById("targetSearchBtn"),
  targetTable: document.getElementById("targetTable"),
  selectedTargetTitle: document.getElementById("selectedTargetTitle"),
  selectedTargetSubtitle: document.getElementById("selectedTargetSubtitle"),
  targetSummary: document.getElementById("targetSummary"),
  attackPaths: document.getElementById("attackPaths"),
  graphCanvas: document.getElementById("graphCanvas"),
  assetList: document.getElementById("assetList"),
  exposureList: document.getElementById("exposureList"),
  identityList: document.getElementById("identityList"),
  vulnerabilityList: document.getElementById("vulnerabilityList"),
  monitoringList: document.getElementById("monitoringList"),
  rawStreamList: document.getElementById("rawStreamList"),
  runIntel: document.getElementById("runIntel"),
  scanSelected: document.getElementById("scanSelected"),
  jobSearch: document.getElementById("jobSearch"),
  jobSearchBtn: document.getElementById("jobSearchBtn"),
  jobTable: document.getElementById("jobTable"),
  reportBody: document.getElementById("reportBody"),
  portfolioCards: document.getElementById("portfolioCards"),
  reportFeed: document.getElementById("reportFeed"),
  exposureBoard: document.getElementById("exposureBoard"),
  assetFeed: document.getElementById("assetFeed"),
  notificationList: document.getElementById("notificationList"),
  automationList: document.getElementById("automationList"),
  runtimeSummary: document.getElementById("runtimeSummary"),
  toolName: document.getElementById("toolName"),
  toolTarget: document.getElementById("toolTarget"),
  toolTimeout: document.getElementById("toolTimeout"),
  runTool: document.getElementById("runTool"),
  toolHint: document.getElementById("toolHint"),
  toolExecution: document.getElementById("toolExecution"),
  toolInventory: document.getElementById("toolInventory"),
  operationsSummary: document.getElementById("operationsSummary"),
  nodeList: document.getElementById("nodeList"),
  settingsCards: document.getElementById("settingsCards"),
  detailDialog: document.getElementById("detailDialog"),
  detailTitle: document.getElementById("detailTitle"),
  detailContent: document.getElementById("detailContent"),
  closeDetail: document.getElementById("closeDetail"),
};

el.apiBaseInput.value = state.apiBase;

const endpoint = (path) => `${state.apiBase}${path}`;
const empty = (message) => `<div class="empty-state">${escapeHtml(message)}</div>`;
const tone = (value) => {
  const v = String(value || "").toLowerCase();
  if (["completed", "resolved", "online"].includes(v)) return "success";
  if (["running", "queued", "retry_pending", "pending"].includes(v)) return "warning";
  if (["failed", "offline"].includes(v)) return "danger";
  return "info";
};
const severityTone = (value) => {
  const v = String(value || "").toLowerCase();
  if (["critical", "high"].includes(v)) return "danger";
  if (v === "medium") return "warning";
  if (v === "low") return "info";
  return "neutral";
};

function executionBadge(result) {
  if (!result?.fallback_used) return { label: "native", tone: "success" };
  const reason = String(result?.fallback_reason || result?.stderr_sample || "").toLowerCase();
  if (reason.includes("forced by configuration")) return { label: "fallback by config", tone: "warning" };
  if (reason.includes("not found in path")) return { label: "fallback missing binary", tone: "warning" };
  if (reason.includes("not implemented")) return { label: "fallback only", tone: "info" };
  return { label: "fallback", tone: "warning" };
}

function executionSummary(result) {
  const badge = executionBadge(result);
  if (!result?.fallback_used) return "Direct native tool execution.";
  if (badge.label === "fallback by config") return "Native execution was available but disabled by runtime configuration.";
  if (badge.label === "fallback missing binary") return "The tool binary was not found in PATH, so the adapter used Python fallback evidence.";
  if (badge.label === "fallback only") return "This adapter currently supports Python fallback evidence only.";
  return "The adapter fell back to Python evidence collection instead of direct native execution.";
}

function outputTitle(result) {
  return result?.fallback_used ? `${result.tool} fallback evidence` : `${result.tool} native output`;
}

function toolAvailabilityLabel(tool) {
  const mode = String(state.runtime?.mode || "unknown").toLowerCase();
  if (!tool.native_supported) return { label: "fallback only", tone: "info" };
  if (tool.native_available && mode === "fallback") return { label: "available but forced fallback", tone: "warning" };
  if (tool.native_available) return { label: "native available", tone: "success" };
  return { label: "fallback missing binary", tone: "warning" };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtDate(value) {
  if (!value) return "N/A";
  try { return new Date(value).toLocaleString(); } catch { return String(value); }
}

function fmtNumber(value, digits = 2) {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed.toFixed(digits) : digits === 4 ? "0.0000" : "0.00";
}

function pill(label, kind = "neutral") {
  return `<span class="pill ${kind}">${escapeHtml(label)}</span>`;
}

function card(title, value, meta) {
  return `<article class="metric-card"><div class="eyebrow">${escapeHtml(title)}</div><div class="value">${escapeHtml(value)}</div><div class="meta">${escapeHtml(meta)}</div></article>`;
}

function signal(title, value, meta, kind = "info") {
  return `<article class="signal-card"><div class="eyebrow">${escapeHtml(title)}</div><div class="value">${escapeHtml(value)}</div><div class="pill-row">${pill(kind === "success" ? "healthy" : kind === "warning" ? "watch" : kind === "danger" ? "risk" : "info", kind)}</div><div class="meta">${escapeHtml(meta)}</div></article>`;
}

function factsOnlyFinding(item) {
  return Boolean(item?.facts_only || item?.details?.evidence_mode === "facts_only" || (!item?.cve && item?.source === "exposure_engine"));
}

function findingMeta(item) {
  const d = item?.details || {};
  if (factsOnlyFinding(item)) {
    return [d.observation, d.asset && `asset ${d.asset}`, d.host && `host ${d.host}`, d.path && `path ${d.path}`, d.provider && `provider ${d.provider}`].filter(Boolean).join(" • ");
  }
  return [item.cve || "No CVE", `CVSS ${fmtNumber(item.cvss, 1)}`, `EPSS ${fmtNumber(item.epss, 4)}`, `risk ${fmtNumber(item.risk_score, 2)}`, item.source].filter(Boolean).join(" • ");
}

function renderFinding(item) {
  return `<article class="list-card"><header><strong>${escapeHtml(item.title)}</strong>${pill(item.severity, severityTone(item.severity))}</header><div class="meta">${escapeHtml(findingMeta(item))}</div><div class="meta-row"><span>${escapeHtml([item.host || item.details?.host, item.exposure || item.details?.classification, item.threat_context || item.details?.title].filter(Boolean).join(" • "))}</span></div></article>`;
}

function openDetail(title, html) {
  el.detailTitle.textContent = title;
  el.detailContent.innerHTML = html;
  el.detailDialog.showModal();
}

async function request(path, options = {}) {
  const response = await fetch(endpoint(path), {
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) throw new Error((await response.text()) || `Request failed: ${response.status}`);
  return response.json();
}

function setView(view) {
  state.view = view;
  const meta = viewMeta[view];
  el.viewTitle.textContent = meta[0];
  el.viewSubtitle.textContent = meta[1];
  el.navButtons.forEach((button) => button.classList.toggle("is-active", button.dataset.view === view));
  document.querySelectorAll(".view").forEach((panel) => panel.classList.toggle("is-active", panel.id === `view-${view}`));
}

function renderGraph(graph) {
  if (!graph?.nodes?.length) {
    el.graphCanvas.innerHTML = "";
    return;
  }
  const columns = { domain: 110, ip: 270, service: 430, application: 600, saas: 600, identity: 760 };
  const grouped = {};
  graph.nodes.forEach((node) => {
    const kind = columns[node.kind] ? node.kind : "application";
    grouped[kind] = grouped[kind] || [];
    grouped[kind].push(node);
  });
  const positions = new Map();
  Object.entries(grouped).forEach(([kind, nodes]) => {
    nodes.forEach((node, index) => positions.set(node.id, { x: columns[kind], y: 66 + index * 76, kind }));
  });
  const edges = (graph.edges || []).map((edge) => {
    const s = positions.get(edge.source);
    const t = positions.get(edge.target);
    return s && t ? `<line class="graph-edge" x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"></line>` : "";
  }).join("");
  const nodes = graph.nodes.map((node) => {
    const pos = positions.get(node.id);
    if (!pos) return "";
    const label = node.label.length > 24 ? `${node.label.slice(0, 24)}...` : node.label;
    return `<g><circle class="graph-node ${escapeHtml(pos.kind)}" cx="${pos.x}" cy="${pos.y}" r="18"></circle><text x="${pos.x + 28}" y="${pos.y + 5}">${escapeHtml(label)}</text></g>`;
  }).join("");
  el.graphCanvas.innerHTML = `${edges}${nodes}`;
}

function renderShell() {
  const stats = state.system?.stats || state.dashboard?.stats || {};
  const summary = state.runtime?.summary || {};
  el.sidebarStatus.innerHTML = [
    signal("Targets", stats.targets || 0, "Registered scope objects", "info"),
    signal("Assets", stats.assets || 0, "Correlated inventory nodes", "success"),
    signal("Findings", stats.vulnerabilities || 0, "Exposure observations and vulnerabilities", stats.vulnerabilities ? "warning" : "success"),
    signal("Open jobs", stats.open_jobs || 0, "Queued, running, or retry pending", stats.open_jobs ? "warning" : "success"),
    signal("Nodes", state.runtime?.nodes?.length || 0, `${summary.native_available_count || 0} native-capable adapters`, state.runtime?.nodes?.length ? "success" : "warning"),
    signal("Identities", stats.identity_exposures || 0, "Credential and identity exposure records", stats.identity_exposures ? "warning" : "info"),
  ].join("");
  el.runtimeMode.textContent = `Mode: ${state.runtime?.mode || "unknown"}`;
  el.lastRefresh.textContent = `Last refresh: ${state.lastRefresh ? fmtDate(state.lastRefresh) : "never"}`;
}

function renderOverview() {
  const stats = state.dashboard?.stats || {};
  el.overviewCards.innerHTML = [
    card("Registered targets", stats.targets || 0, "Domains, IPs, CIDRs, and monitored scope"),
    card("Correlated assets", stats.assets || 0, "Domains, IPs, services, applications, and cloud nodes"),
    card("Findings", stats.vulnerabilities || 0, "Exposure observations plus CVE-backed vulnerabilities"),
    card("Identity surface", stats.identity_exposures || 0, "Exposed credentials and service principals"),
  ].join("");

  const trends = state.dashboard?.trends || [];
  if (!trends.length) el.heroTrend.innerHTML = empty("No trend data yet.");
  else {
    const latest = trends[trends.length - 1];
    const max = Math.max(...trends.flatMap((item) => [item.assets || 0, item.vulnerabilities || 0, item.scans || 0]), 1);
    const bars = [
      ["Assets", latest.assets || 0, "linear-gradient(90deg, rgba(130, 211, 198, 0.9), rgba(143, 197, 255, 0.85))"],
      ["Findings", latest.vulnerabilities || 0, "linear-gradient(90deg, rgba(255, 139, 128, 0.9), rgba(242, 187, 120, 0.92))"],
      ["Scans", latest.scans || 0, "linear-gradient(90deg, rgba(184, 164, 255, 0.88), rgba(143, 197, 255, 0.85))"],
    ];
    el.heroTrend.innerHTML = `<div class="meta">Latest recorded day: ${escapeHtml(latest.date)}</div>` + bars.map(([label, value, color]) => `<div class="trend-bar"><div class="meta-row"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div><div class="trend-track"><div class="trend-fill" style="width:${Math.max((value / max) * 100, 4)}%;background:${color};"></div></div></div>`).join("");
  }

  const heatmap = state.dashboard?.risk_heatmap || {};
  const severityRows = Object.keys(heatmap).map((severity) => `<div class="heatmap-row"><div class="meta-row"><strong>${escapeHtml(severity)}</strong>${pill(severity, severityTone(severity))}</div><div class="heatmap-cells">${Object.entries(heatmap[severity] || {}).map(([exposure, count]) => `<div class="heat-cell"><div class="meta">${escapeHtml(exposure)}</div><strong>${escapeHtml(count)}</strong></div>`).join("")}</div></div>`);
  el.riskHeatmap.innerHTML = severityRows.length ? severityRows.join("") : empty("No risk heatmap data yet.");

  el.recentTargets.innerHTML = (state.dashboard?.recent_targets || []).length ? state.dashboard.recent_targets.map((target) => `<article class="record-card"><header><strong>${escapeHtml(target.name)}</strong>${pill(target.target_type, "info")}</header><div class="meta">${escapeHtml(target.scope || "No scope set")}</div><div class="meta-row"><span>${escapeHtml(target.asset_count)} assets</span><span>${escapeHtml(target.vulnerability_count)} findings</span><span>${escapeHtml(target.latest_job_status || "no-jobs")}</span></div></article>`).join("") : empty("No recent targets yet.");
  el.recentJobs.innerHTML = (state.dashboard?.recent_jobs || []).length ? state.dashboard.recent_jobs.map((job) => {
    const target = state.targets.find((item) => item.id === job.target_id);
    return `<article class="record-card"><header><strong>${escapeHtml(target?.name || `Target ${job.target_id}`)}</strong>${pill(job.status, tone(job.status))}</header><div class="meta">${escapeHtml(`${job.kind} • progress ${job.progress}%`)}</div><div class="meta-row"><span>${escapeHtml(job.current_stage || "queued")}</span><span>${escapeHtml(job.status_message || "No stage message yet.")}</span></div></article>`;
  }).join("") : empty("No jobs queued yet.");
  el.topAssets.innerHTML = (state.dashboard?.top_risky_assets || []).length ? state.dashboard.top_risky_assets.map((asset) => `<article class="list-card"><header><strong>${escapeHtml(asset.value)}</strong>${pill(`risk ${fmtNumber(asset.risk_score, 2)}`, asset.risk_score >= 70 ? "danger" : asset.risk_score >= 40 ? "warning" : "info")}</header><div class="meta">${escapeHtml(`${asset.kind} • ${asset.classification} • ${asset.exposure}`)}</div></article>`).join("") : empty("No asset risk data yet.");
  el.threatIntelList.innerHTML = state.threatIntel.length ? state.threatIntel.map((item) => `<article class="list-card"><header><strong>${escapeHtml(item.cve)}</strong>${pill(item.kev ? "KEV" : item.exploit_maturity, item.kev ? "danger" : "info")}</header><div class="meta">${escapeHtml(`CVSS ${fmtNumber(item.cvss_v3, 1)} • EPSS ${fmtNumber(item.epss, 4)} • ${item.threat_context}`)}</div></article>`).join("") : empty("Threat intelligence records will appear once CVE-backed findings are stored.");
}

function renderTargets(list = state.targets) {
  el.targetTable.innerHTML = list.length ? list.map((target) => `<article class="record-card ${state.selectedTargetId === target.id ? "is-selected" : ""}"><header><div><strong>${escapeHtml(target.name)}</strong><div class="meta-row">${pill(target.target_type, "info")}${pill(`C${target.business_criticality}`, "warning")}${target.latest_job_status ? pill(target.latest_job_status, tone(target.latest_job_status)) : ""}</div></div><div class="record-actions"><button class="button quiet" data-open-target="${target.id}">Open</button></div></header><div class="meta">${escapeHtml(target.scope || "No explicit scope set.")}</div><div class="meta-row"><span>${escapeHtml(target.asset_count)} assets</span><span>${escapeHtml(target.vulnerability_count)} findings</span><span>${escapeHtml(target.exposure_count)} exposures</span><span>${escapeHtml(target.identity_count)} identities</span></div></article>`).join("") : empty("No targets matched the current filter.");
  el.targetTable.querySelectorAll("[data-open-target]").forEach((button) => button.addEventListener("click", () => loadTargetIntel(Number(button.dataset.openTarget))));

  const report = state.selectedTargetReport;
  if (!report) {
    el.selectedTargetTitle.textContent = "Select a target";
    el.selectedTargetSubtitle.textContent = "Assets, identities, graph relationships, and evidence will appear here.";
    el.targetSummary.innerHTML = empty("No target selected.");
    el.attackPaths.innerHTML = empty("No target selected.");
    el.assetList.innerHTML = empty("No target selected.");
    el.exposureList.innerHTML = empty("No target selected.");
    el.identityList.innerHTML = empty("No target selected.");
    el.vulnerabilityList.innerHTML = empty("No target selected.");
    el.monitoringList.innerHTML = empty("No target selected.");
    el.rawStreamList.innerHTML = empty("No target selected.");
    el.graphCanvas.innerHTML = "";
    return;
  }

  const target = report.target || {};
  const summary = report.summary || {};
  el.selectedTargetTitle.textContent = target.name || "Selected target";
  el.selectedTargetSubtitle.textContent = `${target.target_type || "target"} • criticality ${target.business_criticality || 3} • ${summary.asset_count || 0} assets • ${summary.vulnerability_count || 0} findings`;
  el.targetSummary.innerHTML = [
    card("Assets", summary.asset_count || 0, "Normalized graph inventory"),
    card("Findings", summary.vulnerability_count || 0, `${summary.cve_backed_count || 0} CVE-backed • ${summary.facts_only_count || 0} facts-only`),
    card("EPSS avg", fmtNumber(summary.average_epss || 0, 4), "CVE-backed findings only"),
    card("Risk avg", fmtNumber(summary.average_risk || 0, 2), "Contextual enterprise score"),
  ].join("");
  el.attackPaths.innerHTML = (report.attack_paths || []).length ? report.attack_paths.map((path) => `<article class="list-card"><header><strong>${escapeHtml(path.summary)}</strong>${pill(`score ${fmtNumber(path.score, 2)}`, path.score >= 70 ? "danger" : "warning")}</header><div class="meta">${escapeHtml(`${path.entry?.label || "entry"} -> ${path.goal?.label || "goal"}`)}</div></article>`).join("") : empty("No attack paths were modeled for this target yet.");
  renderGraph(report.graph);
  el.assetList.innerHTML = (report.assets || []).length ? report.assets.slice(0, 40).map((asset) => `<article class="list-card"><header><strong>${escapeHtml(asset.value)}</strong>${pill(asset.kind, "info")}</header><div class="meta">${escapeHtml(`${asset.classification} • ${asset.exposure} • ${asset.protocol || "n/a"}`)}</div><div class="meta-row"><span>${escapeHtml(asset.status_code || "no-http")}</span><span>${escapeHtml(Array.isArray(asset.tech_stack) ? asset.tech_stack.join(", ") : asset.tech_stack || "no-tech")}</span></div></article>`).join("") : empty("No assets recorded yet.");
  const facts = (report.vulnerabilities || []).filter(factsOnlyFinding);
  el.exposureList.innerHTML = facts.length ? facts.slice(0, 40).map(renderFinding).join("") : empty("No exposure observations yet.");
  el.identityList.innerHTML = (report.identity_exposures || []).length ? report.identity_exposures.map((identity) => `<article class="list-card"><header><strong>${escapeHtml(identity.principal)}</strong>${pill(identity.status, tone(identity.status))}</header><div class="meta">${escapeHtml(`${identity.kind} • ${identity.secret_type || "unknown secret"} • ${identity.privilege_level}`)}</div><div class="meta">${escapeHtml(identity.evidence || "")}</div></article>`).join("") : empty("No identity exposure recorded yet.");
  const ranked = report.top_risk_vulnerabilities || report.vulnerabilities || [];
  el.vulnerabilityList.innerHTML = ranked.length ? ranked.slice(0, 30).map(renderFinding).join("") : empty("No vulnerabilities stored yet.");
  el.monitoringList.innerHTML = state.selectedTargetMonitoring.length ? state.selectedTargetMonitoring.map((rule) => `<article class="list-card"><header><strong>${escapeHtml(rule.name)}</strong>${pill(rule.enabled ? "enabled" : "disabled", rule.enabled ? "success" : "neutral")}</header><div class="meta">${escapeHtml(`${rule.mode} • ${rule.cron || rule.event_type || "no schedule"}`)}</div><div class="meta">${escapeHtml(`Next run ${fmtDate(rule.next_run_at)}`)}</div></article>`).join("") : empty("No monitoring rules recorded.");
  el.rawStreamList.innerHTML = (report.raw_asset_streams || []).length ? report.raw_asset_streams.slice(0, 30).map((event) => `<article class="list-card"><header><strong>${escapeHtml(event.asset_key)}</strong>${pill(event.source, "info")}</header><div class="meta">${escapeHtml(`confidence ${fmtNumber(event.confidence, 2)} • observed ${fmtDate(event.observed_at)}`)}</div></article>`).join("") : empty("No raw intelligence events stored yet.");
}

function renderJobs(list = state.jobs) {
  el.jobTable.innerHTML = list.length ? list.map((job) => {
    const target = state.targets.find((item) => item.id === job.target_id);
    return `<article class="record-card ${state.selectedJobId === job.id ? "is-selected" : ""}"><header><div><strong>${escapeHtml(target?.name || `Target ${job.target_id}`)}</strong><div class="meta-row">${pill(job.kind, "info")}${pill(job.status, tone(job.status))}${pill(`P${job.priority}`, "warning")}</div></div><div class="record-actions"><button class="button quiet" data-open-job="${job.id}">Open</button>${job.status !== "running" ? `<button class="button quiet" data-requeue-job="${job.id}">Requeue</button><button class="button danger" data-delete-job="${job.id}">Delete</button>` : ""}</div></header><div class="meta">${escapeHtml(`Progress ${job.progress}% • attempts ${job.attempts}/${job.max_retries}`)}</div><div class="meta-row"><span>${escapeHtml(job.current_stage || "queued")}</span><span>${escapeHtml(job.status_message || job.last_error || "No stage message yet.")}</span></div></article>`;
  }).join("") : empty("No jobs matched the current filter.");
  el.jobTable.querySelectorAll("[data-open-job]").forEach((button) => button.addEventListener("click", () => loadJobReport(Number(button.dataset.openJob))));
  el.jobTable.querySelectorAll("[data-requeue-job]").forEach((button) => button.addEventListener("click", () => requeueJob(Number(button.dataset.requeueJob))));
  el.jobTable.querySelectorAll("[data-delete-job]").forEach((button) => button.addEventListener("click", () => deleteJob(Number(button.dataset.deleteJob))));

  const report = state.selectedJobReport;
  if (!report) {
    el.reportBody.innerHTML = empty("Pick a job to open detailed reporting.");
    return;
  }
  const job = report.job || {};
  const target = report.target || {};
  const summary = report.summary || {};
  el.reportBody.innerHTML = `
    <article class="report-card">
      <header><div><strong>${escapeHtml(target.name || "Target")} • Job #${escapeHtml(job.id)}</strong><div class="meta-row">${pill(job.status, tone(job.status))}${pill(job.kind, "info")}${pill(`progress ${job.progress}%`, "warning")}</div></div></header>
      <div class="summary-grid">${card("Assets", summary.inventory_asset_count || 0, "Inventory assets associated with the target")}${card("Findings", summary.vulnerability_count || 0, `${summary.cve_backed_count || 0} CVE-backed • ${summary.facts_only_count || 0} facts-only`)}${card("EPSS avg", fmtNumber(summary.average_epss || 0, 4), "CVE-backed findings only")}${card("Fallback runs", summary.fallback_count || 0, `${summary.tool_count || 0} tool results stored`)}</div>
      ${summary.last_error ? `<div class="meta">Last error: ${escapeHtml(summary.last_error)}</div>` : ""}
    </article>
    <article class="report-card"><header><strong>Stage timeline</strong></header>${(report.stages || []).length ? report.stages.map((stage) => `<article class="list-card"><header><strong>${escapeHtml(stage.name)}</strong>${pill(stage.status, tone(stage.status))}</header><div class="meta">${escapeHtml(`Start ${fmtDate(stage.started_at)} • Finish ${fmtDate(stage.finished_at)} • ${stage.duration_ms || 0} ms`)}</div>${stage.logs ? `<div class="meta">${escapeHtml(stage.logs)}</div>` : ""}</article>`).join("") : empty("No stage records stored yet.")}</article>
    <article class="report-card"><header><strong>Tool results</strong></header>${(report.results || []).length ? report.results.map((result) => {
      const badge = executionBadge(result);
      return `<article class="list-card"><header><strong>${escapeHtml(result.tool)}</strong>${pill(badge.label, badge.tone)}</header><div class="meta">${escapeHtml(`${result.stage} • exit ${result.exit_code} • ${result.status}`)}</div><div class="meta">${escapeHtml(executionSummary(result))}</div><div class="record-actions"><button class="button quiet" data-result-detail="${result.id}">View output</button></div></article>`;
    }).join("") : empty("No tool results stored yet.")}</article>
    <article class="report-card"><header><strong>Findings</strong></header>${(report.vulnerabilities || []).length ? report.vulnerabilities.slice(0, 40).map(renderFinding).join("") : empty("No findings attached to this job.")}</article>
  `;
  el.reportBody.querySelectorAll("[data-result-detail]").forEach((button) => button.addEventListener("click", () => {
    const result = (report.results || []).find((item) => item.id === Number(button.dataset.resultDetail));
    if (!result) return;
    const badge = executionBadge(result);
    openDetail(
      outputTitle(result),
      `<div class="meta-row">${pill(badge.label, badge.tone)}${pill(result.stage, "info")}${pill(`exit ${result.exit_code}`, result.exit_code === 0 ? "success" : "danger")}</div><div class="meta">${escapeHtml(executionSummary(result))}</div><pre>${escapeHtml(JSON.stringify({ command: result.payload?.command, resolved_target: result.resolved_target, fallback_reason: result.fallback_reason, native_available: result.native_available, native_supported: result.native_supported, payload: result.payload, artifact: result.artifact }, null, 2))}</pre><pre>${escapeHtml(result.stdout_sample || "")}</pre>${result.stderr_sample ? `<pre>${escapeHtml(result.stderr_sample)}</pre>` : ""}`
    );
  }));
}

function renderReporting() {
  const summary = state.portfolio?.summary || state.dashboard?.stats || {};
  const trends = state.portfolio?.trends || state.dashboard?.trends || [];
  const avgScans = trends.length ? Math.round(trends.reduce((sum, item) => sum + (item.scans || 0), 0) / trends.length) : 0;
  el.portfolioCards.innerHTML = [card("Targets", summary.targets || 0, "Registered program scope"), card("Assets", summary.assets || 0, "Correlated inventory footprint"), card("Open jobs", summary.open_jobs || 0, `Average ${avgScans} scans per day in current window`), card("Nodes", summary.nodes || state.runtime?.nodes?.length || 0, "Scanner nodes and workers")].join("");
  el.reportFeed.innerHTML = state.recentReports.length ? state.recentReports.map((item) => `<article class="record-card"><header><strong>${escapeHtml(item.target)}</strong>${pill(item.status, tone(item.status))}</header><div class="meta">${escapeHtml(`${item.kind} • progress ${item.progress}% • ${item.vulnerability_count || 0} findings`)}</div><div class="record-actions"><button class="button quiet" data-feed-job="${item.job_id}">Open report</button></div></article>`).join("") : empty("No reports available yet.");
  el.reportFeed.querySelectorAll("[data-feed-job]").forEach((button) => button.addEventListener("click", async () => { setView("jobs"); await loadJobReport(Number(button.dataset.feedJob)); }));
  el.exposureBoard.innerHTML = state.exposures.length ? state.exposures.slice(0, 80).map(renderFinding).join("") : empty("No exposure observations stored.");
  el.assetFeed.innerHTML = state.assetsByUrl.length ? state.assetsByUrl.slice(0, 80).map((asset) => `<article class="list-card"><header><strong>${escapeHtml(asset.host || asset.url || asset.kind)}</strong>${pill(asset.kind, "info")}</header><div class="meta">${escapeHtml(`${asset.classification} • ${asset.exposure}`)}</div><div class="meta-row"><span>${escapeHtml(asset.status_code || "no-http")}</span><span>${escapeHtml((asset.tech || []).join(", ") || "no-tech")}</span></div></article>`).join("") : empty("No URL-facing assets stored.");
  el.notificationList.innerHTML = state.notifications.length ? state.notifications.map((item) => `<article class="list-card"><header><strong>${escapeHtml(item.subject)}</strong>${pill(item.status, tone(item.status))}</header><div class="meta">${escapeHtml(item.message)}</div><div class="meta-row"><span>${escapeHtml(item.channel)}</span><span>${escapeHtml(fmtDate(item.created_at))}</span></div></article>`).join("") : empty("No notifications yet.");
  el.automationList.innerHTML = state.automations.length ? state.automations.map((rule) => `<article class="list-card"><header><strong>${escapeHtml(rule.name)}</strong>${pill(rule.enabled ? "enabled" : "disabled", rule.enabled ? "success" : "neutral")}</header><div class="meta">${escapeHtml(`${rule.event} -> ${rule.action}`)}</div></article>`).join("") : empty("No automation rules configured.");
}

function renderTools() {
  const summary = state.runtime?.summary || {};
  const inventory = state.runtime?.inventory || [];
  el.runtimeSummary.innerHTML = [
    signal("Runtime mode", state.runtime?.mode || "unknown", state.runtime?.wordlist_available ? `Wordlist ready at ${state.runtime.wordlist_path}` : `Wordlist missing at ${state.runtime?.wordlist_path || "unknown"}`, state.runtime?.wordlist_available ? "success" : "warning"),
    signal("Native available", summary.native_available_count || 0, `${summary.tool_count || 0} adapters total`, summary.native_available_count ? "success" : "warning"),
    signal("Fallback only", summary.fallback_only_count || 0, "Adapters that rely on the Python fallback path", summary.fallback_only_count ? "warning" : "success"),
    signal("Workers", state.runtime?.worker_count || 0, `Scheduler every ${state.runtime?.scheduler_interval_seconds || 0}s`, "info"),
  ].join("");
  const currentTool = el.toolName.value;
  el.toolName.innerHTML = inventory.map((item) => `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`).join("");
  if (currentTool && inventory.some((item) => item.name === currentTool)) el.toolName.value = currentTool;
  el.toolInventory.innerHTML = inventory.length ? inventory.map((tool) => {
    const availability = toolAvailabilityLabel(tool);
    return `<article class="tool-card ${el.toolName.value === tool.name ? "is-selected" : ""}"><header><strong>${escapeHtml(tool.name)}</strong>${pill(availability.label, availability.tone)}</header><div class="meta">${escapeHtml(`${tool.stage} • ${tool.category}`)}</div><div class="meta">${escapeHtml(tool.description)}</div><div class="meta">${escapeHtml(`Profiles: ${(tool.profiles || []).join(", ") || "none"}`)}</div><div class="meta">${escapeHtml(`Preview: ${(tool.command_preview || []).join(" ")}`)}</div></article>`;
  }).join("") : empty("No tool inventory available.");
  if (!state.toolExecution) {
    el.toolExecution.innerHTML = empty("Run a tool to inspect command resolution, stdout, stderr, and fallback evidence.");
    return;
  }
  const result = state.toolExecution;
  const badge = executionBadge(result);
  el.toolExecution.innerHTML = `<article class="console-card"><header><strong>${escapeHtml(result.tool)} on ${escapeHtml(result.resolved_target || "")}</strong>${pill(badge.label, badge.tone)}</header><div class="meta-row"><span>${escapeHtml(`stage ${result.stage}`)}</span><span>${escapeHtml(`status ${result.status}`)}</span><span>${escapeHtml(`exit ${result.exit_code}`)}</span><span>${escapeHtml(`${result.duration_ms || 0} ms`)}</span></div><div class="meta">${escapeHtml(executionSummary(result))}</div><pre>${escapeHtml(JSON.stringify({ command: result.command, fallback_reason: result.fallback_reason, native_available: result.native_available, native_supported: result.native_supported, artifact: result.artifact }, null, 2))}</pre><pre>${escapeHtml(result.stdout || "")}</pre>${result.stderr ? `<pre>${escapeHtml(result.stderr)}</pre>` : ""}</article>`;
}

function renderSettings() {
  const nodes = state.runtime?.nodes || [];
  const online = nodes.filter((node) => node.status === "online").length;
  el.operationsSummary.innerHTML = [
    signal("Nodes online", online, `${nodes.length} registered worker nodes`, online ? "success" : "warning"),
    signal("Automation rules", state.automations.length, "Workflow actions configured on the platform", state.automations.length ? "success" : "info"),
    signal("Notifications", state.notifications.length, "Queued and delivered operator messages", state.notifications.length ? "info" : "success"),
    signal("Threat records", state.threatIntel.length, "Stored KEV, exploit, and EPSS enrichment entries", state.threatIntel.length ? "success" : "warning"),
  ].join("");
  el.nodeList.innerHTML = nodes.length ? nodes.map((node) => `<article class="list-card"><header><strong>${escapeHtml(node.node_name)}</strong>${pill(node.status, tone(node.status))}</header><div class="meta">${escapeHtml((node.capabilities || []).join(", ") || "No capabilities reported")}</div><div class="meta-row"><span>${escapeHtml(`load ${node.current_load}/${node.capacity}`)}</span><span>${escapeHtml(`cpu ${node.cpu_percent}%`)}</span><span>${escapeHtml(`mem ${node.memory_percent}%`)}</span><span>${escapeHtml(`disk ${node.disk_percent}%`)}</span></div></article>`).join("") : empty("No scanner nodes have reported a heartbeat yet.");
  el.settingsCards.innerHTML = [card("Backend", state.apiBase, "Current API endpoint for the UI"), card("Native mode", state.runtime?.mode || "unknown", "auto uses binaries when found, fallback uses Python checks"), card("Tool timeout", state.runtime?.tool_timeout_seconds || 0, "Default timeout applied to tool adapters"), card("Wordlist", state.runtime?.wordlist_available ? "ready" : "missing", state.runtime?.wordlist_path || "No wordlist path reported")].join("");
}

function renderAll() {
  renderShell();
  renderOverview();
  renderTargets();
  renderJobs();
  renderReporting();
  renderTools();
  renderSettings();
}

async function loadTargetIntel(targetId) {
  state.selectedTargetId = targetId;
  const [report, monitoring] = await Promise.all([request(`/targets/${targetId}/intel`), request(`/targets/${targetId}/monitoring`)]);
  state.selectedTargetReport = report;
  state.selectedTargetMonitoring = monitoring;
  renderTargets();
}

async function loadJobReport(jobId) {
  state.selectedJobId = jobId;
  state.selectedJobReport = await request(`/reports/jobs/${jobId}`);
  renderJobs();
}

async function loadCoreData() {
  const [system, dashboard, targets, jobs, automations, notifications, threatIntel, portfolio, exposures, assetsByUrl, recentReports] = await Promise.all([
    request("/system/status"),
    request("/dashboard"),
    request("/targets"),
    request("/jobs"),
    request("/automation/rules"),
    request("/notifications"),
    request("/threat-intel").then((payload) => payload.items || []),
    request("/api/reporting/portfolio"),
    request("/api/exposures?limit=60"),
    request("/api/assets/by-url?limit=60"),
    request("/api/reports?limit=25"),
  ]);
  state.system = system;
  state.runtime = system.runtime;
  state.dashboard = dashboard;
  state.targets = targets;
  state.jobs = jobs;
  state.automations = automations;
  state.notifications = notifications;
  state.threatIntel = threatIntel;
  state.portfolio = portfolio;
  state.exposures = exposures;
  state.assetsByUrl = assetsByUrl;
  state.recentReports = recentReports;
  if (!state.selectedTargetId && targets.length) state.selectedTargetId = targets[0].id;
  if (!state.selectedJobId && jobs.length) state.selectedJobId = jobs[0].id;
  if (state.selectedTargetId && targets.some((item) => item.id === state.selectedTargetId)) await loadTargetIntel(state.selectedTargetId);
  else { state.selectedTargetReport = null; state.selectedTargetMonitoring = []; }
  if (state.selectedJobId && jobs.some((item) => item.id === state.selectedJobId)) await loadJobReport(state.selectedJobId);
  else state.selectedJobReport = null;
  state.lastRefresh = new Date().toISOString();
  renderAll();
}

async function refreshData() {
  if (state.loading) return;
  state.loading = true;
  try {
    await loadCoreData();
  } catch (error) {
    openDetail("Refresh failed", `<pre>${escapeHtml(error.message || error)}</pre>`);
  } finally {
    state.loading = false;
  }
}

async function createScan(payload) {
  el.scanHint.textContent = "Submitting scan request...";
  try {
    const response = await request("/targets/scan-or-create", { method: "POST", body: JSON.stringify(payload) });
    state.selectedTargetId = response.target.id;
    state.selectedJobId = response.job.id;
    el.scanHint.textContent = `Queued job #${response.job.id} for ${response.target.name}.`;
    await refreshData();
    setView("jobs");
  } catch (error) {
    el.scanHint.textContent = `Scan request failed: ${error.message || error}`;
  }
}

async function scanSelectedTarget() {
  if (!state.selectedTargetId) {
    el.scanHint.textContent = "Pick a target first.";
    return;
  }
  try {
    const response = await request(`/targets/${state.selectedTargetId}/scan`, {
      method: "POST",
      body: JSON.stringify({ kind: el.scanKind.value, priority: Number(el.scanPriority.value), max_retries: 2, trigger: "manual" }),
    });
    state.selectedJobId = response.job.id;
    el.scanHint.textContent = `Queued job #${response.job.id} for ${response.target.name}.`;
    await refreshData();
    setView("jobs");
  } catch (error) {
    el.scanHint.textContent = `Failed to queue selected target: ${error.message || error}`;
  }
}

async function runTargetIntelligence() {
  if (!state.selectedTargetId) {
    el.scanHint.textContent = "Pick a target first.";
    return;
  }
  try {
    await request(`/targets/${state.selectedTargetId}/intelligence`, { method: "POST", body: JSON.stringify({ sources: [] }) });
    el.scanHint.textContent = "Intelligence refresh queued.";
    await refreshData();
  } catch (error) {
    el.scanHint.textContent = `Intelligence refresh failed: ${error.message || error}`;
  }
}

async function requeueJob(jobId) {
  try { await request(`/jobs/${jobId}/requeue`, { method: "POST" }); await refreshData(); }
  catch (error) { openDetail("Requeue failed", `<pre>${escapeHtml(error.message || error)}</pre>`); }
}

async function deleteJob(jobId) {
  if (!window.confirm("Delete this job and its report artifacts?")) return;
  try {
    await request(`/jobs/${jobId}`, { method: "DELETE" });
    if (state.selectedJobId === jobId) { state.selectedJobId = null; state.selectedJobReport = null; }
    await refreshData();
  } catch (error) {
    openDetail("Delete failed", `<pre>${escapeHtml(error.message || error)}</pre>`);
  }
}

async function runToolExecution() {
  el.toolHint.textContent = "Running tool adapter...";
  try {
    const payload = await request("/tools/execute", {
      method: "POST",
      body: JSON.stringify({ tool: el.toolName.value, target: el.toolTarget.value.trim(), timeout_seconds: Number(el.toolTimeout.value || 20) }),
    });
    state.toolExecution = payload.result || payload;
    el.toolHint.textContent = `Completed ${state.toolExecution.tool} using ${executionBadge(state.toolExecution).label}.`;
    renderTools();
  } catch (error) {
    el.toolHint.textContent = `Tool execution failed: ${error.message || error}`;
  }
}

async function maintenance(path, message, resetSelection = false) {
  try {
    await request(path, { method: "POST" });
    if (resetSelection) {
      state.selectedTargetId = null;
      state.selectedTargetReport = null;
      state.selectedTargetMonitoring = [];
      state.selectedJobId = null;
      state.selectedJobReport = null;
    }
    el.scanHint.textContent = message;
    await refreshData();
  } catch (error) {
    openDetail("Maintenance action failed", `<pre>${escapeHtml(error.message || error)}</pre>`);
  }
}

function bindEvents() {
  el.navButtons.forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  el.saveApiBase.addEventListener("click", async () => { state.apiBase = el.apiBaseInput.value.trim().replace(/\/$/, ""); localStorage.setItem("asm_api_base", state.apiBase); await refreshData(); });
  el.refreshAll.addEventListener("click", refreshData);
  el.scanCreate.addEventListener("click", async () => {
    const name = el.scanInput.value.trim();
    if (!name) { el.scanHint.textContent = "Enter a domain, IP, or CIDR first."; return; }
    await createScan({ name, scope: el.scanScope.value.trim() || null, target_type: el.scanTargetType.value, business_criticality: Number(el.scanCriticality.value), priority: Number(el.scanPriority.value), scan_kind: el.scanKind.value, trigger: "manual", max_retries: 2 });
  });
  el.useSelectedTarget.addEventListener("click", () => {
    const selected = state.targets.find((item) => item.id === state.selectedTargetId);
    if (!selected) { el.scanHint.textContent = "Select a target from inventory first."; return; }
    el.scanInput.value = selected.name;
    el.scanScope.value = selected.scope || "";
    el.scanTargetType.value = selected.target_type || "domain";
    el.scanCriticality.value = String(selected.business_criticality || 3);
    el.scanPriority.value = String(selected.priority || 3);
    el.scanHint.textContent = `Loaded ${selected.name} into the intake form.`;
  });
  el.quickScan.addEventListener("click", async () => {
    if (state.selectedTargetId) { await scanSelectedTarget(); return; }
    const name = el.scanInput.value.trim();
    if (!name) { el.scanHint.textContent = "Select a target or enter a new one first."; return; }
    await createScan({ name, scope: el.scanScope.value.trim() || null, target_type: el.scanTargetType.value, business_criticality: Number(el.scanCriticality.value), priority: Number(el.scanPriority.value), scan_kind: el.scanKind.value, trigger: "manual", max_retries: 2 });
  });
  el.runIntel.addEventListener("click", runTargetIntelligence);
  el.scanSelected.addEventListener("click", scanSelectedTarget);
  el.targetSearchBtn.addEventListener("click", () => {
    const q = el.targetSearch.value.trim().toLowerCase();
    renderTargets(q ? state.targets.filter((item) => item.name.toLowerCase().includes(q) || (item.scope || "").toLowerCase().includes(q)) : state.targets);
  });
  el.targetSearch.addEventListener("keydown", (event) => { if (event.key === "Enter") el.targetSearchBtn.click(); });
  el.jobSearchBtn.addEventListener("click", () => {
    const q = el.jobSearch.value.trim().toLowerCase();
    renderJobs(q ? state.jobs.filter((job) => (state.targets.find((item) => item.id === job.target_id)?.name || "").toLowerCase().includes(q)) : state.jobs);
  });
  el.jobSearch.addEventListener("keydown", (event) => { if (event.key === "Enter") el.jobSearchBtn.click(); });
  el.runTool.addEventListener("click", runToolExecution);
  el.toolName.addEventListener("change", renderTools);
  el.recoverJobs.addEventListener("click", async () => maintenance("/jobs/recover", "Recovered stale jobs."));
  el.cleanupJobs.addEventListener("click", async () => maintenance("/jobs/cleanup-empty", "Cleaned up stale jobs and empty test targets."));
  el.resetData.addEventListener("click", async () => { if (window.confirm("Reset all runtime data? This clears targets, jobs, findings, nodes, snapshots, and notifications.")) await maintenance("/system/reset-data", "Platform runtime data reset.", true); });
  el.closeDetail.addEventListener("click", () => el.detailDialog.close());
}

async function init() {
  bindEvents();
  setView(state.view);
  await refreshData();
  window.setInterval(refreshData, 12000);
}

init();
