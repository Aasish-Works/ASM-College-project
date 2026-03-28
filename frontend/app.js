const state = {
  apiBase: localStorage.getItem("asm_api_base") || "http://127.0.0.1:8000",
  dashboard: null,
  targets: [],
  jobs: [],
  selectedTarget: null,
  selectedReport: null,
  pollHandle: null,
};

const elements = {
  apiBaseInput: document.getElementById("apiBaseInput"),
  saveApiBase: document.getElementById("saveApiBase"),
  refreshAll: document.getElementById("refreshAll"),
  quickScan: document.getElementById("quickScan"),
  scanInput: document.getElementById("scanInput"),
  scanScope: document.getElementById("scanScope"),
  scanTargetType: document.getElementById("scanTargetType"),
  scanCriticality: document.getElementById("scanCriticality"),
  scanPriority: document.getElementById("scanPriority"),
  scanCreate: document.getElementById("scanCreate"),
  scanHint: document.getElementById("scanHint"),
  useSelectedTarget: document.getElementById("useSelectedTarget"),
  overviewCards: document.getElementById("overviewCards"),
  trendChart: document.getElementById("trendChart"),
  riskHeatmap: document.getElementById("riskHeatmap"),
  targetSearch: document.getElementById("targetSearch"),
  targetSearchBtn: document.getElementById("targetSearchBtn"),
  targetTable: document.getElementById("targetTable"),
  selectedTargetTitle: document.getElementById("selectedTargetTitle"),
  selectedTargetSubtitle: document.getElementById("selectedTargetSubtitle"),
  targetSummary: document.getElementById("targetSummary"),
  graphCanvas: document.getElementById("graphCanvas"),
  attackPaths: document.getElementById("attackPaths"),
  assetList: document.getElementById("assetList"),
  exposureList: document.getElementById("exposureList"),
  identityList: document.getElementById("identityList"),
  vulnerabilityList: document.getElementById("vulnerabilityList"),
  monitoringList: document.getElementById("monitoringList"),
  rawStreamList: document.getElementById("rawStreamList"),
  runIntel: document.getElementById("runIntel"),
  scanSelected: document.getElementById("scanSelected"),
  recoverJobs: document.getElementById("recoverJobs"),
  cleanupJobs: document.getElementById("cleanupJobs"),
  jobSearch: document.getElementById("jobSearch"),
  jobSearchBtn: document.getElementById("jobSearchBtn"),
  jobTable: document.getElementById("jobTable"),
  reportBody: document.getElementById("reportBody"),
  nodeList: document.getElementById("nodeList"),
  automationList: document.getElementById("automationList"),
  threatIntelList: document.getElementById("threatIntelList"),
  notificationList: document.getElementById("notificationList"),
  detailDialog: document.getElementById("detailDialog"),
  detailTitle: document.getElementById("detailTitle"),
  detailContent: document.getElementById("detailContent"),
  closeDetail: document.getElementById("closeDetail"),
};

elements.apiBaseInput.value = state.apiBase;

function endpoint(path) {
  return `${state.apiBase}${path}`;
}

async function request(path, options = {}) {
  const response = await fetch(endpoint(path), {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  return response.json();
}

function setHint(message, tone = "info") {
  elements.scanHint.textContent = message;
  elements.scanHint.dataset.tone = tone;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function h(value) {
  return escapeHtml(value);
}

function safeJson(value) {
  return escapeHtml(JSON.stringify(value ?? {}, null, 2));
}

function badge(label, tone = "info") {
  return `<span class="badge ${tone}">${h(label)}</span>`;
}

function severityTone(value) {
  const severity = String(value || "").toLowerCase();
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "success";
}

function statusTone(value) {
  const status = String(value || "").toLowerCase();
  if (status === "completed" || status === "resolved") return "success";
  if (status === "running" || status === "queued" || status === "pending" || status === "retry_pending") return "warning";
  if (status === "failed") return "danger";
  return "info";
}

function fmtDate(value) {
  if (!value) return "N/A";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return String(value);
  }
}

function fmtNumber(value, digits = 2) {
  const parsed = Number(value ?? 0);
  if (!Number.isFinite(parsed)) return digits === 4 ? "0.0000" : "0.00";
  return parsed.toFixed(digits);
}

function joinFacts(parts) {
  return parts
    .filter(Boolean)
    .map((part) => h(part))
    .join(" • ");
}

function isFactsOnlyFinding(item) {
  return Boolean(item?.facts_only || item?.details?.evidence_mode === "facts_only" || (!item?.cve && item?.source === "exposure_engine"));
}

function findingEvidenceParts(item) {
  const details = item?.details || {};
  const parts = [];
  if (details.asset) parts.push(`asset ${details.asset}`);
  if (details.protocol && (details.port ?? item?.port)) {
    parts.push(`${details.protocol}/${details.port ?? item?.port}`);
  } else if (item?.port) {
    parts.push(`port ${item.port}`);
  }
  if (details.provider) parts.push(`provider ${details.provider}`);
  if (details.status_code) parts.push(`HTTP ${details.status_code}`);
  if (details.path) parts.push(`path ${details.path}`);
  if (details.classification) parts.push(`class ${details.classification}`);
  if (details.title) parts.push(`title ${details.title}`);
  return parts;
}

function renderFindingCard(item, options = {}) {
  const { includeSourceInMeta = true } = options;
  const factsOnly = isFactsOnlyFinding(item);
  const details = item?.details || {};
  let primary = "";
  let secondary = "";
  let evidence = "";

  if (factsOnly) {
    primary = joinFacts([item.host || details.host || "observed asset", item.exposure || details.classification || "surface", includeSourceInMeta ? `source ${item.source || "scanner"}` : ""]);
    secondary = h(item.description || details.observation || "Observed exposure without CVE-based scoring.");
    const evidenceParts = findingEvidenceParts(item);
    if (details.observation && details.observation !== item.description) {
      evidenceParts.unshift(details.observation);
    }
    evidence = joinFacts(evidenceParts);
  } else {
    primary = joinFacts([
      item.cve || "No CVE",
      `CVSS ${fmtNumber(item.cvss, 1)}`,
      item.epss_available ? `EPSS ${fmtNumber(item.epss, 4)}` : "EPSS unavailable",
      `risk ${fmtNumber(item.risk_score, 2)}`,
      includeSourceInMeta ? item.source : "",
    ]);
    secondary = joinFacts([item.host || "N/A", item.threat_context, item.exploit_maturity]);
  }

  return `
    <article class="list-item">
      <header><strong>${h(item.title)}</strong>${badge(item.severity, severityTone(item.severity))}</header>
      ${primary ? `<div class="list-meta">${primary}</div>` : ""}
      ${secondary ? `<div class="list-meta">${secondary}</div>` : ""}
      ${evidence ? `<div class="list-meta">${evidence}</div>` : ""}
    </article>
  `;
}

function openDetail(title, content) {
  elements.detailTitle.textContent = title;
  elements.detailContent.innerHTML = content;
  elements.detailDialog.showModal();
}

function renderOverviewCards(dashboard) {
  const stats = dashboard?.stats || {};
  const cards = [
    {
      title: "Targets",
      value: stats.targets || 0,
      meta: "Registered domains, IPs, and CIDRs under monitoring.",
      detail: "Targets are the top-level scope objects. Each can produce assets, vulnerabilities, identity exposures, snapshots, and scheduled monitoring jobs.",
    },
    {
      title: "Assets",
      value: stats.assets || 0,
      meta: "Normalized assets across external, internal, cloud, API, and third-party surfaces.",
      detail: "Assets are deduplicated and correlated nodes in the attack-surface graph. They include domains, IPs, services, applications, buckets, SaaS edges, and identities.",
    },
    {
      title: "Vulnerabilities",
      value: stats.vulnerabilities || 0,
      meta: "Risk-ranked findings enriched with CVSS, EPSS, exploit maturity, and context.",
      detail: "Risk is calculated from CVSS, EPSS, exploit maturity, exposure context, asset criticality, and threat context. The system retains lifecycle, SLA, exceptions, and tickets.",
    },
    {
      title: "Open jobs",
      value: stats.open_jobs || 0,
      meta: "Queued or running scans in the distributed orchestrator.",
      detail: "Jobs move through scheduled or event-driven orchestration. Workers record stage logs, per-tool evidence, retries, and heartbeat-backed execution ownership.",
    },
  ];
  elements.overviewCards.innerHTML = cards
    .map(
      (card) => `
        <article class="stat-card" data-detail="${card.detail}">
          <div class="stat-label">${card.title}</div>
          <div class="stat-value">${card.value}</div>
          <div class="stat-meta">${card.meta}</div>
        </article>
      `
    )
    .join("");
  [...elements.overviewCards.querySelectorAll(".stat-card")].forEach((card, index) => {
    card.addEventListener("click", () => openDetail(cards[index].title, `<p>${cards[index].detail}</p>`));
  });
}

function renderTrendChart(items) {
  if (!items?.length) {
    elements.trendChart.innerHTML = `<div class="list-meta">No trend data yet.</div>`;
    return;
  }
  const max = Math.max(...items.flatMap((item) => [item.assets || 0, item.vulnerabilities || 0, item.scans || 0]), 1);
  const rows = [
    { label: "Assets", color: "linear-gradient(90deg, #7ce2c9, #28c5a5)", key: "assets" },
    { label: "Vulnerabilities", color: "linear-gradient(90deg, #ff6f91, #ff9f7f)", key: "vulnerabilities" },
    { label: "Scans", color: "linear-gradient(90deg, #70a7ff, #90c3ff)", key: "scans" },
  ];
  elements.trendChart.innerHTML = rows
    .map((row) => {
      const latest = items[items.length - 1]?.[row.key] || 0;
      return `
        <div class="line-row">
          <div>${row.label}</div>
          <div class="line-track"><div class="line-fill" style="width:${(latest / max) * 100}%; background:${row.color}"></div></div>
          <div>${latest}</div>
        </div>
      `;
    })
    .join("");
}

function renderHeatmap(heatmap) {
  const severities = ["critical", "high", "medium", "low", "info"];
  const exposures = ["external", "api", "cloud", "internal"];
  const cells = [`<div class="axis">Severity \\ Exposure</div>`, ...exposures.map((value) => `<div class="axis">${value}</div>`)];
  severities.forEach((severity) => {
    cells.push(`<div class="axis">${severity}</div>`);
    exposures.forEach((exposure) => {
      const count = heatmap?.[severity]?.[exposure] || 0;
      cells.push(`<div>${count}</div>`);
    });
  });
  elements.riskHeatmap.innerHTML = cells.join("");
}

function renderTargetTable(targets) {
  elements.targetTable.innerHTML = targets
    .map(
      (target) => `
        <tr data-target-id="${target.id}">
          <td><strong>${h(target.name)}</strong></td>
          <td>${h(target.target_type)}</td>
          <td>${target.asset_count}</td>
          <td>${target.vulnerability_count}</td>
          <td>${target.exposure_count}</td>
          <td>${target.identity_count}</td>
          <td>${badge(`C${target.business_criticality}`, "warning")}</td>
          <td>
            ${target.latest_job_status ? badge(target.latest_job_status, statusTone(target.latest_job_status)) : "N/A"}
            ${target.latest_job_error ? `<div class="list-meta">${h(target.latest_job_error)}</div>` : ""}
          </td>
        </tr>
      `
    )
    .join("");
  [...elements.targetTable.querySelectorAll("tr")].forEach((row) => {
    row.addEventListener("click", () => loadTargetIntel(Number(row.dataset.targetId)));
  });
}

function renderSummary(summary) {
  const cards = [
    ["Assets", summary.asset_count || 0],
    ["Findings", summary.vulnerability_count || 0],
    ["CVE-backed", summary.cve_backed_count || 0],
    ["Facts-only", summary.facts_only_count || 0],
    ["Identity exposures", summary.identity_exposure_count || 0],
    ["Average scored risk", summary.average_risk || 0],
    ["CVE average EPSS", summary.average_epss || 0],
    ["Jobs", summary.job_count || 0],
  ];
  elements.targetSummary.innerHTML = cards
    .map(([label, value]) => `<div class="summary-card"><div class="stat-label">${label}</div><div class="stat-value">${value}</div></div>`)
    .join("");
}

function renderList(container, items, formatter, emptyMessage) {
  if (!items?.length) {
    container.innerHTML = `<div class="list-meta">${emptyMessage}</div>`;
    return;
  }
  container.innerHTML = items.map(formatter).join("");
}

function renderGraph(graph) {
  if (!graph?.nodes?.length) {
    elements.graphCanvas.innerHTML = `<text x="30" y="40">No graph data available.</text>`;
    return;
  }
  const width = 800;
  const height = 420;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) / 2 - 70;
  const positions = new Map();
  graph.nodes.forEach((node, index) => {
    const angle = (Math.PI * 2 * index) / graph.nodes.length;
    positions.set(node.id, {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
    });
  });
  const edges = graph.edges
    .map((edge) => {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) return "";
      return `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"></line>`;
    })
    .join("");
  const nodes = graph.nodes
    .map((node) => {
      const point = positions.get(node.id);
      const color = node.risk_score >= 70 ? "#ff6f91" : node.risk_score >= 40 ? "#ffc85b" : "#7ce2c9";
      return `
        <g>
          <circle cx="${point.x}" cy="${point.y}" r="16" style="fill:${color}"></circle>
          <text x="${point.x + 22}" y="${point.y + 4}">${h((node.label || "").slice(0, 28))}</text>
        </g>
      `;
    })
    .join("");
  elements.graphCanvas.innerHTML = `${edges}${nodes}`;
}

function renderTargetIntel(report, monitoring = []) {
  state.selectedTarget = report;
  elements.selectedTargetTitle.textContent = report.target.name;
  elements.selectedTargetSubtitle.textContent = `${report.target.target_type} • Criticality ${report.target.business_criticality} • ${report.summary.asset_count} assets • ${report.summary.vulnerability_count} findings`;
  renderSummary(report.summary);
  renderGraph(report.graph);

  renderList(
    elements.attackPaths,
    report.attack_paths,
    (item) => `
      <article class="attack-card">
        <div class="attack-score">Score ${item.score}</div>
        <strong>${h(item.summary)}</strong>
        <div class="list-meta">Entry: ${h(item.entry.label)} | Goal: ${h(item.goal.label)}</div>
      </article>
    `,
    "No attack paths generated yet."
  );

  renderList(
    elements.assetList,
    report.assets,
    (asset) => `
      <article class="list-item">
        <header><strong>${h(asset.value)}</strong>${badge(asset.classification, "info")}</header>
        <div class="list-meta">${h(asset.kind)} • exposure: ${h(asset.exposure)} • risk: ${asset.risk_score}</div>
      </article>
    `,
    "No assets for this target."
  );

  renderList(
    elements.exposureList,
    report.vulnerabilities.filter((item) => item.source === "exposure_engine" || item.facts_only),
    (item) => renderFindingCard(item, { includeSourceInMeta: true }),
    "No exposure findings."
  );

  renderList(
    elements.identityList,
    report.identity_exposures,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.principal)}</strong>${badge(item.privilege_level, "warning")}</header>
        <div class="list-meta">${h(item.kind)} • ${h(item.secret_type || "unknown secret")} • ${h(item.source)}</div>
        <div class="list-meta">${h(item.evidence)}</div>
      </article>
    `,
    "No identity exposure observed."
  );

  renderList(
    elements.vulnerabilityList,
    report.vulnerabilities,
    (item) => renderFindingCard(item, { includeSourceInMeta: true }),
    "No vulnerabilities for this target."
  );

  renderList(
    elements.monitoringList,
    monitoring,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.name)}</strong>${badge(item.enabled ? "enabled" : "disabled", item.enabled ? "success" : "warning")}</header>
        <div class="list-meta">${h(item.mode)} • next run ${h(fmtDate(item.next_run_at))}</div>
      </article>
    `,
    "No monitoring rules yet."
  );

  renderList(
    elements.rawStreamList,
    report.raw_asset_streams,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.asset_key)}</strong>${badge(item.source, "info")}</header>
        <div class="list-meta">confidence ${item.confidence} • trusted: ${item.trusted ? "yes" : "no"}</div>
      </article>
    `,
    "No raw asset streams stored yet."
  );
}

function renderJobs(jobs) {
  elements.jobTable.innerHTML = jobs
    .map(
      (job) => `
        <tr data-job-id="${job.id}">
          <td>${h(job.target_name || job.target_id)}</td>
          <td>${h(job.kind)}</td>
          <td>${badge(job.status, statusTone(job.status))}${job.last_error ? `<div class="list-meta">${h(job.last_error)}</div>` : ""}</td>
          <td>${job.priority}</td>
          <td>${job.progress}%</td>
          <td>${job.attempts}/${job.max_retries}</td>
          <td>${h(fmtDate(job.created_at))}</td>
          <td>
            <div class="table-actions">
              <button class="ghost job-details" data-job-id="${job.id}">Open report</button>
              ${job.status === "retry_pending" || job.status === "failed" ? `<button class="ghost job-requeue" data-job-id="${job.id}">Requeue</button>` : ""}
              ${job.status !== "running" ? `<button class="ghost job-delete" data-job-id="${job.id}">Delete</button>` : ""}
            </div>
          </td>
        </tr>
      `
    )
    .join("");
  [...elements.jobTable.querySelectorAll(".job-details")].forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      loadJobReport(Number(button.dataset.jobId));
    });
  });
  [...elements.jobTable.querySelectorAll(".job-requeue")].forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      try {
        await request(`/jobs/${button.dataset.jobId}/requeue`, { method: "POST" });
        setHint(`Job #${button.dataset.jobId} requeued.`, "success");
        await loadDashboard();
      } catch (error) {
        setHint(`Requeue failed: ${error.message}`, "danger");
      }
    });
  });
  [...elements.jobTable.querySelectorAll(".job-delete")].forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      try {
        await request(`/jobs/${button.dataset.jobId}`, { method: "DELETE" });
        setHint(`Job #${button.dataset.jobId} deleted.`, "success");
        await loadDashboard();
      } catch (error) {
        setHint(`Delete failed: ${error.message}`, "danger");
      }
    });
  });
  [...elements.jobTable.querySelectorAll("tr[data-job-id]")].forEach((row) => {
    row.addEventListener("click", () => loadJobReport(Number(row.dataset.jobId)));
  });
}

function renderReport(report) {
  state.selectedReport = report;
  const stages = report.stages
    .map(
      (stage) => `
        <div class="list-item">
          <header><strong>${h(stage.name)}</strong>${badge(stage.status, statusTone(stage.status))}</header>
          <div class="list-meta">${stage.duration_ms} ms • start ${h(fmtDate(stage.started_at))} • finish ${h(fmtDate(stage.finished_at))}</div>
          <div class="list-meta">${h(stage.logs || "")}</div>
        </div>
      `
    )
    .join("");
  const results = report.results
    .slice(0, 20)
    .map(
      (result) => `
        <div class="list-item">
          <header><strong>${h(result.tool)}</strong>${badge(result.fallback_used ? "fallback" : "native", result.fallback_used ? "warning" : "success")}</header>
          <div class="list-meta">${h(result.stage)} • exit ${result.exit_code}</div>
          ${result.artifact?.command?.length ? `<div class="list-meta">Command: ${h(result.artifact.command.join(" "))}</div>` : ""}
          ${result.stdout_sample ? `<pre>${h(result.stdout_sample)}</pre>` : ""}
          ${result.stderr_sample ? `<pre>${h(result.stderr_sample)}</pre>` : ""}
        </div>
      `
    )
    .join("");
  const topFindings = report.vulnerabilities
    .slice(0, 20)
    .map((item) => renderFindingCard(item, { includeSourceInMeta: true }))
    .join("");
  elements.reportBody.innerHTML = `
    <section class="report-section">
      <h3>${h(report.target.name)} • Job #${report.job.id}</h3>
      <p>Status: ${h(report.job.status)} | ${report.summary.asset_count} scan assets | ${report.summary.inventory_asset_count || report.summary.asset_count} inventory assets | ${report.summary.vulnerability_count} findings | ${report.summary.cve_backed_count || 0} CVE-backed | ${report.summary.facts_only_count || 0} facts-only | CVE average EPSS ${report.summary.average_epss}</p>
      ${report.summary.last_error ? `<p class="list-meta">Last error: ${h(report.summary.last_error)}</p>` : ""}
      <div class="report-summary-grid">
        <div class="summary-card"><div class="stat-label">Stages</div><div class="stat-value">${report.summary.stage_count}</div></div>
        <div class="summary-card"><div class="stat-label">Tool results</div><div class="stat-value">${report.summary.tool_count}</div></div>
        <div class="summary-card"><div class="stat-label">Fallback runs</div><div class="stat-value">${report.summary.fallback_count}</div></div>
        <div class="summary-card"><div class="stat-label">SLA overdue</div><div class="stat-value">${report.summary.overdue_count}</div></div>
      </div>
    </section>
    <section class="report-section">
      <h3>Stage timeline</h3>
      ${stages || `<div class="list-meta">No stage data.</div>`}
    </section>
    <section class="report-section">
      <h3>Top findings</h3>
      ${topFindings || `<div class="list-meta">No findings for this job.</div>`}
    </section>
    <section class="report-section">
      <h3>Tool execution</h3>
      ${results || `<div class="list-meta">No tool result records.</div>`}
    </section>
    <section class="report-section">
      <h3>Risk summary</h3>
      <pre>${safeJson(report.summary)}</pre>
    </section>
  `;
}

function renderOperations(dashboard, automations, threatIntel, notifications) {
  renderList(
    elements.nodeList,
    dashboard.nodes,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.node_name)}</strong>${badge(item.status, statusTone(item.status))}</header>
        <div class="list-meta">load ${item.current_load}/${item.capacity} • cpu ${item.cpu_percent}% • mem ${item.memory_percent}% • disk ${item.disk_percent}%</div>
      </article>
    `,
    "No nodes have reported heartbeat yet."
  );
  renderList(
    elements.automationList,
    automations,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.name)}</strong>${badge(item.enabled ? "enabled" : "disabled", item.enabled ? "success" : "warning")}</header>
        <div class="list-meta">${h(item.event)} -> ${h(item.action)}</div>
      </article>
    `,
    "No automation rules configured."
  );
  renderList(
    elements.threatIntelList,
    threatIntel.items || [],
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.cve)}</strong>${badge(item.kev ? "KEV" : "intel", item.kev ? "danger" : "info")}</header>
        <div class="list-meta">CVSS ${item.cvss_v3} • EPSS ${item.epss} • ${h(item.exploit_maturity)}</div>
      </article>
    `,
    "Threat intelligence records will appear once CVE-backed findings are stored."
  );
  renderList(
    elements.notificationList,
    notifications,
    (item) => `
      <article class="list-item">
        <header><strong>${h(item.subject)}</strong>${badge(item.severity, severityTone(item.severity))}</header>
        <div class="list-meta">${h(item.channel)} -> ${h(item.destination)}</div>
      </article>
    `,
    "No notifications queued."
  );
}

async function loadDashboard() {
  const [dashboard, targets, jobs, automations, threatIntel, notifications] = await Promise.all([
    request("/dashboard"),
    request("/targets"),
    request("/jobs"),
    request("/automation/rules"),
    request("/threat-intel"),
    request("/notifications"),
  ]);
  state.dashboard = dashboard;
  state.targets = targets;
  state.jobs = jobs.map((job) => ({
    ...job,
    target_name: targets.find((target) => target.id === job.target_id)?.name || `Target ${job.target_id}`,
  }));
  renderOverviewCards(dashboard);
  renderTrendChart(dashboard.trends || []);
  renderHeatmap(dashboard.risk_heatmap || {});
  renderTargetTable(state.targets);
  renderJobs(state.jobs);
  renderOperations(dashboard, automations, threatIntel, notifications);
  if (!state.selectedTarget && state.targets.length) {
    await loadTargetIntel(state.targets[0].id);
  }
}

async function loadTargetIntel(targetId) {
  const [report, monitoring] = await Promise.all([
    request(`/targets/${targetId}/intel`),
    request(`/targets/${targetId}/monitoring`),
  ]);
  renderTargetIntel(report, monitoring.items || []);
}

async function loadJobReport(jobId, options = {}) {
  const { scroll = true } = options;
  const report = await request(`/reports/jobs/${jobId}`);
  renderReport(report);
  if (scroll) {
    document.getElementById("reporting").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

async function pollData() {
  try {
    await loadDashboard();
    if (state.selectedTarget?.target?.id) {
      await loadTargetIntel(state.selectedTarget.target.id);
    }
    if (state.selectedReport?.job?.id) {
      await loadJobReport(state.selectedReport.job.id, { scroll: false });
    }
  } catch (error) {
    setHint(`Background refresh failed: ${error.message}`, "warning");
  }
}

async function submitScan() {
  const name = elements.scanInput.value.trim();
  if (!name) {
    setHint("Enter a domain, IP, or CIDR first.", "danger");
    return;
  }
  setHint("Queueing scan job...", "info");
  try {
    const payload = {
      name,
      scope: elements.scanScope.value.trim() || null,
      target_type: elements.scanTargetType.value,
      business_criticality: Number(elements.scanCriticality.value),
      priority: Number(elements.scanPriority.value),
      scan_kind: "full_scan",
      trigger: "manual",
      max_retries: 2,
    };
    const response = await request("/targets/scan-or-create", { method: "POST", body: JSON.stringify(payload) });
    setHint(`Job #${response.job.id} queued for ${response.target.name}.`, "success");
    elements.scanInput.value = "";
    elements.scanScope.value = "";
    await loadDashboard();
    await loadTargetIntel(response.target.id);
  } catch (error) {
    setHint(`Scan request failed: ${error.message}`, "danger");
  }
}

async function searchTargets() {
  const value = elements.targetSearch.value.trim();
  if (!value) {
    renderTargetTable(state.targets);
    return;
  }
  try {
    const results = await request(`/targets/search?query=${encodeURIComponent(value)}`);
    renderTargetTable(results);
    setHint(`Found ${results.length} target(s).`, "success");
  } catch (error) {
    setHint(`Target search failed: ${error.message}`, "danger");
  }
}

async function searchJobs() {
  const value = elements.jobSearch.value.trim();
  if (!value) {
    renderJobs(state.jobs);
    return;
  }
  try {
    const results = await request(`/jobs/search?query=${encodeURIComponent(value)}`);
    const hydrated = results.map((job) => ({
      ...job,
      target_name: state.targets.find((target) => target.id === job.target_id)?.name || `Target ${job.target_id}`,
    }));
    renderJobs(hydrated);
    setHint(`Found ${hydrated.length} job(s).`, "success");
  } catch (error) {
    setHint(`Job search failed: ${error.message}`, "danger");
  }
}

async function recoverJobs() {
  try {
    const response = await request("/jobs/recover", { method: "POST" });
    setHint(`Recovered ${response.recovered} stuck job(s).`, "success");
    await loadDashboard();
  } catch (error) {
    setHint(`Recovery failed: ${error.message}`, "danger");
  }
}

async function cleanupJobs() {
  try {
    const response = await request("/jobs/cleanup-empty", { method: "POST" });
    setHint(`Removed ${response.deleted_jobs} stale job(s) and ${response.deleted_targets} empty target(s).`, "success");
    await loadDashboard();
  } catch (error) {
    setHint(`Cleanup failed: ${error.message}`, "danger");
  }
}

async function refreshIntelForSelected() {
  if (!state.selectedTarget?.target?.id) {
    setHint("Select a target before requesting intelligence refresh.", "warning");
    return;
  }
  await request(`/targets/${state.selectedTarget.target.id}/intelligence`, {
    method: "POST",
    body: JSON.stringify({ sources: [] }),
  });
  setHint("Intelligence refresh queued.", "success");
  await loadDashboard();
}

async function quickScanSelected() {
  if (!state.selectedTarget?.target?.id) {
    setHint("Select a target before queuing a scan.", "warning");
    return;
  }
  const response = await request(`/targets/${state.selectedTarget.target.id}/scan`, {
    method: "POST",
    body: JSON.stringify({ kind: "full_scan", trigger: "manual", priority: 2, max_retries: 2 }),
  });
  setHint(`Scan queued: job #${response.job.id}`, "success");
  await loadDashboard();
}

function bindEvents() {
  elements.saveApiBase.addEventListener("click", () => {
    state.apiBase = elements.apiBaseInput.value.trim() || state.apiBase;
    localStorage.setItem("asm_api_base", state.apiBase);
    loadDashboard().catch((error) => setHint(`Failed to refresh: ${error.message}`, "danger"));
  });
  elements.refreshAll.addEventListener("click", () => loadDashboard().catch((error) => setHint(error.message, "danger")));
  elements.scanCreate.addEventListener("click", submitScan);
  elements.targetSearchBtn.addEventListener("click", searchTargets);
  elements.jobSearchBtn.addEventListener("click", searchJobs);
  elements.recoverJobs.addEventListener("click", recoverJobs);
  elements.cleanupJobs.addEventListener("click", cleanupJobs);
  elements.runIntel.addEventListener("click", () => refreshIntelForSelected().catch((error) => setHint(error.message, "danger")));
  elements.scanSelected.addEventListener("click", () => quickScanSelected().catch((error) => setHint(error.message, "danger")));
  elements.quickScan.addEventListener("click", () => quickScanSelected().catch((error) => setHint(error.message, "danger")));
  elements.scanInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitScan();
  });
  elements.targetSearch.addEventListener("keydown", (event) => {
    if (event.key === "Enter") searchTargets();
  });
  elements.jobSearch.addEventListener("keydown", (event) => {
    if (event.key === "Enter") searchJobs();
  });
  elements.useSelectedTarget.addEventListener("click", () => {
    if (!state.selectedTarget?.target) return;
    elements.scanInput.value = state.selectedTarget.target.name;
    elements.scanScope.value = state.selectedTarget.target.scope || "";
    elements.scanTargetType.value = state.selectedTarget.target.target_type || "domain";
    elements.scanCriticality.value = String(state.selectedTarget.target.business_criticality || 3);
    elements.scanPriority.value = String(state.selectedTarget.target.priority || 3);
  });
  elements.closeDetail.addEventListener("click", () => elements.detailDialog.close());
}

async function init() {
  bindEvents();
  try {
    await loadDashboard();
    setHint("Platform data loaded.", "success");
    if (!state.pollHandle) {
      state.pollHandle = window.setInterval(() => {
        if (document.visibilityState === "visible") {
          pollData();
        }
      }, 8000);
    }
  } catch (error) {
    setHint(`Unable to reach backend: ${error.message}`, "danger");
  }
}

init();
