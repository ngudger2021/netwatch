/* Kali NetWatch front end. Vanilla JS; every value from the API is inserted via esc() or textContent. */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return isNaN(d) ? esc(iso) : d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
  }
  function ago(iso) {
    if (!iso) return "never";
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return Math.round(s) + "s ago";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }
  function sevBadge(sev) {
    return `<span class="badge badge-sev-${esc(sev)} rounded-pill text-uppercase">${esc(sev)}</span>`;
  }
  function statusDot(status) {
    return `<span class="dot dot-${esc(status)}"></span>${esc(status)}`;
  }
  function riskBar(score) {
    const color = score >= 60 ? "var(--nw-bad)" : score >= 25 ? "var(--nw-warn)" : "var(--nw-ok)";
    return `<div class="d-flex align-items-center gap-2"><span class="mono">${esc(score)}</span>` +
      `<div class="risk-bar flex-grow-1"><span style="width:${Math.min(100, score)}%;background:${color}"></span></div></div>`;
  }

  async function api(method, url, body) {
    const opts = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") {
      opts.headers["X-CSRF-Token"] = csrf();
    }
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 401 && !url.includes("/auth/")) { window.location.href = "/login"; throw new Error("signed out"); }
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      let msg = (data && data.detail) || `Request failed (${res.status})`;
      if (typeof msg !== "string") msg = JSON.stringify(msg);
      throw new Error(msg);
    }
    return data;
  }

  function toast(message, kind = "info") {
    const area = $("#toast-area");
    if (!area) return;
    const el = document.createElement("div");
    el.className = "toast show align-items-center mb-2";
    el.setAttribute("role", "status");
    const color = kind === "error" ? "var(--nw-bad)" : kind === "ok" ? "var(--nw-ok)" : "var(--nw-accent)";
    el.innerHTML = `<div class="d-flex"><div class="toast-body" style="border-left:3px solid ${color}">${esc(message)}</div></div>`;
    area.appendChild(el);
    setTimeout(() => el.remove(), 4500);
  }

  function pager(state, total, onChange) {
    const pages = Math.max(1, Math.ceil(total / state.size));
    return {
      prev: () => { if (state.page > 1) { state.page--; onChange(); } },
      next: () => { if (state.page < pages) { state.page++; onChange(); } },
      label: `Page ${state.page} of ${pages} · ${total} total`,
    };
  }

  /* ---------- login -------------------------------------------------- */
  function initLogin() {
    const form = $("#login-form");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = $("#login-error");
      err.classList.add("d-none");
      try {
        await api("POST", "/api/v1/auth/login", { username: $("#username").value.trim(), password: $("#password").value });
        window.location.href = "/";
      } catch (ex) {
        err.textContent = ex.message;
        err.classList.remove("d-none");
        $("#password").value = "";
      }
    });
  }

  /* ---------- dashboard ---------------------------------------------- */
  const charts = {};
  function chart(id, config) {
    if (!window.Chart) return;
    if (charts[id]) { charts[id].destroy(); }
    const ctx = document.getElementById(id);
    if (!ctx) return;
    charts[id] = new Chart(ctx, config);
  }
  const chartColors = { text: "#8ea0b8", grid: "rgba(142,160,184,.12)", accent: "#22d3ee", ok: "#34d399", bad: "#f87171", warn: "#fbbf24", indigo: "#6366f1" };
  function baseOpts(extra = {}) {
    return Object.assign({
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: chartColors.text } } },
      scales: {
        x: { ticks: { color: chartColors.text, maxRotation: 0, autoSkip: true }, grid: { color: chartColors.grid } },
        y: { ticks: { color: chartColors.text }, grid: { color: chartColors.grid }, beginAtZero: true },
      },
    }, extra);
  }

  async function initDashboard() {
    const data = await api("GET", "/api/v1/dashboard");
    renderDashboard(data);
    const sys = await api("GET", "/api/v1/system").catch(() => null);
    if (sys) renderPi(sys);
    setInterval(async () => {
      try { renderDashboard(await api("GET", "/api/v1/dashboard")); } catch (_) {}
      try { renderPi(await api("GET", "/api/v1/system")); } catch (_) {}
    }, 30000);
  }

  function statCard(label, value, cls = "", sub = "") {
    return `<div class="col-6 col-md-4 col-xl-2"><div class="card nw-card stat-card h-100 ${cls}"><div class="card-body">
      <div class="stat-label">${esc(label)}</div><div class="stat-value mt-1">${esc(value)}</div>
      ${sub ? `<div class="small text-secondary mt-1">${esc(sub)}</div>` : ""}</div></div></div>`;
  }

  function renderDashboard(data) {
    const s = data.stats;
    $("#stat-cards").innerHTML = [
      statCard("Discovered devices", s.devices_total, "", `${s.unknown} unknown`),
      statCard("Online", s.online, "good", `${s.offline} offline`),
      statCard("Offline", s.offline, s.offline ? "bad" : "", "absent for threshold scans"),
      statCard("New (24h)", s.new_devices_24h),
      statCard("Open ports", s.open_ports),
      statCard("High-risk devices", s.high_risk_devices, s.high_risk_devices ? "bad" : "good", "risk ≥ 60"),
      statCard("Open findings", s.open_findings, s.open_findings ? "bad" : "good"),
      statCard("Last good scan", ago(s.last_successful_scan), "", fmtTime(s.last_successful_scan)),
    ].join("");

    const run = s.scan_running;
    $("#scan-status").innerHTML = run
      ? `<span class="badge text-bg-info">Scan #${esc(run.id)} ${esc(run.status)}</span> ${esc(run.progress || "")}`
      : `Scanner idle`;

    const nx = s.next_scheduled || {};
    $("#next-scan").innerHTML = nx.enabled === false ? "Scheduling is disabled."
      : `Next discovery: ${esc(nx.quick && nx.quick.startsWith ? fmtTime(nx.quick) : nx.quick || "—")}<br>` +
        `Next standard scan: ${esc(nx.standard && nx.standard.startsWith ? fmtTime(nx.standard) : nx.standard || "—")}`;

    const c = data.charts;
    const oo = c.online_vs_offline;
    chart("chart-status", { type: "doughnut", data: { labels: ["Online", "Offline", "Unknown"],
      datasets: [{ data: [oo.online, oo.offline, oo.unknown], backgroundColor: [chartColors.ok, chartColors.bad, "#475569"], borderWidth: 0 }] },
      options: { plugins: { legend: { labels: { color: chartColors.text } } }, maintainAspectRatio: false, responsive: true } });
    chart("chart-subnets", { type: "bar", data: { labels: c.devices_per_subnet.map((r) => r.cidr),
      datasets: [{ label: "Devices", data: c.devices_per_subnet.map((r) => r.devices), backgroundColor: chartColors.accent },
                 { label: "Online", data: c.devices_per_subnet.map((r) => r.online || 0), backgroundColor: chartColors.indigo }] },
      options: baseOpts() });
    chart("chart-availability", { type: "line", data: { labels: c.availability.map((r) => r.hour.replace("T", " ") + ":00"),
      datasets: [{ label: "Availability %", fill: true, tension: .3, borderColor: chartColors.accent, backgroundColor: "rgba(34,211,238,.12)",
        data: c.availability.map((r) => r.total ? Math.round(1000 * r.online / r.total) / 10 : 0) }] },
      options: baseOpts({ scales: { x: { ticks: { color: chartColors.text, maxTicksLimit: 12 }, grid: { color: chartColors.grid } },
        y: { min: 0, max: 100, ticks: { color: chartColors.text }, grid: { color: chartColors.grid } } } }) });
    chart("chart-discoveries", { type: "bar", data: { labels: c.new_discoveries.map((r) => r.day),
      datasets: [{ label: "New devices", data: c.new_discoveries.map((r) => r.count), backgroundColor: chartColors.ok }] }, options: baseOpts() });
    chart("chart-ports", { type: "bar", data: { labels: c.ports_by_service.map((r) => r.service),
      datasets: [{ label: "Open ports", data: c.ports_by_service.map((r) => r.count), backgroundColor: chartColors.indigo }] },
      options: baseOpts({ indexAxis: "y" }) });
    const sevOrder = ["critical", "high", "medium", "low", "info"];
    const sevCount = (k) => (c.findings_by_severity.find((r) => r.severity === k) || {}).count || 0;
    const sevColor = { critical: "#ef4444", high: chartColors.bad, medium: chartColors.warn, low: chartColors.indigo, info: "#64748b" };
    chart("chart-findings", { type: "doughnut", data: { labels: sevOrder, datasets: [{ data: sevOrder.map(sevCount),
      backgroundColor: sevOrder.map((k) => sevColor[k]), borderWidth: 0 }] },
      options: { maintainAspectRatio: false, responsive: true, plugins: { legend: { labels: { color: chartColors.text } } } } });

    $("#activity").innerHTML = data.activity.length
      ? data.activity.map((e) => `<li><span class="text-secondary">${esc(fmtTime(e.created_at))}</span> ${sevBadge(e.severity)}<br>${esc(e.title)}</li>`).join("")
      : `<li class="text-secondary">No events yet.</li>`;
    $$("[data-quick-scan]").forEach((btn) => btn.addEventListener("click", () => startScan({ profile: btn.dataset.quickScan })));
  }

  function renderPi(sys) {
    const bar = (p) => `<div class="risk-bar"><span style="width:${Math.min(100, p)}%;background:var(--nw-accent)"></span></div>`;
    $("#pi-metrics").innerHTML = `
      <div class="mb-2">CPU ${esc(Math.round(sys.cpu_percent))}% ${bar(sys.cpu_percent)}</div>
      <div class="mb-2">Memory ${esc(sys.memory.percent)}% (${esc(sys.memory.used_mb)} / ${esc(sys.memory.total_mb)} MB) ${bar(sys.memory.percent)}</div>
      <div class="mb-2">SD card ${esc(sys.disk.percent)}% (${esc(sys.disk.used_gb)} / ${esc(sys.disk.total_gb)} GB) ${bar(sys.disk.percent)}</div>
      <div class="mb-2">Temperature ${sys.temperature_c == null ? "n/a" : esc(sys.temperature_c) + " °C"}</div>
      <div class="text-secondary">Uptime ${esc(Math.floor(sys.uptime_seconds / 3600))} h · DB ${esc(sys.database.size_mb)} MB</div>`;
  }

  async function startScan(body) {
    try {
      const res = await api("POST", "/api/v1/scans", body);
      toast(`Scan #${res.job_id} queued`, "ok");
      if (document.body.dataset.page === "scans") loadScans();
    } catch (ex) { toast(ex.message, "error"); }
  }

  /* ---------- devices ------------------------------------------------- */
  const devState = { page: 1, size: 50, sort: "ip", order: "asc" };
  async function initDevices() {
    const nets = await api("GET", "/api/v1/networks");
    $("#f-network").insertAdjacentHTML("beforeend", nets.map((n) => `<option>${esc(n.cidr)}</option>`).join(""));
    const reload = () => loadDevices();
    ["#f-network", "#f-status", "#f-type", "#f-risk"].forEach((s) => $(s).addEventListener("change", () => { devState.page = 1; reload(); }));
    let t;
    ["#f-q", "#f-vendor"].forEach((s) => $(s).addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { devState.page = 1; reload(); }, 300); }));
    $("#f-reset").addEventListener("click", () => setTimeout(() => { devState.page = 1; reload(); }, 0));
    $$("#devices-table th[data-sort]").forEach((th) => th.addEventListener("click", () => {
      if (devState.sort === th.dataset.sort) devState.order = devState.order === "asc" ? "desc" : "asc";
      else { devState.sort = th.dataset.sort; devState.order = "asc"; }
      reload();
    }));
    $("#prev-page").addEventListener("click", () => { if (devState.page > 1) { devState.page--; reload(); } });
    $("#next-page").addEventListener("click", () => { devState.page++; reload(); });
    loadDevices();
  }

  async function loadDevices() {
    const p = new URLSearchParams({ page: devState.page, size: devState.size, sort: devState.sort, order: devState.order });
    const map = { "#f-q": "q", "#f-network": "network", "#f-status": "status", "#f-type": "device_type", "#f-risk": "risk", "#f-vendor": "vendor" };
    Object.entries(map).forEach(([sel, key]) => { const v = $(sel).value.trim(); if (v) p.set(key, v); });
    const data = await api("GET", "/api/v1/devices?" + p.toString());
    const rows = data.items.map((d) => `
      <tr class="clickable-row" data-id="${esc(d.id)}">
        <td class="mono">${esc(d.ip)}</td>
        <td>${esc(d.custom_name || d.hostname || "—")}${d.custom_name && d.hostname ? `<div class="small text-secondary">${esc(d.hostname)}</div>` : ""}</td>
        <td class="mono d-none d-md-table-cell">${esc(d.mac || "—")}${d.mac_randomized ? ' <span class="badge text-bg-secondary">random</span>' : ""}</td>
        <td class="d-none d-lg-table-cell">${esc(d.vendor || "—")}</td>
        <td class="d-none d-xl-table-cell mono">${esc(d.network || "—")}</td>
        <td class="d-none d-md-table-cell">${esc(d.device_type)}</td>
        <td>${statusDot(d.status)}</td>
        <td class="d-none d-lg-table-cell small">${esc(fmtTime(d.last_seen))}</td>
        <td>${esc(d.port_count)}</td>
        <td style="min-width:120px">${riskBar(d.risk_score)}</td>
        <td>${d.trusted ? '<span class="badge text-bg-success">trusted</span>' : ""}</td>
      </tr>`).join("");
    $("#devices-body").innerHTML = rows || `<tr><td colspan="11" class="text-secondary p-4">No devices match these filters.</td></tr>`;
    $$("#devices-body tr[data-id]").forEach((tr) => tr.addEventListener("click", () => { window.location.href = "/devices/" + tr.dataset.id; }));
    const pg = pager(devState, data.total, loadDevices);
    $("#devices-count").textContent = pg.label;
  }

  /* ---------- device detail ------------------------------------------ */
  async function initDevice() {
    const id = $("#device").dataset.id;
    await renderDevice(id);
  }

  async function renderDevice(id) {
    const d = await api("GET", `/api/v1/devices/${id}`);
    const admin = window.__nwUser && window.__nwUser.role === "admin";
    const dis = admin ? "" : "disabled";
    const ports = d.ports.length ? d.ports.map((p) => `<tr><td class="mono">${esc(p.port)}/${esc(p.protocol)}</td>
      <td>${esc(p.service || "—")}</td><td>${esc([p.product, p.version].filter(Boolean).join(" ") || "—")}</td>
      <td>${p.state === "open" ? '<span class="badge text-bg-success">open</span>' : '<span class="badge text-bg-secondary">closed</span>'}</td>
      <td class="small text-secondary">${esc(fmtTime(p.last_seen))}</td></tr>`).join("")
      : `<tr><td colspan="5" class="text-secondary">No port data yet (quick scans do not probe ports).</td></tr>`;
    const findings = d.findings.filter((f) => f.status !== "resolved").length ? d.findings.filter((f) => f.status !== "resolved").map((f) => `
      <div class="border-bottom py-2"><div>${sevBadge(f.severity)} <strong>${esc(f.title)}</strong> <span class="text-secondary small">port ${esc(f.port || "—")} · ${esc(f.status)}</span></div>
      <div class="small">${esc(f.description)}</div><div class="small text-secondary mono">${esc(f.evidence)}</div>
      <div class="small"><em>Remediation:</em> ${esc(f.remediation)}</div></div>`).join("")
      : `<p class="text-secondary small mb-0">No open findings from the current evidence.</p>`;
    const explain = d.risk_explanation.length
      ? `<ul class="small mb-0">${d.risk_explanation.map((r) => `<li>${esc(r.title)} (port ${esc(r.port)}): +${esc(r.weight)}</li>`).join("")}</ul>`
      : `<p class="small text-secondary mb-0">Score is 0: no weighted findings. Informational items carry no weight.</p>`;
    const addrs = d.ip_history.map((a) => `<tr><td class="mono">${esc(a.ip)}</td><td class="small">${esc(fmtTime(a.first_seen))}</td><td class="small">${esc(fmtTime(a.last_seen))}</td></tr>`).join("")
      || `<tr><td colspan="3" class="text-secondary">No address history.</td></tr>`;
    const events = d.events.map((e) => `<li><span class="text-secondary">${esc(fmtTime(e.created_at))}</span> ${sevBadge(e.severity)} ${esc(e.title)}</li>`).join("")
      || `<li class="text-secondary">No changes recorded.</li>`;
    const scans = d.scans.slice(0, 20).map((s) => `<tr><td>#${esc(s.job_id)}</td><td>${esc(s.profile)}</td><td>${esc(s.status)}</td><td class="mono">${esc(s.ip)}</td><td class="small">${esc(fmtTime(s.observed_at))}</td></tr>`).join("")
      || `<tr><td colspan="5" class="text-secondary">No scans yet.</td></tr>`;
    const av = d.availability.percent == null ? "no data" : `${d.availability.percent}% online over ${d.availability.days} days`;

    $("#device").innerHTML = `
      <div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mb-3">
        <div><a href="/devices" class="small">← Inventory</a>
          <h1 class="h3 mb-0">${esc(d.custom_name || d.hostname || d.ip)}</h1>
          <div class="text-secondary small">${statusDot(d.status)} · last seen ${esc(ago(d.last_seen))} · first seen ${esc(fmtTime(d.first_seen))}</div></div>
        <div class="text-end"><div class="stat-label">Risk score</div><div class="stat-value">${esc(d.risk_score)}</div>
          <div class="small text-secondary">${esc(d.risk_level)} · ${d.trusted ? "trusted" : "not trusted"}</div></div>
      </div>
      <div class="row g-3">
        <div class="col-12 col-xl-4"><div class="card nw-card"><div class="card-body">
          <h2 class="h6 text-secondary">Identification</h2>
          <dl class="row small mb-0">
            <dt class="col-5">IP address</dt><dd class="col-7 mono">${esc(d.ip)}</dd>
            <dt class="col-5">Network</dt><dd class="col-7 mono">${esc(d.network || "—")}</dd>
            <dt class="col-5">MAC</dt><dd class="col-7 mono">${esc(d.mac || "unknown")} ${d.mac_randomized ? "(randomised)" : ""}</dd>
            <dt class="col-5">Manufacturer</dt><dd class="col-7">${esc(d.vendor || "—")}</dd>
            <dt class="col-5">Hostname</dt><dd class="col-7">${esc(d.hostname || "—")}</dd>
            <dt class="col-5">Device type</dt><dd class="col-7">${esc(d.device_type)}</dd>
            <dt class="col-5">Availability</dt><dd class="col-7">${esc(av)}</dd>
          </dl></div></div>
          <div class="card nw-card mt-3"><div class="card-body">
            <h2 class="h6 text-secondary">Your details</h2>
            <form id="dev-form">
              <div class="mb-2"><label class="form-label small" for="d-name">Device name</label>
                <input class="form-control form-control-sm" id="d-name" maxlength="64" value="${esc(d.custom_name)}" ${dis}></div>
              <div class="mb-2"><label class="form-label small" for="d-desc">Description</label>
                <input class="form-control form-control-sm" id="d-desc" maxlength="200" value="${esc(d.description)}" ${dis}></div>
              <div class="mb-2"><label class="form-label small" for="d-type">Device type</label>
                <select class="form-select form-select-sm" id="d-type" ${dis}>
                  ${["unknown","router","server","workstation","media","camera","printer","smart-home","server-mgmt","single-board"].map((t) => `<option ${t === d.device_type ? "selected" : ""}>${t}</option>`).join("")}
                </select></div>
              <div class="mb-2"><label class="form-label small" for="d-notes">Notes</label>
                <textarea class="form-control form-control-sm" id="d-notes" rows="3" maxlength="4000" ${dis}>${esc(d.notes)}</textarea></div>
              <div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="d-trusted" ${d.trusted ? "checked" : ""} ${dis}>
                <label class="form-check-label small" for="d-trusted">Trusted device (findings still shown and still scored)</label></div>
              ${admin ? '<button class="btn btn-sm btn-primary" type="submit">Save</button>' : '<p class="small text-secondary mb-0">Administrator role required to edit.</p>'}
            </form></div></div>
        </div>
        <div class="col-12 col-xl-8">
          <div class="card nw-card mb-3"><div class="card-body"><h2 class="h6 text-secondary">Security findings &amp; risk explanation</h2>
            ${findings}<hr class="my-2"><div class="small text-secondary mb-1">Score = sum of weights of open findings (capped at 100):</div>${explain}</div></div>
          <div class="card nw-card mb-3"><div class="card-body"><h2 class="h6 text-secondary">Open ports &amp; services</h2>
            <div class="table-responsive"><table class="table table-dark table-sm nw-table mb-0"><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>State</th><th>Last seen</th></tr></thead><tbody>${ports}</tbody></table></div></div></div>
          <div class="row g-3">
            <div class="col-12 col-lg-6"><div class="card nw-card h-100"><div class="card-body"><h2 class="h6 text-secondary">IP address history</h2>
              <table class="table table-dark table-sm nw-table mb-0"><thead><tr><th>IP</th><th>First</th><th>Last</th></tr></thead><tbody>${addrs}</tbody></table></div></div></div>
            <div class="col-12 col-lg-6"><div class="card nw-card h-100"><div class="card-body"><h2 class="h6 text-secondary">Previous changes</h2>
              <ul class="list-unstyled small mb-0 activity-list">${events}</ul></div></div></div>
            <div class="col-12"><div class="card nw-card"><div class="card-body"><h2 class="h6 text-secondary">Scan history</h2>
              <div class="table-responsive"><table class="table table-dark table-sm nw-table mb-0"><thead><tr><th>Scan</th><th>Profile</th><th>Status</th><th>IP</th><th>When</th></tr></thead><tbody>${scans}</tbody></table></div></div></div></div>
          </div>
        </div>
      </div>`;

    if (admin) {
      $("#dev-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        try {
          await api("PATCH", `/api/v1/devices/${id}`, {
            custom_name: $("#d-name").value, description: $("#d-desc").value, device_type: $("#d-type").value,
            notes: $("#d-notes").value, trusted: $("#d-trusted").checked });
          toast("Device saved", "ok");
          await renderDevice(id);
        } catch (ex) { toast(ex.message, "error"); }
      });
    }
  }

  /* ---------- scans --------------------------------------------------- */
  const scanState = { page: 1, size: 25 };
  async function initScans() {
    const nets = await api("GET", "/api/v1/networks");
    $("#s-networks").innerHTML = nets.filter((n) => n.enabled).map((n) => `<option value="${esc(n.cidr)}">${esc(n.cidr)} ${esc(n.name)}</option>`).join("");
    const form = $("#scan-form");
    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const profile = $("#s-profile").value;
        const body = { profile, networks: Array.from($("#s-networks").selectedOptions).map((o) => o.value),
          targets: $("#s-targets").value.split(",").map((s) => s.trim()).filter(Boolean),
          ports: profile === "detailed" || profile === "custom" ? $("#s-ports").value.trim() : "",
          service_detection: $("#s-svc").checked };
        if ($("#s-conc").value) body.concurrency = parseInt($("#s-conc").value, 10);
        if ($("#s-timeout").value) body.host_timeout = parseInt($("#s-timeout").value, 10);
        await startScan(body);
      });
    }
    if (!(window.__nwUser && window.__nwUser.role === "admin")) {
      $$(".admin-only").forEach((el) => el.classList.add("d-none"));
      $$(".non-admin-only").forEach((el) => el.classList.remove("d-none"));
    }
    $("#scan-prev").addEventListener("click", () => { if (scanState.page > 1) { scanState.page--; loadScans(); } });
    $("#scan-next").addEventListener("click", () => { scanState.page++; loadScans(); });
    loadScans();
    setInterval(loadScans, 8000);
  }

  async function loadScans() {
    if (!$("#scans-body")) return;
    const data = await api("GET", `/api/v1/scans?page=${scanState.page}&size=${scanState.size}`);
    const admin = window.__nwUser && window.__nwUser.role === "admin";
    $("#scans-body").innerHTML = data.items.map((j) => {
      const live = j.status === "queued" || j.status === "running";
      const cancel = live && admin ? `<button class="btn btn-sm btn-outline-danger" data-cancel="${esc(j.id)}">Cancel</button>` : "";
      return `<tr class="clickable-row" data-job="${esc(j.id)}">
        <td>#${esc(j.id)}</td><td>${esc(j.profile)}</td><td>${esc(j.trigger)}</td>
        <td>${live ? '<span class="badge text-bg-info">' + esc(j.status) + "</span>" : esc(j.status)}</td>
        <td class="small">${esc(j.progress)}</td><td>${esc(j.hosts_up)}</td>
        <td class="small">${esc(fmtTime(j.started_at || j.created_at))}</td>
        <td class="small">${j.duration_seconds ? esc(Math.round(j.duration_seconds)) + "s" : "—"}</td>
        <td>${cancel}</td></tr>`;
    }).join("") || `<tr><td colspan="9" class="text-secondary p-3">No scans yet.</td></tr>`;
    $$("#scans-body [data-cancel]").forEach((b) => b.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      try { await api("POST", `/api/v1/scans/${b.dataset.cancel}/cancel`); toast("Cancellation requested", "ok"); loadScans(); }
      catch (ex) { toast(ex.message, "error"); }
    }));
    $$("#scans-body tr[data-job]").forEach((tr) => tr.addEventListener("click", () => showScan(tr.dataset.job)));
  }

  async function showScan(id) {
    const d = await api("GET", `/api/v1/scans/${id}`);
    $("#scan-detail").classList.remove("d-none");
    $("#scan-detail-title").textContent = `Scan #${d.id} · ${d.profile} · ${d.status}`;
    $("#scan-detail-log").textContent = (d.log || "(no log lines)") + (d.error ? `\nError: ${d.error}` : "");
    $("#scan-detail-units").innerHTML = d.units.map((u) => `<li class="mono">${esc(u.cidr)} — ${esc(u.status)} ${u.hosts_up ? "(" + esc(u.hosts_up) + " up)" : ""} ${esc(u.error)}</li>`).join("")
      || `<li class="text-secondary">No network units recorded yet.</li>`;
  }

  /* ---------- findings ------------------------------------------------ */
  const findState = { page: 1, size: 50 };
  async function initFindings() {
    ["#fs-status", "#fs-sev"].forEach((s) => $(s).addEventListener("change", () => { findState.page = 1; loadFindings(); }));
    $("#fn-prev").addEventListener("click", () => { if (findState.page > 1) { findState.page--; loadFindings(); } });
    $("#fn-next").addEventListener("click", () => { findState.page++; loadFindings(); });
    loadFindings();
  }
  async function loadFindings() {
    const p = new URLSearchParams({ page: findState.page, size: findState.size, status: $("#fs-status").value });
    if ($("#fs-sev").value) p.set("severity", $("#fs-sev").value);
    const data = await api("GET", "/api/v1/findings?" + p.toString());
    const admin = window.__nwUser && window.__nwUser.role === "admin";
    $("#findings-body").innerHTML = data.items.map((f) => `<tr>
        <td>${sevBadge(f.severity)}</td>
        <td><strong>${esc(f.title)}</strong><div class="small text-secondary">${esc(f.description)}</div></td>
        <td><a href="/devices/${esc(f.device_id)}">${esc(f.hostname || f.ip)}</a><div class="small mono">${esc(f.ip)}</div>${f.trusted ? '<span class="badge text-bg-success">trusted</span>' : ""}</td>
        <td class="mono">${esc(f.port || "—")}</td>
        <td class="small mono">${esc(f.evidence)}</td>
        <td class="small">${esc(f.remediation)}</td>
        <td>${esc(f.status)}</td>
        <td class="small">${esc(fmtTime(f.first_detected))}</td>
        <td>${admin && f.status === "open" ? `<button class="btn btn-sm btn-outline-secondary" data-ack="${esc(f.id)}">Acknowledge</button>` : ""}</td>
      </tr>`).join("") || `<tr><td colspan="9" class="text-secondary p-3">No findings match.</td></tr>`;
    $$("#findings-body [data-ack]").forEach((b) => b.addEventListener("click", async () => {
      try { await api("POST", `/api/v1/findings/${b.dataset.ack}/acknowledge`); toast("Acknowledged; still visible and scored", "ok"); loadFindings(); }
      catch (ex) { toast(ex.message, "error"); }
    }));
  }

  /* ---------- events -------------------------------------------------- */
  const evState = { page: 1, size: 50 };
  async function initEvents() {
    ["#ev-sev"].forEach((s) => $(s).addEventListener("change", () => { evState.page = 1; loadEvents(); }));
    let t; $("#ev-type").addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { evState.page = 1; loadEvents(); }, 300); });
    $("#ev-prev").addEventListener("click", () => { if (evState.page > 1) { evState.page--; loadEvents(); } });
    $("#ev-next").addEventListener("click", () => { evState.page++; loadEvents(); });
    loadEvents();
  }
  async function loadEvents() {
    const p = new URLSearchParams({ page: evState.page, size: evState.size });
    if ($("#ev-type").value.trim()) p.set("type", $("#ev-type").value.trim());
    if ($("#ev-sev").value) p.set("severity", $("#ev-sev").value);
    const data = await api("GET", "/api/v1/events?" + p.toString());
    $("#events-body").innerHTML = data.items.map((e) => `<tr>
        <td class="small">${esc(fmtTime(e.created_at))}</td><td class="mono small">${esc(e.type)}</td>
        <td>${sevBadge(e.severity)}</td><td>${e.device_id ? `<a href="/devices/${esc(e.device_id)}">${esc(e.title)}</a>` : esc(e.title)}</td></tr>`).join("")
      || `<tr><td colspan="4" class="text-secondary p-3">No events.</td></tr>`;
  }

  /* ---------- settings ------------------------------------------------ */
  async function initSettings() {
    const admin = window.__nwUser && window.__nwUser.role === "admin";
    if (!admin) $$(".admin-only").forEach((el) => el.classList.add("d-none"));
    async function load() {
      const s = await api("GET", "/api/v1/settings");
      $("#networks-body").innerHTML = s.networks.map((n) => `<tr>
          <td class="mono">${esc(n.cidr)}</td><td>${esc(n.name)}</td><td>${n.is_local ? "yes" : "routed"}</td>
          <td>${esc(n.devices)} <span class="text-secondary small">(${esc(n.online || 0)} online)</span></td>
          <td>${admin ? `<div class="form-check form-switch"><input class="form-check-input" type="checkbox" data-net="${esc(n.id)}" ${n.enabled ? "checked" : ""}></div>` : (n.enabled ? "yes" : "no")}</td></tr>`).join("");
      $$("#networks-body [data-net]").forEach((cb) => cb.addEventListener("change", async () => {
        try { await api("PATCH", `/api/v1/networks/${cb.dataset.net}`, { enabled: cb.checked }); toast("Network updated", "ok"); }
        catch (ex) { toast(ex.message, "error"); load(); }
      }));
      $("#schedule-info").innerHTML = `
        <dt class="col-7">Discovery (quick) every</dt><dd class="col-5">${esc(s.schedule.discovery_minutes)} min</dd>
        <dt class="col-7">Standard scan every</dt><dd class="col-5">${esc(s.schedule.standard_hours)} h</dd>
        <dt class="col-7">Daily summary every</dt><dd class="col-5">${esc(s.schedule.summary_hours)} h</dd>
        <dt class="col-7">Offline after absent scans</dt><dd class="col-5">${esc(s.change.offline_threshold)}</dd>
        <dt class="col-7">History retention</dt><dd class="col-5">${esc(s.retention_days)} days</dd>
        <dt class="col-7">Privileged discovery</dt><dd class="col-5">${s.scanning.privileged ? "enabled" : "off (unprivileged nmap)"}</dd>`;
      $("#telegram-info").innerHTML = s.telegram.enabled
        ? (s.telegram.credentials_present ? '<span class="badge text-bg-success">enabled</span> credentials present in environment' : '<span class="badge text-bg-warning">enabled but credentials missing</span>')
        : '<span class="badge text-bg-secondary">disabled</span> set telegram.enabled = true and the environment variables to use it';
      $("#rules-body").innerHTML = s.alert_rules.map((r) => `<tr data-rule="${esc(r.event_type)}">
          <td class="mono small">${esc(r.event_type)}</td>
          <td><input type="checkbox" class="form-check-input" data-f="enabled" ${r.enabled ? "checked" : ""} ${admin ? "" : "disabled"}></td>
          <td><select class="form-select form-select-sm" data-f="min_severity" ${admin ? "" : "disabled"}>
            ${["info","low","medium","high","critical"].map((v) => `<option ${v === r.min_severity ? "selected" : ""}>${v}</option>`).join("")}</select></td>
          <td><input type="number" min="0" max="86400" class="form-control form-control-sm" data-f="cooldown_seconds" value="${esc(r.cooldown_seconds)}" ${admin ? "" : "disabled"}></td></tr>`).join("");
    }
    await load();
    const n = await api("GET", "/api/v1/notifications?size=20");
    $("#notif-list").innerHTML = n.items.map((x) => `<li><span class="text-secondary">${esc(fmtTime(x.created_at))}</span> ${esc(x.event_type)} —
      <strong>${esc(x.status)}</strong> ${esc(x.message.slice(0, 120))}${x.error ? ` <span class="text-danger">${esc(x.error)}</span>` : ""}</li>`).join("")
      || `<li class="text-secondary">No notifications sent.</li>`;
    if (admin) {
      const au = await api("GET", "/api/v1/audit?size=30");
      $("#audit-list").innerHTML = au.items.map((x) => `<li><span class="text-secondary">${esc(fmtTime(x.created_at))}</span> ${esc(x.username || "—")} <strong>${esc(x.action)}</strong> ${esc(x.target)}</li>`).join("");
      $("#network-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        try { await api("POST", "/api/v1/networks", { cidr: $("#n-cidr").value.trim(), name: $("#n-name").value.trim() }); toast("Network added", "ok"); $("#n-cidr").value = ""; $("#n-name").value = ""; load(); }
        catch (ex) { toast(ex.message, "error"); }
      });
      $("#rules-save").addEventListener("click", async () => {
        const rules = $$("#rules-body tr[data-rule]").map((tr) => ({
          event_type: tr.dataset.rule,
          enabled: tr.querySelector('[data-f="enabled"]').checked,
          min_severity: tr.querySelector('[data-f="min_severity"]').value,
          cooldown_seconds: parseInt(tr.querySelector('[data-f="cooldown_seconds"]').value || "0", 10),
        }));
        try { await api("PUT", "/api/v1/settings/alert-rules", { rules }); toast("Alert rules saved", "ok"); }
        catch (ex) { toast(ex.message, "error"); }
      });
      $("#telegram-test").addEventListener("click", async () => {
        try { await api("POST", "/api/v1/notifications/test"); toast("Test message sent", "ok"); }
        catch (ex) { toast(ex.message, "error"); }
      });
    }
  }

  /* ---------- system -------------------------------------------------- */
  async function initSystem() {
    const load = async () => {
      const s = await api("GET", "/api/v1/system");
      const card = (label, value, sub) => `<div class="col-6 col-lg-3"><div class="card nw-card h-100"><div class="card-body">
        <div class="stat-label">${esc(label)}</div><div class="stat-value">${esc(value)}</div><div class="small text-secondary">${esc(sub || "")}</div></div></div></div>`;
      $("#sys-cards").innerHTML = [
        card("CPU", Math.round(s.cpu_percent) + "%", "load " + s.load_average.map((x) => x.toFixed(2)).join(" ")),
        card("Memory", s.memory.percent + "%", `${s.memory.used_mb} / ${s.memory.total_mb} MB`),
        card("SD card", s.disk.percent + "%", `${s.disk.used_gb} / ${s.disk.total_gb} GB`),
        card("Temperature", s.temperature_c == null ? "n/a" : s.temperature_c + " °C", "uptime " + Math.floor(s.uptime_seconds / 3600) + " h"),
        card("Database", s.database.size_mb + " MB", "SQLite WAL"),
        card("Last scan", s.last_scan_duration_seconds == null ? "—" : Math.round(s.last_scan_duration_seconds) + " s", "duration"),
        card("Scheduler", s.scheduler_healthy ? "healthy" : "not running", "heartbeat " + ago(s.scheduler_heartbeat)),
      ].join("");
      $("#sys-ifaces").innerHTML = s.interfaces.map((i) => `<tr><td class="mono">${esc(i.name)}</td>
        <td>${i.up ? '<span class="badge text-bg-success">up</span>' : '<span class="badge text-bg-danger">down</span>'}</td>
        <td class="mono small">${esc(i.ipv4.join(", ") || "—")}</td><td class="small">${esc(i.speed_mbps ? i.speed_mbps + " Mb/s" : "")}</td></tr>`).join("");
      $("#sys-services").innerHTML = Object.entries(s.services || {}).map(([u, st]) => `<tr><td class="mono small">${esc(u)}</td>
        <td>${st === "active" ? '<span class="badge text-bg-success">active</span>' : `<span class="badge text-bg-warning">${esc(st)}</span>`}</td></tr>`).join("");
      $("#sys-load").textContent = s.load_average.map((x) => x.toFixed(2)).join(" / ");
    };
    await load();
    setInterval(() => load().catch(() => {}), 10000);
  }

  /* ---------- bootstrap ----------------------------------------------- */
  document.addEventListener("DOMContentLoaded", async () => {
    const page = document.body.dataset.page;
    const logout = $("#logout-btn");
    if (logout) logout.addEventListener("click", async () => {
      try { await api("POST", "/api/v1/auth/logout"); } catch (_) {}
      window.location.href = "/login";
    });
    if (page !== "login") {
      try {
        const me = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
        if (me.status === 401) { window.location.href = "/login"; return; }
        window.__nwUser = await me.json();
        // Keep the CSRF token in sync with the session (it is per session on the server).
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta && window.__nwUser.csrf_token) meta.content = window.__nwUser.csrf_token;
        if (window.__nwUser.role !== "admin") $$(".admin-only").forEach((el) => el.classList.add("d-none"));
      } catch (_) { return; }
    }
    const handlers = {
      login: initLogin, dashboard: initDashboard, devices: initDevices, device: initDevice,
      scans: initScans, findings: initFindings, events: initEvents, settings: initSettings, system: initSystem,
    };
    if (handlers[page]) {
      try { await handlers[page](); }
      catch (ex) { toast(ex.message || "Failed to load page", "error"); }
    }
  });
})();
