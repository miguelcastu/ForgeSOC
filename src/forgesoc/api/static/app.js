const state = {
  stats: null,
  scenarios: [],
  eventCursors: [null],
  eventPage: 0,
  eventNext: null,
  alertCursors: [null],
  alertPage: 0,
  alertNext: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = (value) => String(value ?? "—").replace(/[&<>'"]/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
}[char]));

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.message || `Request failed (${response.status})`);
  return payload;
}

function toast(message, type = "success") {
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.textContent = message;
  $("#toasts").append(item);
  window.setTimeout(() => item.remove(), 4200);
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("es-ES", {
    dateStyle: "short", timeStyle: "medium", hour12: false,
  }).format(new Date(value));
}

function queryString(values) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") params.set(key, value);
  });
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

function switchView(name) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  const titles = { dashboard: "Security overview", events: "Event explorer", alerts: "Alert investigation", workshop: "Architecture & workshop" };
  $("#page-title").textContent = titles[name];
  window.location.hash = name;
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (name === "events") loadEvents(true);
  if (name === "alerts") loadAlerts(true);
}

async function checkHealth() {
  try {
    await api("/health/ready");
    $(".pulse").classList.add("online");
    $("#system-label").textContent = "All systems operational";
  } catch (error) {
    $(".pulse").classList.remove("online");
    $("#system-label").textContent = "Database unavailable";
    toast(error.message, "error");
  }
}

function populateFilterOptions(stats) {
  const typeSelect = $('#event-filters select[name="event_type"]');
  const sourceSelect = $('#event-filters select[name="source"]');
  const ruleSelect = $('#alert-filters select[name="rule_id"]');
  const keep = (select, values, label) => {
    const current = select.value;
    select.innerHTML = `<option value="">${label}</option>${values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("")}`;
    select.value = current;
  };
  keep(typeSelect, Object.keys(stats.events_by_type), "All types");
  keep(sourceSelect, Object.keys(stats.events_by_source), "All sources");
  keep(ruleSelect, Object.keys(stats.alerts_by_rule), "All rules");
}

function renderStats(stats) {
  state.stats = stats;
  $("#metric-events").textContent = stats.events.toLocaleString();
  $("#metric-alerts").textContent = stats.alerts.toLocaleString();
  $("#metric-sources").textContent = Object.keys(stats.events_by_source).length;
  $("#metric-rules").textContent = Object.keys(stats.alerts_by_rule).length;
  $("#nav-events").textContent = stats.events;
  $("#nav-alerts").textContent = stats.alerts;
  const high = stats.alerts_by_severity.high || 0;
  const critical = stats.alerts_by_severity.critical || 0;
  $("#high-count").textContent = high;
  $("#critical-count").textContent = critical;
  const score = Math.max(15, 100 - high * 12 - critical * 25);
  $("#posture-score").textContent = score;
  $("#posture-meter").style.width = `${score}%`;
  $("#posture-copy").textContent = critical ? "Critical findings require immediate investigation." : high ? "High-severity activity is ready for investigation." : "No critical findings in the current dataset.";
  populateFilterOptions(stats);
  renderEventChart(stats.events_by_type);
  renderSeverity(stats.alerts_by_severity, stats.alerts);
}

function renderEventChart(values) {
  const root = $("#event-chart");
  const entries = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 7);
  if (!entries.length) { root.innerHTML = '<div class="empty-state">Generate telemetry to populate this chart</div>'; return; }
  const max = Math.max(...entries.map(([, count]) => count));
  root.innerHTML = entries.map(([name, count]) => `<div class="bar-item"><b>${count}</b><i style="height:${Math.max(8, count / max * 125)}px"></i><span>${esc(name.replace("authentication.", "auth."))}</span></div>`).join("");
}

function renderSeverity(values, total) {
  const colors = { critical: "#ff3f57", high: "#ff6b64", medium: "#ffbd66", low: "#3ce6d2" };
  const entries = Object.entries(values);
  let offset = 0;
  const sections = entries.map(([name, count]) => {
    const start = total ? offset / total * 100 : 0; offset += count;
    const end = total ? offset / total * 100 : 0;
    return `${colors[name] || "#9c87ff"} ${start}% ${end}%`;
  });
  $("#severity-donut").style.background = sections.length ? `conic-gradient(${sections.join(",")})` : "var(--line)";
  $("#donut-total").innerHTML = `${total}<small>alerts</small>`;
  $("#severity-legend").innerHTML = entries.map(([name, count]) => `<div class="legend-row"><i style="background:${colors[name] || "#9c87ff"}"></i><span>${esc(name)}</span><b>${count}</b></div>`).join("") || '<span class="subline">No severity data</span>';
}

async function loadDashboard() {
  try {
    const [stats, alerts] = await Promise.all([api("/api/v1/stats"), api("/api/v1/alerts?limit=4")]);
    renderStats(stats);
    renderLatestAlerts(alerts.items);
    $("#last-update").textContent = `Updated ${new Date().toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" })}`;
  } catch (error) { toast(error.message, "error"); }
}

function renderLatestAlerts(items) {
  const root = $("#latest-alerts");
  if (!items.length) { root.innerHTML = '<div class="empty-state">No alerts detected. Launch a brute-force demo.</div>'; return; }
  root.innerHTML = items.map((alert) => `<div class="compact-alert" data-alert-id="${esc(alert.alert_id)}"><i></i><b>${esc(alert.title)}</b><span>${esc(alert.username)}</span><time>${formatDate(alert.timestamp)}</time><span class="badge ${esc(alert.severity)}">${esc(alert.severity)}</span></div>`).join("");
  $$('[data-alert-id]', root).forEach((item) => item.addEventListener("click", () => openAlert(item.dataset.alertId)));
}

function formValues(form) { return Object.fromEntries(new FormData(form).entries()); }

async function loadEvents(reset = false) {
  if (reset) { state.eventCursors = [null]; state.eventPage = 0; }
  const filters = formValues($("#event-filters"));
  const cursor = state.eventCursors[state.eventPage];
  $("#events-body").innerHTML = '<tr class="loading-row"><td colspan="7">Loading telemetry…</td></tr>';
  try {
    const page = await api(`/api/v1/events${queryString({ ...filters, limit: 30, cursor })}`);
    state.eventNext = page.next_cursor;
    renderEvents(page.items);
    $("#events-page").textContent = `Page ${state.eventPage + 1}`;
    $("#events-back").disabled = state.eventPage === 0;
    $("#events-next").disabled = !page.next_cursor;
    $("#event-result-label").textContent = `${page.items.length} events on this page`;
  } catch (error) { $("#events-body").innerHTML = `<tr class="loading-row"><td colspan="7">${esc(error.message)}</td></tr>`; }
}

function renderEvents(items) {
  const root = $("#events-body");
  if (!items.length) { root.innerHTML = '<tr class="loading-row"><td colspan="7">No events match these filters</td></tr>'; return; }
  root.innerHTML = items.map((event) => `<tr data-event-id="${esc(event.event_id)}"><td>${formatDate(event.timestamp)}<span class="subline">${esc(event.host)}</span></td><td><span class="event-type">${esc(event.event_type)}</span></td><td>${esc(event.username)}<span class="subline">${esc(event.event_id)}</span></td><td>${esc(event.source_ip)}</td><td>${esc(event.source)}</td><td><span class="badge ${esc(event.outcome)}">${esc(event.outcome || "n/a")}</span></td><td class="row-arrow">→</td></tr>`).join("");
  $$('[data-event-id]', root).forEach((row) => row.addEventListener("click", () => openEvent(row.dataset.eventId)));
}

async function loadAlerts(reset = false) {
  if (reset) { state.alertCursors = [null]; state.alertPage = 0; }
  const filters = formValues($("#alert-filters"));
  const cursor = state.alertCursors[state.alertPage];
  $("#alerts-grid").innerHTML = '<div class="empty-state">Loading findings…</div>';
  try {
    const page = await api(`/api/v1/alerts${queryString({ ...filters, limit: 20, cursor })}`);
    state.alertNext = page.next_cursor;
    renderAlerts(page.items);
    $("#alerts-page").textContent = `Page ${state.alertPage + 1}`;
    $("#alerts-back").disabled = state.alertPage === 0;
    $("#alerts-next").disabled = !page.next_cursor;
  } catch (error) { $("#alerts-grid").innerHTML = `<div class="empty-state">${esc(error.message)}</div>`; }
}

function renderAlerts(items) {
  const root = $("#alerts-grid");
  if (!items.length) { root.innerHTML = '<div class="empty-state">No alerts match these filters</div>'; return; }
  root.innerHTML = items.map((alert) => `<article class="alert-card" data-alert-id="${esc(alert.alert_id)}"><div class="alert-top"><span class="badge ${esc(alert.severity)}">${esc(alert.severity)}</span><time class="subline">${formatDate(alert.timestamp)}</time></div><h3>${esc(alert.title)}</h3><p>${esc(alert.reason)}</p><div class="alert-meta"><span>${esc(alert.rule_id)}</span><span>${alert.related_event_ids.length} evidence events</span><span>Investigate →</span></div></article>`).join("");
  $$('[data-alert-id]', root).forEach((item) => item.addEventListener("click", () => openAlert(item.dataset.alertId)));
}

function openDrawer(html) {
  $("#drawer-content").innerHTML = html;
  $("#detail-drawer").classList.add("open");
  $("#detail-drawer").setAttribute("aria-hidden", "false");
}

async function openEvent(id) {
  openDrawer('<div class="empty-state">Loading event…</div>');
  try {
    const event = await api(`/api/v1/events/${encodeURIComponent(id)}`);
    openDrawer(`<span class="eyebrow">EVENT DETAIL</span><h2 class="detail-title">${esc(event.event_type)}</h2><span class="badge ${esc(event.outcome)}">${esc(event.outcome || "n/a")}</span><div class="detail-grid"><div><small>Timestamp</small><b>${formatDate(event.timestamp)}</b></div><div><small>Event ID</small><b>${esc(event.event_id)}</b></div><div><small>Source</small><b>${esc(event.source)}</b></div><div><small>Source record</small><b>${esc(event.source_record_id)}</b></div><div><small>Username</small><b>${esc(event.username)}</b></div><div><small>Source IP</small><b>${esc(event.source_ip)}</b></div><div><small>Host</small><b>${esc(event.host)}</b></div><div><small>Schema</small><b>${esc(event.schema_version)}</b></div></div><span class="eyebrow">ATTRIBUTES</span><pre class="json-block">${esc(JSON.stringify(event.attributes, null, 2))}</pre>`);
  } catch (error) { openDrawer(`<div class="empty-state">${esc(error.message)}</div>`); }
}

async function openAlert(id) {
  openDrawer('<div class="empty-state">Loading investigation…</div>');
  try {
    const [alert, evidence] = await Promise.all([api(`/api/v1/alerts/${id}`), api(`/api/v1/alerts/${id}/events`)]);
    openDrawer(`<span class="eyebrow">ALERT INVESTIGATION</span><h2 class="detail-title">${esc(alert.title)}</h2><span class="badge ${esc(alert.severity)}">${esc(alert.severity)}</span><p class="detail-reason">${esc(alert.reason)}</p><div class="detail-grid"><div><small>Rule</small><b>${esc(alert.rule_id)}</b></div><div><small>Detected</small><b>${formatDate(alert.timestamp)}</b></div><div><small>Username</small><b>${esc(alert.username)}</b></div><div><small>Source IP</small><b>${esc(alert.source_ip)}</b></div><div><small>Alert ID</small><b>${esc(alert.alert_id)}</b></div><div><small>Evidence</small><b>${evidence.length} events</b></div></div><span class="eyebrow">ORDERED EVIDENCE</span><div class="evidence-list">${evidence.map((event, index) => `<div class="evidence-item" data-evidence-id="${esc(event.event_id)}"><b>${String(index + 1).padStart(2, "0")} · ${esc(event.event_type)} · ${esc(event.username)}</b><span>${formatDate(event.timestamp)} · ${esc(event.source_ip)} · ${esc(event.event_id)}</span></div>`).join("")}</div>`);
    $$('[data-evidence-id]', $("#drawer-content")).forEach((item) => item.addEventListener("click", () => openEvent(item.dataset.evidenceId)));
  } catch (error) { openDrawer(`<div class="empty-state">${esc(error.message)}</div>`); }
}

async function loadScenarios() {
  try {
    state.scenarios = await api("/api/v1/scenarios");
    const select = $("#scenario-select");
    select.innerHTML = state.scenarios.map((item) => `<option value="${esc(item.name)}">${esc(item.name)}</option>`).join("");
    select.value = "brute-force";
    updateScenarioDescription();
  } catch (error) { toast(error.message, "error"); }
}

function updateScenarioDescription() {
  const selected = state.scenarios.find((item) => item.name === $("#scenario-select").value);
  $("#scenario-description").textContent = selected?.description || "";
}

function modal(open) {
  $("#demo-modal").classList.toggle("open", open);
  $("#demo-modal").setAttribute("aria-hidden", String(!open));
}

async function seedScenario() {
  const button = $("#seed-button"); button.disabled = true; button.textContent = "Generating…";
  try {
    const localTime = new Date($("#scenario-start").value);
    const result = await api("/api/v1/demo/seed", { method: "POST", body: JSON.stringify({ scenario: $("#scenario-select").value, seed: Number($("#scenario-seed").value), start_time: localTime.toISOString() }) });
    toast(`${result.events_inserted} events inserted · ${result.duplicates} duplicates`);
    modal(false); await refreshAll();
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "Generate & ingest"; }
}

async function runDetection() {
  const button = $("#run-detection"); button.disabled = true; button.textContent = "Running…";
  try {
    const result = await api("/api/v1/detections/run", { method: "POST", body: JSON.stringify({ start: "2025-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" }) });
    toast(`${result.alerts_inserted} alerts inserted · ${result.duplicates} duplicates`);
    await refreshAll(); loadAlerts(true);
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.textContent = "▶ Run detection"; }
}

async function importJsonl(file) {
  if (!file) return;
  try {
    const text = await file.text();
    const events = text.split(/\r?\n/).filter((line) => line.trim()).map((line, index) => {
      try { return JSON.parse(line); } catch { throw new Error(`Invalid JSON at line ${index + 1}`); }
    });
    if (events.length > 5000) throw new Error("Import limit is 5,000 events per file");
    const isRawTelemetry = events.some((event) => event.source_type && event.payload);
    const result = isRawTelemetry
      ? await api("/api/v1/raw/import", { method: "POST", body: JSON.stringify({ records: events }) })
      : await api("/api/v1/events/import", { method: "POST", body: JSON.stringify({ events }) });
    const rejected = result.events_rejected ? ` · ${result.events_rejected} rejected` : "";
    toast(`${result.events_inserted} events imported · ${result.duplicates} duplicates${rejected}`, result.events_rejected ? "error" : "success");
    if (result.rejections?.length) {
      openDrawer(`<span class="eyebrow">IMPORT QUALITY REPORT</span><h2 class="detail-title">${result.events_rejected} rejected records</h2><p class="detail-reason">Valid records were normalized and ingested. Rejections contain metadata only, never the raw payload.</p><div class="evidence-list">${result.rejections.map((item) => `<div class="evidence-item"><b>Line ${item.line_number} · ${esc(item.error_code)}</b><span>${esc(item.source_type)} · ${esc(item.source_record_id)}</span><span>${esc(item.message)}</span></div>`).join("")}</div>`);
    }
    await refreshAll(); loadEvents(true);
  } catch (error) { toast(error.message, "error"); }
  finally { $("#jsonl-input").value = ""; }
}

async function refreshAll() { await Promise.all([checkHealth(), loadDashboard()]); }

function bindEvents() {
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => switchView(item.dataset.view)));
  $$('[data-view-target]').forEach((item) => item.addEventListener("click", () => switchView(item.dataset.viewTarget)));
  $$('[data-open-demo]').forEach((item) => item.addEventListener("click", () => modal(true)));
  $$('[data-close-modal]').forEach((item) => item.addEventListener("click", () => modal(false)));
  $("#demo-modal").addEventListener("click", (event) => { if (event.target === $("#demo-modal")) modal(false); });
  $("#scenario-select").addEventListener("change", updateScenarioDescription);
  $("#seed-button").addEventListener("click", seedScenario);
  $("#refresh-button").addEventListener("click", refreshAll);
  $("#run-detection").addEventListener("click", runDetection);
  $("#jsonl-input").addEventListener("change", (event) => importJsonl(event.target.files[0]));
  $("#drawer-close").addEventListener("click", () => $("#detail-drawer").classList.remove("open"));
  $("#event-filters").addEventListener("submit", (event) => { event.preventDefault(); loadEvents(true); });
  $("#event-filters").addEventListener("reset", () => window.setTimeout(() => loadEvents(true), 0));
  $("#alert-filters").addEventListener("submit", (event) => { event.preventDefault(); loadAlerts(true); });
  $("#alert-filters").addEventListener("reset", () => window.setTimeout(() => loadAlerts(true), 0));
  $("#events-next").addEventListener("click", () => { if (!state.eventNext) return; state.eventCursors.push(state.eventNext); state.eventPage += 1; loadEvents(); });
  $("#events-back").addEventListener("click", () => { if (!state.eventPage) return; state.eventCursors.pop(); state.eventPage -= 1; loadEvents(); });
  $("#alerts-next").addEventListener("click", () => { if (!state.alertNext) return; state.alertCursors.push(state.alertNext); state.alertPage += 1; loadAlerts(); });
  $("#alerts-back").addEventListener("click", () => { if (!state.alertPage) return; state.alertCursors.pop(); state.alertPage -= 1; loadAlerts(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") { modal(false); $("#detail-drawer").classList.remove("open"); } });
}

async function init() {
  bindEvents();
  const initial = window.location.hash.slice(1);
  if (["dashboard", "events", "alerts", "workshop"].includes(initial)) switchView(initial);
  await Promise.all([refreshAll(), loadScenarios()]);
}

init();
