const settingsKey = "obi-instrumentation-workbench-settings";
const pageSize = 12;
const defaultSelectorText = '[{"open_ports":"18080,18082-18083"}]';

const savedSettings = readJSON(settingsKey, {});
const state = {
  selectorText: !savedSettings.selectorText || savedSettings.selectorText === '[{"open_ports":"18080"}]' ? defaultSelectorText : savedSettings.selectorText,
  processes: [],
  services: [],
  probes: [],
  rules: [],
  selectedServiceKey: "",
  selected: new Set(),
  spanNames: new Map(),
  functionFilter: "all",
  functionScope: "application",
  shownFunctions: pageSize,
  composerRuleId: "",
  composerSelectorText: "",
  composerOriginalRuleId: null,
  selectedRuleId: null,
  editorOriginalRuleId: null,
  editorDraft: null,
  workspace: "inventory"
};

const byId = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const text = await response.text();
  let body = {};
  if (text) {
    try { body = JSON.parse(text); }
    catch { body = { message: text }; }
  }
  if (!response.ok) throw new Error(body.error || body.message || `${response.status} ${response.statusText}`);
  return body;
}

function readJSON(key, fallback) {
  try { return JSON.parse(localStorage.getItem(key) || "null") ?? fallback; }
  catch { return fallback; }
}

function normalizeRule(rule) {
  if (!rule || !rule.id || !Array.isArray(rule.spans)) return null;
  const probes = Array.isArray(rule.probes) ? rule.probes : [];
  const serviceNames = [...new Set(probes.filter((probe) => probe.service_name).map((probe) => (
    probe.service_namespace ? `${probe.service_namespace}/${probe.service_name}` : probe.service_name
  )))];
  return {
    id: String(rule.id),
    origin: rule.origin || "api",
    editable: rule.editable !== false,
    service: Array.isArray(rule.service) ? rule.service : [],
    serviceLabel: serviceNames.join(", ") || "Custom selector",
    spans: rule.spans.map((span) => ({
      symbol: span.on?.function_span || span.on?.function_noret || span.on?.usdt_span || span.on?.usdt_noret || "",
      target: Object.entries(span.on || {}).find(([key, value]) => ["function_span", "function_noret", "usdt_span", "usdt_noret"].includes(key) && value)?.[0] || "",
      name: span.name || "",
      definition: structuredClone(span)
    })).filter((span) => span.symbol && span.name),
    probes
  };
}

function persistSettings() {
  localStorage.setItem(settingsKey, JSON.stringify({ selectorText: state.selectorText }));
}

function parseSelector(raw = state.selectorText) {
  const selector = JSON.parse(raw);
  if (!Array.isArray(selector) || !selector.length) throw new Error("The service selector must be a non-empty JSON array");
  return selector;
}

function selectorForService(service) {
  const selector = structuredClone(parseSelector());
  const languages = service?.languages || [];
  if (!languages.length) return selector;
  const language = languages.length === 1 ? languages[0] : `{${languages.join(",")}}`;
  return selector.map((criteria) => ({ ...criteria, languages: language }));
}

function selectorTextForService(service) {
  return JSON.stringify(selectorForService(service), null, 2);
}

function serviceKey(namespace, name) {
  return encodeURIComponent(JSON.stringify([namespace, name]));
}

function setNotice(message = "", kind = "") {
  const notice = byId("notice");
  notice.textContent = message;
  notice.className = `notice${kind ? ` ${kind}` : ""}`;
}

async function checkHealth() {
  try {
    const response = await fetch("/obi/healthz", { cache: "no-store" });
    if (!response.ok) throw new Error("unavailable");
    byId("connection").textContent = "OBI API connected";
    byId("connection").classList.add("connected");
  } catch {
    byId("connection").textContent = "OBI API unavailable";
    byId("connection").classList.remove("connected");
    setNotice("OBI is not reachable. Confirm that the demo stack is running.", "error");
  }
}

async function refreshAll(showNotice = false) {
  if (showNotice) setNotice("Refreshing the service inventory and active instrumentation…");
  byId("refresh-all").disabled = true;
  try {
    const selector = encodeURIComponent(JSON.stringify(parseSelector()));
    const [symbolsBody, probesBody, rulesBody] = await Promise.all([
      api(`/obi/v1/dynamic-instrumentation/symbols?service=${selector}`),
      api("/obi/v1/dynamic-instrumentation/probes"),
      api("/obi/v1/dynamic-instrumentation/rules")
    ]);
    state.processes = symbolsBody.processes || [];
    state.probes = probesBody.probes || [];
    state.rules = (rulesBody.rules || []).map(normalizeRule).filter(Boolean);
    if (state.selectedRuleId) {
      const selectedRule = state.rules.find((rule) => rule.id === state.selectedRuleId) || null;
      state.editorOriginalRuleId = selectedRule?.id || null;
      state.editorDraft = selectedRule ? structuredClone(selectedRule) : null;
      if (!selectedRule) state.selectedRuleId = null;
    }
    buildServices();
    renderAll();
    const failures = state.processes.filter((process) => process.error);
    if (!state.services.length) {
      setNotice("No services match the current inventory selector. Change the selector in Settings.", "error");
    } else if (failures.length) {
      setNotice(`${failures.length} matching process${failures.length === 1 ? " could" : "es could"} not provide symbols; successful services remain available.`, "error");
    } else if (showNotice) {
      setNotice("Service inventory refreshed.", "success");
    }
  } catch (error) {
    state.processes = [];
    state.probes = [];
    state.rules = [];
    state.services = [];
    renderAll();
    setNotice(`Inventory refresh failed: ${error.message}`, "error");
  } finally {
    byId("refresh-all").disabled = false;
  }
}

function buildServices() {
  const groups = new Map();
  state.processes.forEach((process) => {
    if (!(process.symbols || []).length && !process.service_name) return;
    const name = process.service_name || `PID ${process.pid}`;
    const namespace = process.service_namespace || "default";
    const key = serviceKey(namespace, name);
    if (!groups.has(key)) groups.set(key, { key, name, namespace, processes: [], languages: new Set(), symbols: new Set(), errors: [] });
    const service = groups.get(key);
    service.processes.push(process);
    if (process.language) service.languages.add(process.language);
    (process.symbols || []).forEach((symbol) => service.symbols.add(symbol));
    if (process.error) service.errors.push(process.error);
  });

  state.probes.forEach((probe) => {
    const name = probe.service_name || `PID ${probe.pid}`;
    const namespace = probe.service_namespace || "default";
    const key = serviceKey(namespace, name);
    if (!groups.has(key)) groups.set(key, { key, name, namespace, processes: [], languages: new Set(), symbols: new Set(), errors: [] });
    const service = groups.get(key);
    if (probe.language) service.languages.add(probe.language);
    service.symbols.add(probe.function);
  });

  state.services = [...groups.values()].map((service) => ({
    ...service,
    languages: [...service.languages].sort(),
    symbols: [...service.symbols].sort((a, b) => a.localeCompare(b))
  })).sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name));

  if (!state.services.some((service) => service.key === state.selectedServiceKey)) {
    state.selectedServiceKey = state.services[0]?.key || "";
  }
}

function selectedService() {
  return state.services.find((service) => service.key === state.selectedServiceKey) || null;
}

function serviceProbes(service) {
  if (!service) return [];
  const pids = new Set(service.processes.map((process) => Number(process.pid)));
  return state.probes.filter((probe) => (
    probe.service_name === service.name && (probe.service_namespace || "default") === service.namespace
  ) || pids.has(Number(probe.pid)));
}

function ruleBelongsToService(rule, service) {
  if (!service) return false;
  const pids = new Set(service.processes.map((process) => Number(process.pid)));
  const attachedToService = rule.probes.some((probe) => (
    probe.service_name === service.name && (probe.service_namespace || "default") === service.namespace
  ) || pids.has(Number(probe.pid)));
  if (rule.probes.length) return attachedToService;
  const functions = new Set(service.symbols);
  return rule.spans.some((span) => functions.has(span.symbol));
}

function serviceRules(service) {
  return state.rules.filter((rule) => ruleBelongsToService(rule, service));
}

function scopeForSymbol(service, symbol) {
  return OBISymbolScope.classify(symbol, service.languages);
}

function symbolsInScope(service, scope = state.functionScope) {
  if (scope === "all") return service.symbols;
  return service.symbols.filter((symbol) => scopeForSymbol(service, symbol) === scope);
}

function matchingServiceSymbols(service, probesByFunction) {
  const query = byId("function-search").value.trim().toLowerCase();
  let symbols = symbolsInScope(service).filter((symbol) => symbol.toLowerCase().includes(query));
  if (state.functionFilter === "instrumented") symbols = symbols.filter((symbol) => probesByFunction.has(symbol));
  if (state.functionFilter === "available") symbols = symbols.filter((symbol) => !probesByFunction.has(symbol));
  return symbols.sort((a, b) => a.localeCompare(b));
}

function ownersForFunction(service, symbol, spanName = "") {
  return state.rules.filter((rule) => ruleBelongsToService(rule, service) && (
    rule.probes.some((probe) => probe.function === symbol && (!spanName || probe.span_name === spanName)) ||
    rule.spans.some((span) => span.symbol === symbol && (!spanName || span.name === spanName))
  ));
}

function renderAll() {
  renderTargetSummary();
  renderServices();
  renderFunctions();
  renderComposer();
  renderRuleCatalog();
  renderRuleEditor();
}

function renderTargetSummary() {
  const processCount = state.services.reduce((total, service) => total + service.processes.length, 0);
  byId("target-summary").innerHTML = state.services.length
    ? `<strong>${state.services.length} service${state.services.length === 1 ? "" : "s"}</strong><span>${processCount} matching process${processCount === 1 ? "" : "es"}</span>`
    : "<strong>No matching services</strong>";
}

function renderServices() {
  const query = byId("service-search").value.trim().toLowerCase();
  const services = state.services.filter((service) => `${service.namespace}/${service.name}`.toLowerCase().includes(query));
  byId("service-count").textContent = `${state.services.length} service${state.services.length === 1 ? "" : "s"}`;
  const rows = byId("service-rows");
  rows.innerHTML = services.map((service) => {
    const probes = serviceProbes(service);
    const rules = serviceRules(service);
    return `<button class="service-row ${service.key === state.selectedServiceKey ? "selected" : ""}" data-service-key="${escapeHTML(service.key)}" type="button">
      <strong>${escapeHTML(service.name)}</strong>
      <span>${escapeHTML(service.namespace)}</span>
      <span>${escapeHTML(service.languages.join(", ") || "unknown")}</span>
      <span>${service.processes.length}</span>
      <span>${service.symbols.length.toLocaleString()}</span>
      <span class="mint-value">${probes.length}</span>
      <span class="amber-value">${rules.length}</span>
    </button>`;
  }).join("") || '<div class="empty-state">No services match this search.</div>';
  document.querySelectorAll("[data-service-key]").forEach((button) => button.addEventListener("click", () => chooseService(button.dataset.serviceKey)));
}

function chooseService(key) {
  if (key === state.selectedServiceKey) return;
  if (state.selected.size && !window.confirm("Changing services will clear the current rule draft. Continue?")) return;
  clearDraft();
  state.selectedServiceKey = key;
  state.functionScope = "application";
  state.shownFunctions = pageSize;
  byId("function-search").value = "";
  renderAll();
}

function renderFunctions() {
  const service = selectedService();
  const selectVisible = byId("select-visible-functions");
  if (!service) {
    byId("service-title").textContent = "Select a service";
    byId("service-namespace").textContent = "";
    byId("service-language").textContent = "";
    byId("service-summary").textContent = "Choose a service above to inspect its available functions.";
    byId("service-stats").innerHTML = "";
    byId("scope-summary").textContent = "";
    document.querySelectorAll("[data-function-scope]").forEach((button) => { button.disabled = true; });
    byId("function-status").disabled = true;
    byId("function-rows").innerHTML = '<div class="empty-state">Select a service to see its functions.</div>';
    selectVisible.checked = false;
    selectVisible.indeterminate = false;
    selectVisible.disabled = true;
    return;
  }

  const probes = serviceProbes(service);
  document.querySelectorAll("[data-function-scope]").forEach((button) => { button.disabled = false; });
  byId("function-status").disabled = false;
  const probesByFunction = new Map();
  probes.forEach((probe) => {
    if (!probesByFunction.has(probe.function)) probesByFunction.set(probe.function, []);
    probesByFunction.get(probe.function).push(probe);
  });
  const scopedSymbols = symbolsInScope(service);
  const instrumented = scopedSymbols.filter((symbol) => probesByFunction.has(symbol));
  byId("service-title").textContent = service.name;
  byId("service-namespace").textContent = service.namespace;
  byId("service-language").textContent = service.languages.join(", ") || "unknown";
  byId("service-summary").textContent = `${service.symbols.length.toLocaleString()} exact symbols across ${service.processes.length} matching process${service.processes.length === 1 ? "" : "es"}.`;
  const knownRules = serviceRules(service).length;
  byId("service-stats").innerHTML = `<span><strong>${service.processes.length}</strong> processes</span><span><strong>${service.symbols.length.toLocaleString()}</strong> available</span><span><strong>${probes.length}</strong> instrumented</span><span><strong>${knownRules}</strong> rules</span>`;
  const scopeCounts = { application: 0, dependency: 0, runtime: 0 };
  service.symbols.forEach((symbol) => { scopeCounts[scopeForSymbol(service, symbol)]++; });
  document.querySelectorAll("[data-function-scope]").forEach((button) => {
    const scope = button.dataset.functionScope;
    const count = scope === "all" ? service.symbols.length : scopeCounts[scope];
    button.querySelector("span").textContent = count.toLocaleString();
    button.setAttribute("aria-pressed", String(scope === state.functionScope));
  });
  const statusSelect = byId("function-status");
  statusSelect.value = state.functionFilter;
  statusSelect.options[0].textContent = `Any status (${scopedSymbols.length.toLocaleString()})`;
  statusSelect.options[1].textContent = `Instrumented (${instrumented.length.toLocaleString()})`;
  statusSelect.options[2].textContent = `Available (${(scopedSymbols.length - instrumented.length).toLocaleString()})`;
  const hiddenCount = service.symbols.length - scopedSymbols.length;
  const scopeLabels = { application: "application", dependency: "dependency", runtime: "runtime/internal", all: "all" };
  const scopeLabel = scopeLabels[state.functionScope];
  byId("scope-summary").innerHTML = state.functionScope === "all"
    ? `Showing the complete symbol catalog. Scope is inferred from ${escapeHTML(service.languages.join(", ") || "language")} naming conventions.`
    : `Showing <strong>${escapeHTML(scopeLabel.toLowerCase())}</strong> functions. ${hiddenCount.toLocaleString()} function${hiddenCount === 1 ? " is" : "s are"} hidden by inferred scope. <button id="show-all-scopes" type="button">Show all</button>`;
  byId("show-all-scopes")?.addEventListener("click", () => setFunctionScope("all"));

  const symbols = matchingServiceSymbols(service, probesByFunction);
  const visible = symbols.slice(0, state.shownFunctions);
  const selectedVisible = visible.filter((symbol) => state.selected.has(symbol)).length;
  selectVisible.disabled = !visible.length;
  selectVisible.checked = Boolean(visible.length) && selectedVisible === visible.length;
  selectVisible.indeterminate = selectedVisible > 0 && selectedVisible < visible.length;
  selectVisible.setAttribute("aria-label", `${selectVisible.checked ? "Deselect" : "Select"} all ${visible.length} visible functions`);
  selectVisible.title = `${selectVisible.checked ? "Deselect" : "Select"} all ${visible.length} visible functions`;
  byId("show-more-functions").hidden = visible.length >= symbols.length;
  byId("show-more-functions").textContent = `Show more functions · ${visible.length.toLocaleString()} of ${symbols.length.toLocaleString()}`;

  byId("function-rows").innerHTML = visible.map((symbol) => {
    const selected = state.selected.has(symbol);
    const functionProbes = probesByFunction.get(symbol) || [];
    const owners = ownersForFunction(service, symbol);
    const status = selected ? "Selected" : functionProbes.length ? "Instrumented" : "Available";
    const statusClass = selected ? "selected" : functionProbes.length ? "instrumented" : "available";
    const spanName = state.spanNames.get(symbol) || [...new Set(functionProbes.map((probe) => probe.span_name))].join(", ") || owners[0]?.spans.find((span) => span.symbol === symbol)?.name || "—";
    return `<label class="function-row ${selected ? "selected" : ""}">
      <input type="checkbox" data-function-symbol="${escapeHTML(symbol)}" ${selected ? "checked" : ""}>
      <code title="${escapeHTML(symbol)}">${escapeHTML(symbol)}</code>
      <span class="state-pill ${statusClass}">${status}</span>
      ${owners.length ? `<span class="owner-links">${owners.map((owner) => `<button class="rule-link" data-open-rule="${escapeHTML(owner.id)}" type="button">${escapeHTML(owner.id)}</button>`).join("")}</span>` : '<span class="owner-label">—</span>'}
      <code class="span-label" title="${escapeHTML(spanName)}">${escapeHTML(spanName)}</code>
    </label>`;
  }).join("") || '<div class="empty-state">No functions match this filter.</div>';

  document.querySelectorAll("[data-function-symbol]").forEach((input) => input.addEventListener("change", () => toggleFunction(input.dataset.functionSymbol, input.checked)));
  document.querySelectorAll("[data-open-rule]").forEach((button) => button.addEventListener("click", (event) => {
    event.preventDefault();
    openRule(button.dataset.openRule);
  }));
}

function toggleVisibleFunctions(checked) {
  const service = selectedService();
  if (!service) return;
  const probesByFunction = new Map();
  serviceProbes(service).forEach((probe) => {
    if (!probesByFunction.has(probe.function)) probesByFunction.set(probe.function, []);
    probesByFunction.get(probe.function).push(probe);
  });
  const visible = matchingServiceSymbols(service, probesByFunction).slice(0, state.shownFunctions);
  visible.forEach((symbol) => {
    if (checked) {
      state.selected.add(symbol);
      if (!state.spanNames.has(symbol)) state.spanNames.set(symbol, defaultSpanName(symbol));
    } else {
      state.selected.delete(symbol);
    }
  });
  if (checked && visible.length) {
    if (!state.composerRuleId) state.composerRuleId = suggestedRuleName(service.name);
    if (!state.composerSelectorText) state.composerSelectorText = selectorTextForService(service);
  }
  renderFunctions();
  renderComposer();
}

function setFunctionScope(scope) {
  state.functionScope = scope;
  state.shownFunctions = pageSize;
  renderFunctions();
}

function toggleFunction(symbol, checked) {
  if (checked) {
    state.selected.add(symbol);
    if (!state.spanNames.has(symbol)) state.spanNames.set(symbol, defaultSpanName(symbol));
    if (!state.composerRuleId) state.composerRuleId = suggestedRuleName(selectedService()?.name || "rule");
    if (!state.composerSelectorText) state.composerSelectorText = selectorTextForService(selectedService());
  } else {
    state.selected.delete(symbol);
  }
  renderFunctions();
  renderComposer();
}

function defaultSpanName(symbol) {
  return `dynamic.${symbol}`.replace(/[^a-zA-Z0-9_.:/-]/g, "_");
}

function suggestedRuleName(serviceName) {
  const prefix = serviceName.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-|-$/g, "") || "instrumentation";
  return `${prefix}-${Date.now().toString(36).slice(-6)}`;
}

function renderComposer() {
  const composer = byId("rule-composer");
  const symbols = [...state.selected].sort((a, b) => a.localeCompare(b));
  composer.hidden = !symbols.length;
  byId("inventory-layout").classList.toggle("with-composer", Boolean(symbols.length));
  document.querySelector("main").classList.toggle("composer-open", Boolean(symbols.length));
  if (!symbols.length) return;

  const service = selectedService();
  const editableRules = state.rules.filter((rule) => rule.editable && ruleBelongsToService(rule, service));
  const existingRule = editableRules.find((rule) => rule.id === state.composerOriginalRuleId) || null;
  const editing = Boolean(existingRule);
  byId("composer-title").textContent = editing ? "Add functions to rule" : "Create instrumentation rule";
  byId("composer-destination").innerHTML = '<option value="">New instrumentation rule</option>' + editableRules.map((rule) => (
    `<option value="${escapeHTML(rule.id)}" ${rule.id === state.composerOriginalRuleId ? "selected" : ""}>${escapeHTML(rule.id)}</option>`
  )).join("");
  byId("rule-id-field").hidden = editing;
  byId("rule-id").value = state.composerRuleId;
  byId("composer-selector").value = state.composerSelectorText || selectorTextForService(service);
  byId("composer-service").textContent = existingRule?.serviceLabel || service?.name || "Current selector";
  byId("selection-count").textContent = symbols.length;
  byId("apply-rule").textContent = editing ? `Add to ${existingRule.id}` : `Create rule (${symbols.length} function${symbols.length === 1 ? "" : "s"})`;
  byId("selection-list").innerHTML = symbols.map((symbol) => `<div class="composer-function">
    <div><code>${escapeHTML(symbol)}</code><button class="text-button" data-remove-selected="${escapeHTML(symbol)}" type="button">Remove</button></div>
    <label><span>Span name</span><input data-composer-span="${escapeHTML(symbol)}" value="${escapeHTML(state.spanNames.get(symbol) || defaultSpanName(symbol))}"></label>
  </div>`).join("");
  document.querySelectorAll("[data-remove-selected]").forEach((button) => button.addEventListener("click", () => toggleFunction(button.dataset.removeSelected, false)));
  document.querySelectorAll("[data-composer-span]").forEach((input) => input.addEventListener("input", () => state.spanNames.set(input.dataset.composerSpan, input.value.trim())));
  validateComposer();
}

function chooseComposerDestination() {
  const id = byId("composer-destination").value;
  const rule = state.rules.find((candidate) => candidate.id === id && candidate.editable);
  if (rule) {
    state.composerOriginalRuleId = rule.id;
    state.composerRuleId = rule.id;
    state.composerSelectorText = JSON.stringify(rule.service, null, 2);
    rule.spans.forEach((span) => {
      if (state.selected.has(span.symbol)) state.spanNames.set(span.symbol, span.name);
    });
  } else {
    state.composerOriginalRuleId = null;
    state.composerRuleId = suggestedRuleName(selectedService()?.name || "rule");
    state.composerSelectorText = selectorTextForService(selectedService());
  }
  renderComposer();
}

function validateComposer() {
  const id = byId("rule-id").value.trim();
  const spans = [...state.selected].map((symbol) => ({ symbol, name: (state.spanNames.get(symbol) || "").trim() }));
  const existingRule = state.rules.find((rule) => rule.id === state.composerOriginalRuleId && rule.editable);
  const selectedSymbols = new Set(state.selected);
  const allSpanNames = [...(existingRule?.spans || []).filter((span) => !selectedSymbols.has(span.symbol)).map((span) => span.name), ...spans.map((span) => span.name)];
  let message = "Rule is ready to apply.";
  let valid = true;
  try { parseSelector(byId("composer-selector").value.trim()); }
  catch (error) { valid = false; message = error.message; }
  if (!spans.length) { valid = false; message = "Select at least one function."; }
  else if (!/^[a-zA-Z0-9._-]+$/.test(id)) { valid = false; message = "Rule names may contain letters, numbers, periods, underscores, and hyphens."; }
  else if (spans.some((span) => !span.name)) { valid = false; message = "Every function needs a span name."; }
  else if (new Set(allSpanNames).size !== allSpanNames.length) { valid = false; message = "Span names must be unique within a rule."; }
  byId("composer-validation").textContent = message;
  byId("composer-validation").classList.toggle("valid", valid);
  byId("apply-rule").disabled = !valid;
  return valid;
}

async function applyComposerRule() {
  state.composerRuleId = byId("rule-id").value.trim();
  state.composerSelectorText = byId("composer-selector").value.trim();
  if (!validateComposer()) return;
  const existingRule = state.rules.find((candidate) => candidate.id === state.composerOriginalRuleId && candidate.editable);
  const selectedSpans = [...state.selected].sort().map((symbol) => {
    const existingSpan = existingRule?.spans.find((span) => span.symbol === symbol);
    return {
      symbol,
      target: existingSpan?.target || "function_span",
      name: state.spanNames.get(symbol).trim(),
      definition: existingSpan?.definition || { on: { function_span: symbol } }
    };
  });
  const selectedSymbols = new Set(state.selected);
  const rule = {
    id: state.composerRuleId,
    origin: "api",
    editable: true,
    service: parseSelector(state.composerSelectorText),
    serviceLabel: existingRule?.serviceLabel || selectedService()?.name || "Custom selector",
    spans: existingRule ? [...existingRule.spans.filter((span) => !selectedSymbols.has(span.symbol)), ...selectedSpans] : selectedSpans,
    probes: existingRule?.probes || []
  };
  const button = byId("apply-rule");
  button.disabled = true;
  button.textContent = "Applying…";
  try {
    await putRule(rule, state.composerOriginalRuleId);
    const ruleID = rule.id;
    clearDraft();
    await refreshAll(false);
    openRule(ruleID);
    setNotice(`Rule ${ruleID} is active and ready to modify from the Rules workspace.`, "success");
  } catch (error) {
    setNotice(`Rule application failed: ${error.message}`, "error");
    renderComposer();
  }
}

async function putRule(rule, previousID = null) {
  await api(`/obi/v1/dynamic-instrumentation/rules/${encodeURIComponent(rule.id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service: rule.service,
      spans: rule.spans.map((span) => ({
        ...structuredClone(span.definition || { on: { [span.target || "function_span"]: span.symbol } }),
        name: span.name
      }))
    })
  });
  if (previousID && previousID !== rule.id) {
    await api(`/obi/v1/dynamic-instrumentation/rules/${encodeURIComponent(previousID)}`, { method: "DELETE" });
  }
}

function clearDraft() {
  state.selected.clear();
  state.spanNames.clear();
  state.composerRuleId = "";
  state.composerSelectorText = "";
  state.composerOriginalRuleId = null;
}

function cancelComposer() {
  clearDraft();
  renderAll();
}

function setWorkspace(workspace) {
  state.workspace = workspace;
  const inventory = workspace === "inventory";
  byId("inventory-tab").setAttribute("aria-selected", String(inventory));
  byId("rules-tab").setAttribute("aria-selected", String(!inventory));
  byId("inventory-view").hidden = !inventory;
  byId("rules-view").hidden = inventory;
}

function ruleAttachment(rule) {
  const attached = rule.probes.filter((probe) => probe.status === "attached").length;
  const failed = rule.probes.filter((probe) => probe.status === "error").length;
  return { attached, failed, total: rule.probes.length || rule.spans.length };
}

function renderRuleCatalog() {
  const editable = state.rules.filter((rule) => rule.editable).length;
  const configured = state.rules.length - editable;
  byId("rules-tab-count").textContent = state.rules.length;
  byId("rules-summary").textContent = `${state.rules.length} active rule${state.rules.length === 1 ? "" : "s"} · ${editable} editable${configured ? ` · ${configured} from configuration` : ""}`;
  const query = byId("rule-search").value.trim().toLowerCase();
  const rules = state.rules.filter((rule) => `${rule.id} ${rule.origin} ${rule.serviceLabel} ${rule.spans.map((span) => span.symbol).join(" ")}`.toLowerCase().includes(query));
  const rows = rules.map((rule) => {
    const attachment = ruleAttachment(rule);
    const status = attachment.failed ? `${attachment.failed} failed` : `${attachment.attached}/${attachment.total} attached`;
    const statusClass = attachment.failed ? "error" : attachment.attached === attachment.total ? "attached" : "pending";
    return `<button class="rule-catalog-row ${rule.id === state.selectedRuleId ? "selected" : ""}" data-rule-id="${escapeHTML(rule.id)}" type="button">
      <strong>${escapeHTML(rule.id)}</strong><span>${escapeHTML(`${rule.origin === "config" ? "Configuration" : "API"} · ${rule.serviceLabel || "Custom selector"}`)}</span><span>${rule.spans.length}</span><span class="state-pill ${statusClass}">${escapeHTML(status)}</span>
    </button>`;
  }).join("");
  byId("rule-catalog-rows").innerHTML = rows || '<div class="empty-state">No rules match this search.</div>';
  document.querySelectorAll("[data-rule-id]").forEach((button) => button.addEventListener("click", () => selectRule(button.dataset.ruleId)));
}

function openRule(id) {
  setWorkspace("rules");
  selectRule(id);
}

function selectRule(id) {
  const rule = state.rules.find((candidate) => candidate.id === id);
  if (!rule) return;
  state.selectedRuleId = id;
  state.editorOriginalRuleId = id;
  state.editorDraft = structuredClone(rule);
  renderRuleCatalog();
  renderRuleEditor();
}

function renderRuleEditor() {
  const content = byId("rule-editor-content");
  const empty = byId("rule-editor-empty");
  if (!state.editorDraft) {
    content.hidden = true;
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  content.hidden = false;
  const draft = state.editorDraft;
  const editable = draft.editable;
  byId("rule-editor-title").textContent = draft.id;
  byId("editor-rule-id").value = draft.id;
  byId("editor-rule-id").disabled = !editable;
  byId("editor-selector").value = JSON.stringify(draft.service, null, 2);
  byId("editor-selector").disabled = !editable;
  byId("delete-rule").hidden = !editable;
  byId("add-rule-functions").hidden = !editable;
  byId("save-rule-changes").hidden = !editable;
  byId("discard-rule-changes").hidden = !editable;
  byId("member-count").textContent = `${draft.spans.length} function${draft.spans.length === 1 ? "" : "s"}`;
  byId("member-rows").innerHTML = draft.spans.map((span, index) => {
    const probes = draft.probes.filter((candidate) => candidate.function === span.symbol && candidate.span_name === span.name);
    const status = probes.find((probe) => probe.status === "error")?.status || probes.find((probe) => probe.status === "attached")?.status || probes[0]?.status || "pending";
    return `<div class="member-row">
      <code title="${escapeHTML(span.symbol)}">${escapeHTML(span.symbol)}</code>
      <input data-member-span="${index}" value="${escapeHTML(span.name)}" aria-label="Span name for ${escapeHTML(span.symbol)}" ${editable ? "" : "disabled"}>
      <span class="state-pill ${escapeHTML(status)}">${escapeHTML(status === "pending" && !probes.length ? "not attached" : status)}</span>
      ${editable ? `<button class="text-button" data-remove-member="${index}" type="button">Remove</button>` : '<span></span>'}
    </div>`;
  }).join("") || '<div class="empty-state">This rule has no functions. Add functions before saving.</div>';
  document.querySelectorAll("[data-member-span]").forEach((input) => input.addEventListener("input", () => {
    state.editorDraft.spans[Number(input.dataset.memberSpan)].name = input.value.trim();
    validateEditor();
  }));
  document.querySelectorAll("[data-remove-member]").forEach((button) => button.addEventListener("click", () => {
    state.editorDraft.spans.splice(Number(button.dataset.removeMember), 1);
    renderRuleEditor();
    validateEditor();
  }));
  if (editable) validateEditor();
  else {
    byId("editor-validation").textContent = "This rule is owned by OBI configuration and is read-only here.";
    byId("editor-validation").classList.remove("valid");
  }
}

function updateEditorDraftFromFields() {
  if (!state.editorDraft) return;
  state.editorDraft.id = byId("editor-rule-id").value.trim();
  try { state.editorDraft.service = parseSelector(byId("editor-selector").value.trim()); }
  catch { state.editorDraft.service = null; }
}

function validateEditor() {
  if (!state.editorDraft?.editable) return false;
  updateEditorDraftFromFields();
  const draft = state.editorDraft;
  let valid = true;
  let message = "Ready to save this rule definition.";
  if (!/^[a-zA-Z0-9._-]+$/.test(draft.id)) { valid = false; message = "Enter a valid rule name."; }
  else if (!Array.isArray(draft.service) || !draft.service.length) { valid = false; message = "Enter a valid non-empty service selector."; }
  else if (!draft.spans.length) { valid = false; message = "A rule must include at least one function."; }
  else if (draft.spans.some((span) => !span.name)) { valid = false; message = "Every function needs a span name."; }
  else if (new Set(draft.spans.map((span) => span.name)).size !== draft.spans.length) { valid = false; message = "Span names must be unique within a rule."; }
  byId("editor-validation").textContent = message;
  byId("editor-validation").classList.toggle("valid", valid);
  byId("save-rule-changes").disabled = !valid;
  return valid;
}

async function saveEditorRule() {
  if (!validateEditor()) return;
  const rule = { ...state.editorDraft };
  byId("save-rule-changes").disabled = true;
  byId("save-rule-changes").textContent = "Saving…";
  try {
    await putRule(rule, state.editorOriginalRuleId);
    await refreshAll(false);
    selectRule(rule.id);
    setNotice(`Rule ${rule.id} updated.`, "success");
  } catch (error) {
    setNotice(`Could not update rule: ${error.message}`, "error");
    renderRuleEditor();
  } finally {
    byId("save-rule-changes").textContent = "Save changes";
  }
}

function duplicateRule() {
  if (!state.editorDraft) return;
  const draft = structuredClone(state.editorDraft);
  draft.id = uniqueRuleID(`${draft.id.replace(/[^a-zA-Z0-9._-]+/g, "-")}-copy`);
  draft.origin = "api";
  draft.editable = true;
  draft.probes = [];
  state.selectedRuleId = null;
  state.editorOriginalRuleId = null;
  state.editorDraft = draft;
  renderRuleCatalog();
  renderRuleEditor();
  setNotice("Review the duplicated definition, then save it as a new rule.");
}

function uniqueRuleID(base) {
  let id = base;
  let suffix = 2;
  while (state.rules.some((rule) => rule.id === id)) id = `${base}-${suffix++}`;
  return id;
}

function discardEditorChanges() {
  if (state.editorOriginalRuleId) selectRule(state.editorOriginalRuleId);
  else {
    state.editorDraft = null;
    state.editorOriginalRuleId = null;
    renderRuleEditor();
  }
  setNotice("Unsaved rule changes discarded.");
}

async function deleteSelectedRule() {
  const id = state.editorOriginalRuleId || state.editorDraft?.id;
  if (!id || !state.rules.some((rule) => rule.id === id && rule.editable)) return;
  if (!window.confirm(`Delete rule ${id} and release the probes it owns?`)) return;
  try {
    await api(`/obi/v1/dynamic-instrumentation/rules/${encodeURIComponent(id)}`, { method: "DELETE" });
    state.selectedRuleId = null;
    state.editorOriginalRuleId = null;
    state.editorDraft = null;
    await refreshAll(false);
    setNotice(`Rule ${id} deleted.`, "success");
  } catch (error) {
    setNotice(`Could not delete rule ${id}: ${error.message}`, "error");
  }
}

function addFunctionsToRule() {
  if (!state.editorDraft?.editable) return;
  const draft = state.editorDraft;
  clearDraft();
  draft.spans.forEach((span) => {
    state.selected.add(span.symbol);
    state.spanNames.set(span.symbol, span.name);
  });
  state.composerRuleId = draft.id;
  state.composerSelectorText = JSON.stringify(draft.service, null, 2);
  state.composerOriginalRuleId = state.editorOriginalRuleId;
  const service = state.services.find((candidate) => ruleBelongsToService(draft, candidate));
  if (service) state.selectedServiceKey = service.key;
  state.functionScope = "all";
  setWorkspace("inventory");
  renderAll();
  setNotice("Add or remove functions in the inventory, then save the complete rule.");
}

function saveSettings(event) {
  event.preventDefault();
  try {
    const selectorText = byId("service-selector").value.trim();
    parseSelector(selectorText);
    state.selectorText = selectorText;
    persistSettings();
    clearDraft();
    byId("settings-dialog").close();
    refreshAll(true);
  } catch (error) {
    setNotice(`Settings were not saved: ${error.message}`, "error");
  }
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function bindEvents() {
  byId("inventory-tab").addEventListener("click", () => setWorkspace("inventory"));
  byId("rules-tab").addEventListener("click", () => setWorkspace("rules"));
  byId("service-search").addEventListener("input", renderServices);
  byId("function-search").addEventListener("input", () => { state.shownFunctions = pageSize; renderFunctions(); });
  byId("function-status").addEventListener("change", () => {
    state.functionFilter = byId("function-status").value;
    state.shownFunctions = pageSize;
    renderFunctions();
  });
  byId("select-visible-functions").addEventListener("change", (event) => toggleVisibleFunctions(event.target.checked));
  byId("rule-search").addEventListener("input", renderRuleCatalog);
  document.querySelectorAll("[data-function-scope]").forEach((button) => button.addEventListener("click", () => setFunctionScope(button.dataset.functionScope)));
  byId("show-more-functions").addEventListener("click", () => { state.shownFunctions += pageSize; renderFunctions(); });
  byId("composer-destination").addEventListener("change", chooseComposerDestination);
  byId("rule-id").addEventListener("input", () => { state.composerRuleId = byId("rule-id").value.trim(); validateComposer(); });
  byId("composer-selector").addEventListener("input", () => { state.composerSelectorText = byId("composer-selector").value; validateComposer(); });
  byId("apply-rule").addEventListener("click", applyComposerRule);
  byId("cancel-composer").addEventListener("click", cancelComposer);
  byId("clear-selection").addEventListener("click", cancelComposer);
  byId("refresh-all").addEventListener("click", () => refreshAll(true));
  byId("open-settings").addEventListener("click", () => byId("settings-dialog").showModal());
  byId("close-settings").addEventListener("click", () => byId("settings-dialog").close());
  byId("settings-form").addEventListener("submit", saveSettings);
  byId("editor-rule-id").addEventListener("input", validateEditor);
  byId("editor-selector").addEventListener("input", validateEditor);
  byId("save-rule-changes").addEventListener("click", saveEditorRule);
  byId("discard-rule-changes").addEventListener("click", discardEditorChanges);
  byId("duplicate-rule").addEventListener("click", duplicateRule);
  byId("delete-rule").addEventListener("click", deleteSelectedRule);
  byId("add-rule-functions").addEventListener("click", addFunctionsToRule);
}

async function initialize() {
  bindEvents();
  byId("service-selector").value = state.selectorText;
  await checkHealth();
  await refreshAll(false);
}

initialize();
