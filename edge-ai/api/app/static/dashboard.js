const PREFIX =
  location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
const $ = (id) => document.getElementById(id);
const node = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
};
const icon = (name) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", "svg"),
    u = document.createElementNS(n.namespaceURI, "use");
  u.setAttribute("href", "#i-" + name);
  n.append(u);
  n.setAttribute("aria-hidden", "true");
  return n;
};
const number = (value) => Number(value || 0).toLocaleString("en-US");
const date = (value) => {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(+d)
    ? String(value)
    : d.toLocaleString("en-GB", { timeZone: "UTC", hour12: false });
};
const layers = {
  crowdsec: "HTTP-WAF",
  waf: "HTTP-WAF",
  suricata: "NETWORK-IDS",
  wazuh: "HOST-EDR",
  manual: "MANUAL",
};
const tabs = {
  triage: [
    "AI alert triage copilot",
    "Wazuh SIEM evidence · Local Ollama streaming analysis",
  ],
  requests: ["HTTP request explorer", "Retained gateway access-log history"],
  incidents: ["Incident center", "HTTP-WAF · Network-IDS · Host-EDR evidence"],
  approvals: ["Approval queue", "Review each proposed action before execution"],
  campaigns: ["Attack campaigns", "Correlated incidents in the database"],
  decisions: [
    "Decision history",
    "Policy verdicts and enforcement audit trail",
  ],
  attacks: [
    "Attack lab",
    "Controlled campaigns against the authorized lab target",
  ],
  policy: [
    "Defense policy",
    "Deterministic rules used to evaluate AI proposals",
  ],
};
let kind = "requests",
  state = {},
  items = [],
  pageAbort,
  detailAbort,
  sequence = 0,
  detailSequence = 0,
  selectedIndex = -1,
  selectedRecord = null,
  summaryBusy = false,
  tableBusy = false,
  labBusy = false,
  agentStatus = {},
  searchTimer;

async function request(path, options = {}, controller = new AbortController()) {
  let timedOut = false;
  const timer = setTimeout(
    () => {
      timedOut = true;
      controller.abort();
    },
    options.method === "POST" ? 210000 : 15000,
  );
  try {
    const response = await fetch(PREFIX + path, {
      ...options,
      signal: controller.signal,
    });
    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      throw new Error(
        response.ok
          ? "Unexpected API response format"
          : `HTTP ${response.status}`,
      );
    }
    if (!response.ok)
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : `HTTP ${response.status}`,
      );
    return data;
  } catch (error) {
    if (timedOut) throw new Error("API request timed out");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
function badge(value) {
  const safe = String(value || "unknown");
  const allowed = [
    "high",
    "critical",
    "medium",
    "low",
    "failed",
    "rejected",
    "pending_approval",
    "executed",
    "execution_unknown",
  ];
  const cls = allowed.includes(safe)
    ? safe
    : /^[1-5]\d\d$/.test(safe)
      ? "http-" + safe[0] + "xx"
      : "";
  return node("span", "record-badge " + cls, safe);
}
function dot(state) {
  return node(
    "i",
    "dot" + (state === true ? "" : state === false ? " off" : " pending"),
  );
}
function textCell(row, label, value, cls = "") {
  const td = node("td", cls);
  td.dataset.label = label;
  if (value instanceof Node) td.append(value);
  else
    td.textContent =
      value === undefined || value === null ? "—" : String(value);
  row.append(td);
  return td;
}
function pathCopy(main, sub) {
  const n = node("span");
  const title = node("span", "record-path", main || "—");
  title.title = main || "";
  n.append(title);
  if (sub) n.append(node("small", "record-subtitle", sub));
  return n;
}

async function loadSummary() {
  if (summaryBusy) return;
  summaryBusy = true;
  $("refreshDashboard").disabled = true;
  const paths = [
    "/health",
    "/api/v1/visibility",
    "/api/v1/agents/status",
    "/api/v1/dashboard/summary",
  ];
  const results = await Promise.allSettled(paths.map((path) => request(path)));
  const health = results[0].status === "fulfilled" ? results[0].value : {};
  $("serviceStatus").replaceChildren(
    ...["ollama", "crowdsec", "redis", "postgres"].map((name) => {
      const n = node("span");
      const known = Object.hasOwn(health, name);
      n.append(
        dot(known ? health[name] === "ok" : null),
        node(
          "span",
          "",
          name + " · " + (known ? String(health[name]) : "unavailable"),
        ),
      );
      n.title = known ? String(health[name]) : "unavailable";
      return n;
    }),
  );
  const visibility =
    results[1].status === "fulfilled" ? results[1].value.layers : {};
  $("layerStatus").replaceChildren(
    ...[
      ["http_waf", "HTTP-WAF"],
      ["network_ids", "NETWORK-IDS"],
      ["host_edr", "HOST-EDR"],
    ].map(([key, label]) => {
      const data = visibility[key];
      const n = node("span");
      n.append(
        dot(data ? data.state === "online" : null),
        node("span", "", label),
        node("small", "", data?.label || "UNAVAILABLE"),
      );
      n.title = data?.detail || "Sensor status unavailable";
      return n;
    }),
  );
  agentStatus = results[2].status === "fulfilled" ? results[2].value : {};
  $("responseMode").textContent =
    agentStatus.defense?.mode || "Response mode unavailable";
  const summary = results[3].status === "fulfilled" ? results[3].value : null;
  for (const [id, key] of [
    ["statRequests", "requests"],
    ["statIncidents", "incidents"],
    ["statPending", "pending"],
    ["statCampaigns", "campaigns"],
  ])
    $(id).textContent = summary ? number(summary[key]) : "—";
  $("analyzedScope").textContent = summary
    ? `${number(summary.analyzed)} analyzed · all stored incidents`
    : "Summary unavailable";
  $("requestScope").textContent = summary?.requests_since
    ? `Retained since ${date(summary.requests_since)} UTC`
    : "Retained HTTP history";
  $("pendingBadge").textContent = summary?.pending
    ? number(summary.pending)
    : "";
  $("trafficBadge").textContent = summary ? number(summary.requests) : "";
  const failures = results.filter((r) => r.status === "rejected").length;
  $("connectionState").replaceChildren(
    dot(failures ? null : true),
    node("span", "", failures ? "PARTIAL DATA" : "SYSTEM CONNECTED"),
  );
  updateLab();
  summaryBusy = false;
  $("refreshDashboard").disabled = false;
}

function reset() {
  state = {
    page: 1,
    page_size: Number($("pageSize").value),
    pages: 1,
    total: 0,
    snapshot: null,
    q: "",
    source: "",
    severity: "",
    status: "",
  };
}
function configureFilters() {
  $("sourceFilterLabel").hidden = kind !== "incidents";
  $("severityFilterLabel").hidden = ![
    "incidents",
    "approvals",
    "campaigns",
    "decisions",
  ].includes(kind);
  $("statusFilterLabel").hidden = !["requests", "decisions"].includes(kind);
  const options =
    kind === "requests"
      ? [
          ["", "All statuses"],
          ["2xx", "2xx · Success"],
          ["3xx", "3xx · Redirect"],
          ["4xx", "4xx · Client"],
          ["403", "403 · Forbidden"],
          ["5xx", "5xx · Server"],
        ]
      : [
          ["", "All statuses"],
          ...[
            "pending_approval",
            "executing",
            "executed",
            "failed",
            "rejected",
            "execution_unknown",
          ].map((s) => [s, s]),
        ];
  $("recordStatus").replaceChildren(
    ...options.map(([value, text]) => {
      const n = node("option", "", text);
      n.value = value;
      return n;
    }),
  );
  $("recordSearch").value = "";
  $("sourceFilter").value = "";
  $("recordSeverity").value = "";
  $("labControls").hidden = kind !== "attacks";
  $("tableToolbar").hidden = ["policy", "triage"].includes(kind);
  $("pager").hidden = ["policy", "triage"].includes(kind);
  $("dataView").hidden = kind === "triage";
  $("triageWorkspace").hidden = kind !== "triage";
  document.querySelector(".capture-note").hidden = kind === "triage";
  $("dataView").setAttribute("aria-labelledby", "tab-" + kind);
}
function switchTab(next) {
  if (!Object.hasOwn(tabs, next)) next = "requests";
  kind = next;
  sequence++;
  pageAbort?.abort();
  detailAbort?.abort();
  if ($("detailDialog").open) $("detailDialog").close();
  document.querySelectorAll("[data-kind]").forEach((button) => {
    const active = button.dataset.kind === kind;
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });
  $("recordsTitle").textContent = tabs[kind][0];
  $("recordDescription").textContent = tabs[kind][1];
  configureFilters();
  reset();
  if (kind === "triage") window.EdgeTriage.open();
  else window.EdgeTriage.leave();
  loadPage();
}
function filtersChanged() {
  state.q = $("recordSearch").value.trim();
  state.source = $("sourceFilter").value;
  state.severity = $("recordSeverity").value;
  state.status = $("recordStatus").value;
  state.page = 1;
  state.snapshot = null;
  loadPage();
}

async function loadPage() {
  const ticket = ++sequence;
  pageAbort?.abort();
  pageAbort = new AbortController();
  tableBusy = true;
  updatePager();
  $("dataView").setAttribute("aria-busy", "true");
  $("refreshState").textContent = "กำลังโหลดข้อมูล…";
  try {
    if (kind === "triage") {
      $("refreshState").textContent = "On-demand analysis · Wazuh alerts";
      return;
    }
    if (kind === "policy") {
      const policy = await request("/api/v1/policy", {}, pageAbort);
      if (ticket !== sequence) return;
      const n = node("div", "policy-view");
      n.append(
        node("h3", "", "Active deterministic policy"),
        node("p", "", policy.mode),
        node("pre", "", JSON.stringify(policy.policy, null, 2)),
      );
      $("dataView").replaceChildren(n);
      $("refreshState").textContent = "โหลด policy แล้ว";
      return;
    }
    const params = new URLSearchParams({
      page: state.page,
      page_size: state.page_size,
      q: state.q,
      source: state.source,
      severity: state.severity,
      status: state.status,
    });
    if (state.snapshot !== null) params.set("snapshot", state.snapshot);
    const result = await request(
      "/api/v1/dashboard/data/" + kind + "?" + params,
      {},
      pageAbort,
    );
    if (ticket !== sequence) return;
    state = {
      ...state,
      error: false,
      page: result.page,
      pages: result.pages,
      total: result.total,
      snapshot: result.snapshot,
    };
    items = result.items;
    renderTable();
    $("refreshState").textContent =
      state.page > 1
        ? "พัก auto-refresh ระหว่างดูหน้าถัดไป"
        : `อัปเดต ${new Date().toLocaleTimeString("th-TH")} · รีเฟรชทุก 30 วินาที`;
  } catch (error) {
    if (ticket !== sequence || error.name === "AbortError") return;
    items = [];
    state.error = true;
    $("dataView").replaceChildren(
      node(
        "p",
        "table-empty table-error",
        "โหลดข้อมูลไม่ได้: " + error.message + " · กดโหลดใหม่เพื่อลองอีกครั้ง",
      ),
    );
    $("pageInfo").textContent = "ข้อมูลไม่พร้อมใช้งาน";
    $("refreshState").textContent = "Data unavailable";
  } finally {
    if (ticket === sequence) {
      tableBusy = false;
      $("dataView").removeAttribute("aria-busy");
      updatePager();
    }
  }
}

function renderTable() {
  if (!items.length) {
    $("dataView").replaceChildren(
      node(
        "p",
        "table-empty",
        state.q || state.source || state.severity || state.status
          ? "ไม่พบข้อมูลตามเงื่อนไขที่เลือก"
          : "ยังไม่มีข้อมูลในส่วนนี้",
      ),
    );
    return;
  }
  const columns = {
    requests: [
      ["Time (UTC)", "col-time"],
      ["Method", "col-method"],
      ["Request target", ""],
      ["Gateway peer", "col-peer"],
      ["Status", "col-status"],
      ["Latency", "col-latency"],
      ["Evidence", "col-action"],
    ],
    incidents: [
      ["Time (UTC)", "col-time"],
      ["Layer / source", "col-peer"],
      ["Incident", ""],
      ["Severity", "col-status"],
      ["AI analysis", "col-status"],
      ["Evidence", "col-action"],
    ],
    approvals: [
      ["Created (UTC)", "col-time"],
      ["Action / target", ""],
      ["Duration", "col-latency"],
      ["Policy reason", ""],
      ["Review", "col-action"],
    ],
    campaigns: [
      ["Last seen (UTC)", "col-time"],
      ["Campaign", ""],
      ["Source IP", "col-peer"],
      ["Severity", "col-status"],
      ["Incidents", "col-status"],
      ["Evidence", "col-action"],
    ],
    decisions: [
      ["Created (UTC)", "col-time"],
      ["Action / target", ""],
      ["Policy verdict", "col-peer"],
      ["Status", "col-peer"],
      ["Evidence", "col-action"],
    ],
    attacks: [
      ["Created (UTC)", "col-time"],
      ["Lab target", ""],
      ["Attacker", "col-peer"],
      ["Detected", "col-status"],
      ["New alerts", "col-status"],
      ["Evidence", "col-action"],
    ],
  }[kind];
  const table = node("table", "record-table");
  const head = node("thead"),
    heading = node("tr");
  columns.forEach(([label, cls]) => {
    const th = node("th", cls, label);
    th.scope = "col";
    heading.append(th);
  });
  head.append(heading);
  table.append(head);
  const body = node("tbody");
  items.forEach((item, index) => {
    const row = node("tr");
    row.dataset.id = item.id;
    const open = node("button", "record-open", "Inspect #" + item.id);
    open.type = "button";
    open.addEventListener("click", () => openDetail(index));
    const actions = () => {
      const cell = textCell(row, "Evidence", open, "actions-cell");
      return cell;
    };
    if (kind === "requests") {
      textCell(row, "Time (UTC)", date(item.observed_at));
      textCell(row, "Method", node("span", "method-label", item.method));
      textCell(
        row,
        "Request target",
        pathCopy(item.path, item.host),
        "path-cell",
      );
      textCell(row, "Gateway peer", item.source_ip);
      textCell(row, "Status", badge(item.status));
      textCell(row, "Latency", (item.duration_ns / 1e6).toFixed(1) + " ms");
      actions();
    } else if (kind === "incidents") {
      textCell(row, "Time (UTC)", date(item.created_at));
      textCell(
        row,
        "Layer / source",
        pathCopy(
          layers[item.source] || item.source,
          item.endpoint || item.source_ip,
        ),
      );
      textCell(
        row,
        "Incident",
        pathCopy(item.attack_type || item.reason, item.alert_id),
        "path-cell",
      );
      textCell(row, "Severity", badge(item.severity));
      textCell(row, "AI analysis", item.analyzed ? "Analyzed" : "Pending");
      actions();
    } else if (kind === "approvals") {
      textCell(row, "Created (UTC)", date(item.created_at));
      textCell(
        row,
        "Action / target",
        pathCopy(item.action, item.target || "No target"),
        "path-cell",
      );
      textCell(row, "Duration", item.duration_seconds + " s");
      textCell(row, "Policy reason", item.policy_reason, "evidence-cell");
      const cell = actions(),
        buttons = node("span", "row-actions");
      for (const verb of ["approve", "reject"]) {
        const button = node(
          "button",
          verb,
          verb === "approve" ? "Approve" : "Reject",
        );
        button.type = "button";
        button.addEventListener("click", () => act(item, verb, button));
        buttons.append(button);
      }
      cell.append(buttons);
    } else if (kind === "campaigns") {
      textCell(row, "Last seen (UTC)", date(item.last_seen));
      textCell(
        row,
        "Campaign",
        pathCopy(item.attack_type, item.title),
        "path-cell",
      );
      textCell(row, "Source IP", item.source_ip);
      textCell(row, "Severity", badge(item.severity));
      textCell(row, "Incidents", number(item.incident_count));
      actions();
    } else if (kind === "decisions") {
      textCell(row, "Created (UTC)", date(item.created_at));
      textCell(
        row,
        "Action / target",
        pathCopy(item.action, item.target || "No target"),
        "path-cell",
      );
      textCell(row, "Policy verdict", item.policy_verdict);
      textCell(row, "Status", badge(item.status));
      actions();
    } else {
      textCell(row, "Created (UTC)", date(item.created_at));
      textCell(row, "Lab target", item.target_host, "path-cell");
      textCell(row, "Attacker", item.attacker_ip);
      textCell(
        row,
        "Detected",
        `${item.techniques_detected} / ${item.techniques_total}`,
      );
      textCell(row, "New alerts", number(item.new_alerts));
      actions();
    }
    body.append(row);
  });
  table.append(body);
  $("dataView").replaceChildren(table);
}

function updatePager() {
  $("pageNumber").value = state.page || 1;
  $("pageNumber").max = state.pages || 1;
  $("pageNumber").disabled = tableBusy || state.error;
  $("pageTotal").textContent = number(state.pages || 1);
  if (!tableBusy) {
    const start = state.total ? (state.page - 1) * state.page_size + 1 : 0,
      end = Math.min(state.total || 0, (state.page || 1) * state.page_size);
    $("pageInfo").textContent = state.error
      ? "ข้อมูลไม่พร้อมใช้งาน"
      : `${number(start)}–${number(end)} จาก ${number(state.total)} รายการ · หน้า ${state.page} / ${number(state.pages)}`;
  }
  $("firstPage").disabled = $("prevPage").disabled =
    tableBusy || state.error || state.page <= 1;
  $("lastPage").disabled = $("nextPage").disabled =
    tableBusy || state.error || state.page >= state.pages;
  $("goPage").disabled = tableBusy || state.error || !state.total;
}
function go(page) {
  if (tableBusy) return;
  state.page = Math.max(
    1,
    Math.min(state.pages, Math.trunc(Number(page)) || 1),
  );
  loadPage();
}

function metadata(container, entries) {
  const dl = node("dl", "detail-grid");
  entries.forEach(([name, value]) => {
    const entry = node("div");
    entry.append(
      node("dt", "", name),
      node(
        "dd",
        "",
        value === undefined || value === null || value === "" ? "—" : value,
      ),
    );
    dl.append(entry);
  });
  container.append(dl);
}
function findPayload(raw, depth = 0) {
  if (typeof raw?.payload_printable === "string" && raw.payload_printable)
    return { name: "payload_printable", value: raw.payload_printable };
  if (!raw || typeof raw !== "object" || depth > 7) return null;
  for (const [key, value] of Object.entries(raw).slice(0, 200)) {
    if (
      [
        "body",
        "http_body",
        "request_body",
        "payload_printable",
        "payload",
      ].includes(key.toLowerCase()) &&
      typeof value === "string" &&
      value
    )
      return { name: key, value };
    if (
      key === "key" &&
      ["http_body", "request_body", "payload"].includes(
        String(value).toLowerCase(),
      ) &&
      raw.value
    )
      return { name: value, value: String(raw.value) };
  }
  for (const value of Object.values(raw).slice(0, 200)) {
    if (value && typeof value === "object") {
      const found = findPayload(value, depth + 1);
      if (found) return found;
    }
  }
  return null;
}

function packetHex(encoded) {
  try {
    const binary = atob(encoded),
      size = Math.min(binary.length, 4096),
      lines = [];
    for (let offset = 0; offset < size; offset += 16) {
      const bytes = [...binary.slice(offset, offset + 16)].map((c) =>
        c.charCodeAt(0),
      );
      const hex = bytes
        .map((n) => n.toString(16).padStart(2, "0"))
        .join(" ")
        .padEnd(47);
      const ascii = bytes
        .map((n) => (n >= 32 && n < 127 ? String.fromCharCode(n) : "."))
        .join("");
      lines.push(
        offset.toString(16).padStart(4, "0") + "  " + hex + "  " + ascii,
      );
    }
    return (
      `${binary.length} captured bytes${binary.length > size ? " · preview limited to 4096 bytes" : ""}\n\n` +
      lines.join("\n")
    );
  } catch (_) {
    return "Packet data is not valid base64";
  }
}

async function openDetail(index) {
  if (!items[index]) return;
  selectedIndex = index;
  selectedRecord = null;
  detailAbort?.abort();
  detailAbort = new AbortController();
  const ticket = ++detailSequence;
  const recordKind = kind,
    item = items[index];
  $("detailTitle").textContent =
    (kind === "requests" ? "Request" : "Record") + " #" + item.id;
  $("detailSource").textContent =
    kind === "requests"
      ? "HTTP request metadata"
      : layers[item.source] || tabs[kind][0];
  $("downloadRecord").disabled = true;
  $("detailBody").replaceChildren(node("p", "", "กำลังโหลดหลักฐาน…"));
  $("previousDetail").disabled = index === 0;
  $("nextDetail").disabled = index === items.length - 1;
  if (!$("detailDialog").open) $("detailDialog").showModal();
  try {
    const row = await request(
      "/api/v1/dashboard/data/" + recordKind + "/" + item.id,
      {},
      detailAbort,
    );
    if (ticket !== detailSequence || !$("detailDialog").open) return;
    selectedRecord = row;
    $("downloadRecord").disabled = false;
    const content = node("div");
    if (recordKind === "requests") {
      content.append(
        node("h3", "", "Request target"),
        node("pre", "evidence-code", row.path),
      );
      content.append(node("h3", "", "Transport & response"));
      metadata(content, [
        ["Observed (UTC)", date(row.observed_at)],
        ["Method", row.method],
        ["Host", row.host],
        ["Gateway peer", row.source_ip],
        ["HTTP status", row.status],
        ["Latency", (row.duration_ns / 1e6).toFixed(2) + " ms"],
        ["Protocol", row.raw.RequestProtocol],
        ["Router", row.router],
        ["Request bytes", row.raw.RequestContentSize],
        ["Response bytes", row.raw.DownstreamContentSize],
      ]);
      content.append(node("h3", "", "Captured request headers"));
      const headers = row.capture?.headers || {};
      if (Object.keys(headers).length) {
        const list = node("dl", "header-list");
        Object.entries(headers).forEach(([key, value]) => {
          list.append(node("dt", "", key), node("dd", "", String(value)));
        });
        content.append(list);
      } else
        content.append(
          node(
            "p",
            "payload-note",
            "รายการนี้ไม่มี headers ใน access log เดิม Headers แบบ allowlist จะเริ่มมีในคำขอที่บันทึกหลังปรับ gateway",
          ),
        );
      content.append(
        node("h3", "", "HTTP body / payload"),
        node(
          "p",
          "payload-note",
          "ไม่ได้บันทึก HTTP body หรือ PCAP สำหรับรายการนี้ ดู raw metadata ด้านล่าง หรือเปิด Incidents เพื่อดู payload ที่ sensor เก็บไว้",
        ),
      );
    } else if (recordKind === "incidents") {
      const raw = row.event?.event || row.event || {};
      metadata(content, [
        ["Alert ID", row.alert_id],
        ["Layer", layers[row.source] || row.source],
        ["Source IP", row.source_ip],
        ["Endpoint", raw.agent?.name],
        ["Time (UTC)", date(row.created_at)],
        ["Severity", row.severity],
      ]);
      content.append(
        node("h3", "", "Detection evidence"),
        node("p", "detail-analysis", row.reason),
      );
      if (raw.src_ip || raw.dest_ip) {
        content.append(node("h3", "", "Network packet metadata"));
        metadata(content, [
          ["Source", `${raw.src_ip || "—"}:${raw.src_port || "—"}`],
          ["Destination", `${raw.dest_ip || "—"}:${raw.dest_port || "—"}`],
          ["Protocol", raw.proto],
          ["Interface", raw.in_iface],
          ["Signature", raw.alert?.signature],
          ["HTTP target", raw.http?.url],
        ]);
      }
      if (row.analysis) {
        content.append(node("h3", "", "AI analysis"));
        const analysis = node("div", "detail-analysis");
        analysis.append(
          node("strong", "", row.analysis.attack_type || "Analysis"),
          node("p", "", row.analysis.reasoning || "No reasoning recorded"),
        );
        content.append(analysis);
      }
      content.append(node("h3", "", "Captured payload"));
      const payload = findPayload(raw);
      content.append(
        payload
          ? node("pre", "evidence-code", payload.name + ":\n" + payload.value)
          : node(
              "p",
              "payload-note",
              "Sensor ไม่ได้บันทึก payload สำหรับเหตุการณ์นี้ หลักฐานดิบที่มีอยู่แสดงด้านล่าง",
            ),
      );
      if (typeof raw.packet === "string" && raw.packet) {
        content.append(
          node("h3", "", "Captured network frame · hex / ASCII"),
          node("pre", "evidence-code", packetHex(raw.packet)),
        );
      }
    } else if (["decisions", "approvals"].includes(recordKind)) {
      metadata(content, [
        ["Action", row.action],
        ["Target", row.target],
        ["Duration", row.duration_seconds + " s"],
        ["Policy verdict", row.policy_verdict],
        ["Status", row.status],
        ["Confidence", row.confidence],
      ]);
      content.append(
        node("h3", "", "Policy reasoning"),
        node("p", "detail-analysis", row.policy_reason),
      );
      if (row.incident_alert_id) {
        const button = node(
          "button",
          "workspace-button",
          "Open linked incident evidence",
        );
        button.addEventListener("click", async () => {
          try {
            const incident = await request(
              "/api/v1/incidents/" + encodeURIComponent(row.incident_alert_id),
            );
            const block = node(
              "pre",
              "evidence-code",
              JSON.stringify(incident, null, 2),
            );
            button.replaceWith(block);
          } catch (error) {
            button.textContent = "โหลดหลักฐานไม่ได้: " + error.message;
          }
        });
        content.append(node("h3", "", "Linked incident"), button);
      }
    } else
      metadata(
        content,
        Object.entries(row)
          .filter(([, value]) => value === null || typeof value !== "object")
          .map(([key, value]) => [key, value]),
      );
    const details = node("details"),
      summary = node("summary", "", "Raw JSON evidence");
    details.append(
      summary,
      node("pre", "evidence-code", JSON.stringify(row, null, 2)),
    );
    if (
      !["requests", "incidents", "decisions", "approvals"].includes(recordKind)
    )
      details.open = true;
    content.append(details);
    $("detailBody").replaceChildren(...content.childNodes);
  } catch (error) {
    if (ticket !== detailSequence || error.name === "AbortError") return;
    $("detailBody").replaceChildren(
      node("p", "table-error", "โหลดรายละเอียดไม่ได้: " + error.message),
    );
  }
}

async function act(item, verb, button) {
  if (
    !confirm(
      `${verb === "approve" ? "อนุมัติและดำเนินการ" : "ปฏิเสธ"} decision #${item.id}: ${item.action} ${item.target || "(ไม่มี target)"}?`,
    )
  )
    return;
  button.disabled = true;
  try {
    const result = await request(`/api/v1/decisions/${item.id}/${verb}`, {
      method: "POST",
    });
    if (result.status === "failed")
      alert("ดำเนินการไม่สำเร็จ: " + JSON.stringify(result.result));
    await Promise.all([loadSummary(), loadPage()]);
  } catch (error) {
    alert("ดำเนินการไม่ได้: " + error.message);
    button.disabled = false;
  }
}
function updateLab() {
  const enabled = agentStatus.attack?.mode === "lab";
  $("runLab").disabled = labBusy || !enabled;
  $("labScope").textContent =
    `${agentStatus.attack?.mode || "Unavailable"} · target: juicelab.lab.local`;
}
async function runLab() {
  if (labBusy || agentStatus.attack?.mode !== "lab") return;
  if (
    !confirm(
      "Run controlled campaign against juicelab.lab.local? การทดสอบจะสร้าง alerts จริง",
    )
  )
    return;
  labBusy = true;
  updateLab();
  $("labResult").textContent = "กำลังทดสอบ…";
  try {
    const result = await request("/api/v1/attacks/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "juicelab.lab.local" }),
    });
    $("labResult").textContent =
      `Run #${result.id}: detected ${result.techniques_detected}/${result.techniques_total} · ${result.new_alerts} alerts`;
    state.snapshot = null;
    await loadPage();
    loadSummary();
  } catch (error) {
    $("labResult").textContent = "ทดสอบไม่สำเร็จ: " + error.message;
  } finally {
    labBusy = false;
    updateLab();
  }
}

$("recordTabs").addEventListener("click", (event) => {
  const button = event.target.closest("[data-kind]");
  if (button) location.hash = button.dataset.kind;
});
$("recordTabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const buttons = [...document.querySelectorAll("[data-kind]")],
    index = buttons.indexOf(document.activeElement);
  const next =
    event.key === "Home"
      ? 0
      : event.key === "End"
        ? buttons.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) %
          buttons.length;
  buttons[next].focus();
  location.hash = buttons[next].dataset.kind;
});
window.addEventListener("hashchange", () => switchTab(location.hash.slice(1)));
$("recordSearch").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(filtersChanged, 350);
});
["sourceFilter", "recordSeverity", "recordStatus"].forEach((id) =>
  $(id).addEventListener("change", filtersChanged),
);
$("pageSize").addEventListener("change", () => {
  state.page_size = Number($("pageSize").value);
  state.page = 1;
  loadPage();
});
$("firstPage").addEventListener("click", () => go(1));
$("prevPage").addEventListener("click", () => go(state.page - 1));
$("nextPage").addEventListener("click", () => go(state.page + 1));
$("lastPage").addEventListener("click", () => go(state.pages));
$("goPage").addEventListener("click", () => go($("pageNumber").value));
$("pageNumber").addEventListener("keydown", (event) => {
  if (event.key === "Enter") go($("pageNumber").value);
});
$("refreshDashboard").addEventListener("click", () => {
  state.page = 1;
  state.snapshot = null;
  loadSummary();
  loadPage();
});
$("closeDetail").addEventListener("click", () => $("detailDialog").close());
$("detailDialog").addEventListener("close", () => {
  detailSequence++;
  detailAbort?.abort();
  selectedRecord = null;
});
$("previousDetail").addEventListener("click", () =>
  openDetail(selectedIndex - 1),
);
$("nextDetail").addEventListener("click", () => openDetail(selectedIndex + 1));
$("downloadRecord").addEventListener("click", () => {
  if (!selectedRecord) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(selectedRecord, null, 2)], {
      type: "application/json",
    }),
  );
  const link = node("a");
  link.href = url;
  link.download = `edgeguard-${kind}-${selectedRecord.id}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("runLab").addEventListener("click", runLab);
["brandLink", "missionLink", "footerMissionLink"].forEach(
  (id) => ($(id).href = PREFIX + "/mission"),
);
function clock() {
  $("clock").textContent =
    new Date().toLocaleTimeString("en-GB", { timeZone: "UTC", hour12: false }) +
    " UTC";
}
clock();
setInterval(clock, 1000);
$("pageSize").value = matchMedia("(max-width: 600px)").matches ? "5" : "10";
loadSummary();
switchTab(location.hash.slice(1));
setInterval(() => {
  if (document.hidden) return;
  loadSummary();
  if (
    state.page === 1 &&
    !$("detailDialog").open &&
    !document.activeElement.matches("input,select")
  ) {
    state.snapshot = null;
    loadPage();
  }
}, 30000);
