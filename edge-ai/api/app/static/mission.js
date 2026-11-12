const prefix =
  location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
const byId = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
};
const icon = (name) => {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS(svg.namespaceURI, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  svg.setAttribute("aria-hidden", "true");
  return svg;
};
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
let refreshing = false,
  attackMode = "unknown",
  attackRunning = false,
  incidents = [],
  incidentsAvailable = false;
const severityColors = {
  critical: "#f33257",
  high: "#f27343",
  medium: "#eeb74c",
  low: "#21cba1",
  unknown: "#547287",
};
async function request(path, options) {
  const controller = new AbortController(),
    timer = setTimeout(
      () => controller.abort(),
      options?.method === "POST" ? 210000 : 15000,
    );
  try {
    const r = await fetch(prefix + path, {
      ...options,
      signal: controller.signal,
    });
    const data = await r.json();
    if (!r.ok)
      throw new Error(
        typeof data.detail === "string" ? data.detail : `HTTP ${r.status}`,
      );
    return data;
  } finally {
    clearTimeout(timer);
  }
}
function empty(id, message) {
  byId(id).replaceChildren(el("p", "empty", message));
}
function renderIncidents(rows) {
  incidentsAvailable = true;
  incidents = rows;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  rows.forEach(
    (row) =>
      counts[Object.hasOwn(counts, row.severity) ? row.severity : "unknown"]++,
  );
  byId("totalCount").textContent = fmt(rows.length);
  byId("highCount").textContent = fmt(counts.high + counts.critical);
  byId("mediumCount").textContent = fmt(counts.medium);
  byId("lowCount").textContent = fmt(counts.low);
  byId("donutCount").textContent = fmt(rows.length);
  let offset = 0;
  const segments = [];
  const legend = [];
  Object.entries(counts)
    .filter(([severity, count]) => count || severity !== "unknown")
    .forEach(([severity, count]) => {
      const next = offset + (rows.length ? (count / rows.length) * 100 : 0);
      segments.push(`${severityColors[severity]} ${offset}% ${next}%`);
      offset = next;
      const n = el("div", "legend-row");
      n.style.setProperty("--swatch", severityColors[severity]);
      n.append(
        el("i"),
        el("span", "", severity[0].toUpperCase() + severity.slice(1)),
        el("strong", "", fmt(count)),
      );
      legend.push(n);
    });
  byId("severityRing").style.background = rows.length
    ? `conic-gradient(${segments.join(",")})`
    : "#133145";
  byId("severityLegend").replaceChildren(...legend);
  const times = rows
    .map((r) => new Date(r.created_at).getTime())
    .filter(Number.isFinite);
  const bins = Array(24).fill(0);
  const min = Math.min(...times),
    span = Math.max(...times) - min || 1;
  times.forEach(
    (t) => bins[Math.min(23, Math.floor(((t - min) / span) * 23))]++,
  );
  const max = Math.max(...bins, 1);
  const points = bins.map((n, i) => `${(i / 23) * 400},${83 - (n / max) * 72}`);
  byId("chartLine").setAttribute("d", "M" + points.join(" L"));
  byId("chartArea").setAttribute("d", `M0,90 L${points.join(" L")} L400,90 Z`);
  const analyzed = rows.filter((r) => r.analyzed).length,
    pct = rows.length ? Math.round((analyzed / rows.length) * 100) : 0;
  byId("procLbl").textContent =
    `Analyzed ${fmt(analyzed)} / ${fmt(rows.length)}`;
  byId("analyzedPercent").textContent = pct + "%";
  byId("analysisBar").style.width = pct + "%";
  const feed = rows.slice(0, 5).map((row) => {
    const n = el("button", "feed-item");
    n.type = "button";
    n.dataset.incident = row.alert_id;
    const sev = Object.hasOwn(severityColors, row.severity)
      ? row.severity
      : "unknown";
    const badge = el("span", "severity-badge " + sev, sev.toUpperCase());
    const copy = el("span", "feed-copy");
    const title = row.attack_type || row.reason || "Awaiting analysis";
    copy.append(
      el("strong", "", title),
      el(
        "small",
        "",
        `${{ crowdsec: "HTTP-WAF", waf: "HTTP-WAF", suricata: "NETWORK-IDS", wazuh: "HOST-EDR" }[row.source] || "EVENT"} · ${row.endpoint || row.source_ip || "No source IP"}`,
      ),
    );
    n.title = title;
    const date = new Date(row.created_at);
    const time = el(
      "time",
      "feed-time",
      Number.isNaN(+date)
        ? "—"
        : date.toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" }),
    );
    n.append(badge, copy, time);
    return n;
  });
  byId("feed").replaceChildren(...feed);
  if (!feed.length) empty("feed", "ยังไม่มีเหตุการณ์");
  renderVectors();
}
function renderVectors() {
  if (!incidentsAvailable) {
    empty("vectors", "อ่านเหตุการณ์ไม่ได้");
    return;
  }
  const filter = byId("severityFilter").value;
  const selected = incidents.filter(
    (i) =>
      filter === "all" ||
      (filter === "high"
        ? ["high", "critical"].includes(i.severity)
        : i.severity === filter),
  );
  const counts = new Map();
  selected.forEach((i) => {
    const name = i.attack_type || "Awaiting analysis";
    counts.set(name, (counts.get(name) || 0) + 1);
  });
  const palette = ["#f34c68", "#ee7945", "#eeb74c", "#27c39e", "#38b7ea"];
  const nodes = [...counts]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count], i) => {
      const n = el("div", "vector-row");
      const label = el("span", "vector-label", name);
      label.title = name;
      const track = el("span", "vector-track"),
        bar = el("i");
      bar.style.width = `${(count / selected.length) * 100}%`;
      bar.style.setProperty("--vector-color", palette[i]);
      track.append(bar);
      n.append(
        label,
        track,
        el("strong", "", ((count / selected.length) * 100).toFixed(1) + "%"),
      );
      return n;
    });
  byId("vectors").replaceChildren(...nodes);
  if (!nodes.length) empty("vectors", "ไม่มีเหตุการณ์ในตัวกรองนี้");
}
function renderAgents(agents) {
  const modes = [
    ["analysis", "Incident analysis", "chip"],
    ["detection", "Threat correlation", "network"],
    ["decision", "Policy evaluation", "shield"],
    ["learning", "Incident memory", "database"],
  ];
  byId("engine").replaceChildren(
    ...modes.map(([key, label, name]) => {
      const row = el("div", "engine-layer"),
        copy = el("div");
      copy.append(
        el("strong", "", label),
        el("small", "", agents[key]?.mode || "unavailable"),
      );
      row.append(icon(name), copy);
      return row;
    }),
  );
  attackMode = agents.attack?.mode || "off";
  byId("defenseMode").textContent = agents.defense?.mode?.startsWith(
    "auto_execute",
  )
    ? "POLICY-APPROVED AUTOMATIC RESPONSE"
    : "HUMAN APPROVAL REQUIRED";
}
function renderHealth(health) {
  const names = [
    ["ollama", "chip"],
    ["crowdsec", "shield"],
    ["redis", "network"],
    ["postgres", "database"],
  ];
  let healthy = 0;
  byId("services").replaceChildren(
    ...names.map(([name, ic]) => {
      const ok = health[name] === "ok";
      if (ok) healthy++;
      const n = el("div", "service"),
        circle = el("div", "service-indicator" + (ok ? "" : " off"));
      circle.append(icon(ic));
      n.append(
        circle,
        el("strong", "", name),
        el("small", ok ? "" : "off", ok ? "Online" : "Unavailable"),
      );
      n.title = String(health[name] || "unknown");
      return n;
    }),
  );
  byId("healthyCount").textContent = healthy + " / 4";
  byId("protectionDot").className =
    "dot" + (health.crowdsec === "ok" ? "" : " off");
  byId("protectionLabel").textContent =
    health.crowdsec === "ok" ? "GATEWAY ONLINE" : "GATEWAY CHECK REQUIRED";
}
function renderDecisions(rows) {
  byId("pendingCount").textContent = fmt(
    rows.filter((d) => d.status === "pending_approval").length,
  );
  byId("executedCount").textContent = fmt(
    rows.filter((d) => d.status === "executed").length,
  );
}
function renderPackets(data) {
  byId("requestCount").textContent = fmt(data.count);
  byId("blockedCount").textContent = fmt(data.blocked_403);
  byId("trafficBars").replaceChildren(
    ...(data.packets || [])
      .slice(0, 25)
      .reverse()
      .map((row) => {
        const n = el("i", row.status === 403 ? "blocked" : "");
        n.style.height = `${Math.min(100, 15 + Math.log2((row.ms || 0) + 1) * 10)}%`;
        return n;
      }),
  );
}
function renderMemory(data) {
  byId("embeddedCount").textContent = fmt(data.embedded);
  byId("embeddingNote").textContent =
    `${data.dim}d · ${fmt(data.analyzed)} analyzed`;
  byId("embeddingBar").style.width =
    (data.analyzed ? Math.min(100, (data.embedded / data.analyzed) * 100) : 0) +
    "%";
}
function renderVisibility(data) {
  const colors = {
    online: "",
    receiving: "",
    stale: "pending",
    not_connected: "off",
    unknown: "pending",
  };
  const names = {
    http_waf: "HTTP-WAF",
    network_ids: "NETWORK-IDS",
    host_edr: "HOST-EDR",
  };
  const nodes = Object.entries(data.layers || {}).map(([key, layer]) => {
    const n = el("div", "visibility-layer"),
      ic = el("div", "layer-icon");
    ic.append(
      icon(
        key === "http_waf"
          ? "shield"
          : key === "network_ids"
            ? "network"
            : "chip",
      ),
    );
    const copy = el("div", "layer-copy");
    copy.append(
      el("strong", "", names[key] || key),
      el("small", "", layer.detail || layer.sensor),
    );
    const state = el("span", "layer-state");
    state.append(
      el("i", "dot " + (colors[layer.state] || "")),
      el("span", "", layer.label),
    );
    n.append(ic, copy, state);
    return n;
  });
  byId("visibilityLayers").replaceChildren(...nodes);
  byId("coverageCount").textContent =
    `${Object.values(data.layers || {}).filter((l) => ["online", "receiving"].includes(l.state)).length} / 3 layers`;
}
async function loadStatus() {
  if (refreshing) return;
  refreshing = true;
  byId("refresh").disabled = true;
  const specs = [
    ["/health", renderHealth],
    ["/api/v1/agents/status", renderAgents],
    ["/api/v1/incidents?limit=200", renderIncidents],
    ["/api/v1/decisions?limit=100", renderDecisions],
    ["/api/v1/packets?limit=80", renderPackets],
    ["/api/v1/learning/stats", renderMemory],
    ["/api/v1/visibility", renderVisibility],
  ];
  const results = await Promise.allSettled(
    specs.map(async ([path, render]) => {
      const value = await request(path);
      render(value);
      return value;
    }),
  );
  const failed = results.flatMap((r, i) =>
    r.status === "rejected" ? [specs[i][0] + ": " + r.reason.message] : [],
  );
  if (results[1].status === "rejected") {
    attackMode = "unknown";
    empty("engine", "อ่านสถานะ Agent ไม่ได้");
    byId("defenseMode").textContent = "RESPONSE POLICY UNAVAILABLE";
  }
  if (results[2].status === "rejected") {
    incidents = [];
    incidentsAvailable = false;
    empty("feed", "อ่านเหตุการณ์ไม่ได้");
    empty("vectors", "อ่านเหตุการณ์ไม่ได้");
    empty("severityLegend", "Data unavailable");
    [
      "totalCount",
      "highCount",
      "mediumCount",
      "lowCount",
      "donutCount",
      "analyzedPercent",
    ].forEach((id) => (byId(id).textContent = "—"));
    byId("procLbl").textContent = "Incident data unavailable";
    byId("analysisBar").style.width = "0%";
    byId("severityRing").style.background = "#133145";
    byId("chartArea").setAttribute("d", "");
    byId("chartLine").setAttribute("d", "");
  }
  if (results[3].status === "rejected") {
    byId("pendingCount").textContent = "—";
    byId("executedCount").textContent = "—";
  }
  if (results[4].status === "rejected") {
    byId("requestCount").textContent = "—";
    byId("blockedCount").textContent = "—";
    empty("trafficBars", "Traffic unavailable");
  }
  if (results[5].status === "rejected") {
    byId("embeddedCount").textContent = "—";
    byId("embeddingNote").textContent = "Memory data unavailable";
    byId("embeddingBar").style.width = "0%";
  }
  if (results[6].status === "rejected") {
    renderVisibility({
      layers: Object.fromEntries(
        ["http_waf", "network_ids", "host_edr"].map((name) => [
          name,
          {
            state: "unknown",
            label: "UNAVAILABLE",
            detail: "Sensor heartbeat unavailable",
          },
        ]),
      ),
    });
    byId("coverageCount").textContent = "— / 3 layers";
  }
  if (results[0].status === "rejected") {
    renderHealth({});
    byId("protectionLabel").textContent = "HEALTH DATA UNAVAILABLE";
  }
  byId("connectionDot").className = "dot" + (failed.length ? " pending" : "");
  byId("connectionLabel").textContent = failed.length
    ? "PARTIAL DATA"
    : "SYSTEM CONNECTED";
  byId("refreshInfo").textContent = failed.length
    ? `โหลดข้อมูลบางส่วนไม่ได้ — ${failed.join("; ")} · กดโหลดใหม่เพื่อลองอีกครั้ง`
    : `อัปเดต ${new Date().toLocaleTimeString("th-TH")} · โหลดใหม่ทุก 30 วินาที`;
  byId("attack").disabled = attackRunning || attackMode !== "lab";
  byId("attackHint").textContent =
    attackMode === "lab"
      ? "Juice Shop เท่านั้น · การทดสอบสร้าง alert จริง"
      : "ปิดการทดสอบอยู่ หรืออ่านสถานะไม่ได้";
  byId("refresh").disabled = false;
  refreshing = false;
}
async function testLiveFire() {
  if (attackMode !== "lab" || attackRunning) return;
  if (!confirm("เริ่มทดสอบกับ Juice Shop ใน lab? การทดสอบจะสร้าง alert จริง"))
    return;
  attackRunning = true;
  byId("attack").disabled = true;
  byId("attackResult").textContent = "กำลังทดสอบ กรุณารอผล…";
  try {
    const r = await request("/api/v1/attacks/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "juicelab.lab.local" }),
    });
    byId("attackResult").textContent =
      `ทดสอบ #${r.id}: ตรวจพบ ${r.techniques_detected}/${r.techniques_total} เทคนิค · alert ใหม่ ${r.new_alerts}`;
  } catch (e) {
    byId("attackResult").textContent = "ทดสอบไม่สำเร็จ: " + e.message;
  } finally {
    attackRunning = false;
    byId("attack").disabled = attackMode !== "lab";
  }
}
byId("feed").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-incident]");
  if (!button) return;
  const dialog = byId("incidentDialog");
  byId("incidentDetail").textContent = "กำลังโหลดหลักฐาน…";
  dialog.showModal();
  try {
    const row = await request(
      "/api/v1/incidents/" + encodeURIComponent(button.dataset.incident),
    );
    const title = el("strong", "", row.analysis?.attack_type || row.kind);
    byId("incidentDetail").replaceChildren(
      title,
      el("p", "", `Source: ${row.source_ip || "unknown"} · ${row.created_at}`),
      el("p", "", row.reason),
      el("pre", "", row.analysis?.reasoning || "รอการวิเคราะห์"),
    );
  } catch (e) {
    byId("incidentDetail").textContent = "โหลดไม่ได้: " + e.message;
  }
});
byId("closeDialog").addEventListener("click", () =>
  byId("incidentDialog").close(),
);
byId("refresh").addEventListener("click", loadStatus);
byId("attack").addEventListener("click", testLiveFire);
byId("severityFilter").addEventListener("change", renderVectors);
Object.entries({
  dashboardLink: "requests",
  incidentsLink: "incidents",
  approvalsLink: "approvals",
}).forEach(([id, tab]) => {
  byId(id).href = prefix + "/dashboard#" + tab;
});
function clock() {
  byId("clock").textContent =
    new Date().toLocaleTimeString("en-GB", { hour12: false, timeZone: "UTC" }) +
    " UTC";
}
clock();
setInterval(clock, 1000);
loadStatus();
setInterval(() => {
  if (!document.hidden) loadStatus();
}, 30000);
