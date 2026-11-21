(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const n = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  };
  const uuid = () => {
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  const time = (value) =>
    value
      ? new Date(value)
          .toISOString()
          .replace("T", " ")
          .replace(/\.\d+Z$/, " UTC")
      : "Unavailable";
  async function api(path, options = {}) {
    const response = await fetch(prefix + "/api/v1/cases" + path, {
      ...options,
      signal: AbortSignal.timeout(45000),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("Unexpected response · HTTP " + response.status);
    }
    if (!response.ok) {
      const error = new Error(
        typeof data.detail === "string"
          ? data.detail
          : "Invalid request · HTTP " + response.status,
      );
      error.status = response.status;
      if (response.status === 403) sessionStorage.removeItem("opkey");
      throw error;
    }
    return data;
  }
  function attach(parent, kind, row) {
    const section = n("section", undefined, "case-section");
    section.setAttribute("aria-label", "Candidate evidence graph");
    section.innerHTML = `<h3>Candidate evidence graph</h3><p class="case-help">เชื่อมโยงหลักฐานรอบรายการนี้เพียง 1 hop · IP หรือเวลาใกล้กันไม่ยืนยันว่าเป็นผู้โจมตีเดียวกัน · timestamp มาจากแหล่งข้อมูลและยังไม่ได้ยืนยัน clock</p>
      <details class="case-create"><summary>Create case snapshot</summary><form class="case-form"><label>Window around event time<select name="minutes"><option value="5">±5 minutes</option><option value="15" selected>±15 minutes</option><option value="30">±30 minutes</option><option value="60">±60 minutes</option></select></label><label>Declared by · self-reported<input name="author" required minlength="2" maxlength="80" autocomplete="off" /></label><label>Investigation purpose / evidence<textarea name="reason" required minlength="8" maxlength="2000" rows="3"></textarea></label><button class="workspace-button case-save">Save candidate graph</button></form></details>
      <p class="case-status" role="status"></p><div class="case-actions"><button class="quiet-button case-load">Load saved cases</button></div><div class="case-saved"></div><div class="case-pager case-history-pager"><button class="quiet-button case-previous">Previous</button><span>—</span><button class="quiet-button case-next">Next</button></div><div class="case-result"></div>`;
    parent.append(section);
    const $ = (selector) => section.querySelector(selector),
      form = $("form"),
      save = $(".case-save"),
      status = $(".case-status"),
      result = $(".case-result");
    const storageKey = `edgeguard.case.pending.${kind}.${row.id}`;
    let pending,
      busy = false,
      listPage = 1,
      listTicket = 0,
      graphTicket = 0,
      current,
      nodePage = 1,
      selectedNode;
    try {
      pending = JSON.parse(sessionStorage.getItem(storageKey) || "null");
    } catch {
      /* invalid session input not used */
    }
    const message = (text, error = false) => {
      status.textContent = text;
      status.classList.toggle("error", error);
    };
    function lock(value) {
      busy = value;
      form
        .querySelectorAll("input,textarea,select")
        .forEach((e) => (e.disabled = value || !!pending));
      section.querySelectorAll("button").forEach((e) => {
        if (!e.closest(".case-checks")) e.disabled = value;
      });
      save.textContent = pending
        ? "Retry same case snapshot"
        : "Save candidate graph";
      if (!value && current) drawNodes();
    }
    function link(text, path) {
      const a = n("a", text);
      a.href = prefix + path;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      return a;
    }
    function disclosure(title, data) {
      const d = n("details");
      d.append(
        n("summary", title),
        n("pre", JSON.stringify(data, null, 2), "case-code"),
      );
      return d;
    }
    async function list() {
      const ticket = ++listTicket,
        requested = listPage;
      const data = await api(
        `?anchor_kind=${kind}&anchor_id=${row.id}&page=${requested}`,
      );
      if (ticket !== listTicket || !section.isConnected) return;
      $(".case-saved").replaceChildren();
      data.items.forEach((item) => {
        const b = n(
          "button",
          `${time(item.created_at)} · ${item.id}`,
          "case-node",
        );
        b.type = "button";
        b.disabled = busy;
        b.onclick = () => load(item.id);
        $(".case-saved").append(b);
      });
      if (!data.items.length)
        $(".case-saved").append(
          n(
            "p",
            "ยังไม่มี case snapshot ที่บันทึกสำหรับรายการนี้",
            "case-help",
          ),
        );
      $(".case-history-pager span").textContent =
        `${requested} / ${Math.max(1, Math.ceil(data.total / 10))} · ${data.total} cases`;
      $(".case-previous").disabled = busy || requested <= 1;
      $(".case-next").disabled = busy || requested * 10 >= data.total;
    }
    function nodeDetail(node) {
      selectedNode = node.id;
      const target = $(".case-node-evidence");
      target.replaceChildren(n("h4", node.title));
      const dl = n("dl");
      for (const [label, value] of [
        ["Record", node.id],
        ["Source", node.source],
        ["Observed time", time(node.observed_at)],
        ["Ingested / stored time", time(node.ingested_at)],
        ["Timeline basis", node.time_basis],
        ["Source time field", node.time_field || "Not a sensor event"],
        ["Time state", node.time_state || "Stored decision time"],
        [
          "Arrival delay",
          node.arrival_delay_seconds == null
            ? "Not measurable"
            : `${node.arrival_delay_seconds}s · source clock unverified`,
        ],
        [
          "Late / clock warning",
          node.late_arrival
            ? ">5 min ingestion delay (clock unverified)"
            : node.clock_warning
              ? "Source clock ahead of ingestion"
              : "No indicated delay / not measurable",
        ],
      ]) {
        dl.append(n("dt", label), n("dd", value));
      }
      target.append(
        dl,
        link(
          "Open stored record JSON",
          `/api/v1/dashboard/data/${node.kind}/${node.record_id}`,
        ),
      );
      const edges = current.graph.edges.filter(
        (e) => e.from === node.id || e.to === node.id,
      );
      if (!edges.length)
        target.append(n("p", "No association edge for this node", "case-help"));
      edges.forEach((edge) => {
        const block = n("div", undefined, "case-edge");
        block.append(
          n(
            "p",
            `${edge.type} · ${edge.confidence} confidence in ${edge.meaning}`,
          ),
          n(
            "p",
            `${edge.from} ${edge.direction === "directed" ? "→" : "↔"} ${edge.to}`,
          ),
          n("p", edge.reason, "case-help"),
        );
        target.append(block);
      });
      target.append(disclosure("Pinned node facts and source hash", node));
      section
        .querySelectorAll(".case-node-list button")
        .forEach((b) =>
          b.setAttribute("aria-pressed", String(b.dataset.node === node.id)),
        );
    }
    function drawNodes() {
      const graph = current.graph,
        anchor = graph.nodes.find((x) => x.id === graph.anchor);
      const others = graph.nodes.filter((x) => x.id !== graph.anchor),
        size = matchMedia("(max-width:600px)").matches ? 4 : 8;
      nodePage = Math.min(
        Math.max(1, nodePage),
        Math.max(1, Math.ceil(others.length / size)),
      );
      const shown = others.slice((nodePage - 1) * size, nodePage * size),
        height = Math.max(150, shown.length * 44 + 40);
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.classList.add("case-chart");
      svg.style.height = Math.min(420, height) + "px";
      svg.setAttribute("viewBox", `0 0 380 ${height}`);
      svg.setAttribute("role", "img");
      svg.setAttribute(
        "aria-label",
        "One-hop candidate association diagram. Dashed links mean low confidence. Complete nodes and edge reasons follow in the selectable list.",
      );
      function shape(tag, attrs, text) {
        const e = document.createElementNS(svg.namespaceURI, tag);
        Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, String(v)));
        if (text) e.textContent = text;
        svg.append(e);
        return e;
      }
      shown.forEach((node, i) => {
        const edges = graph.edges.filter(
          (e) => e.to === node.id || e.from === node.id,
        );
        const confidence = edges.some((e) => e.confidence === "high")
          ? "high"
          : edges.some((e) => e.confidence === "medium")
            ? "medium"
            : "low";
        shape("line", {
          x1: 65,
          y1: height / 2,
          x2: 220,
          y2: 40 + i * 44,
          "data-confidence": confidence,
        });
        shape("circle", { cx: 220, cy: 40 + i * 44, r: 5 });
        shape("text", { x: 232, y: 44 + i * 44 }, node.id);
      });
      shape("circle", { cx: 65, cy: height / 2, r: 8 });
      shape("text", { x: 10, y: height / 2 - 18 }, "Anchor");
      $(".case-visual").replaceChildren(svg);
      $(".case-node-list").replaceChildren();
      [anchor, ...shown].forEach((node) => {
        const b = n("button", `${node.id} · ${node.title}`, "case-node");
        b.dataset.node = node.id;
        b.type = "button";
        b.setAttribute("aria-pressed", String(selectedNode === node.id));
        b.append(n("span", `${time(node.effective_at)} · ${node.time_basis}`));
        b.onclick = () => nodeDetail(node);
        $(".case-node-list").append(b);
      });
      $(".case-node-pager span").textContent =
        `${nodePage} / ${Math.max(1, Math.ceil(others.length / size))} · ${others.length} linked nodes + anchor`;
      $(".case-node-prev").disabled = nodePage <= 1;
      $(".case-node-next").disabled = nodePage * size >= others.length;
    }
    function render(data) {
      current = data;
      nodePage = 1;
      selectedNode = undefined;
      result.replaceChildren();
      const graph = data.graph;
      result.append(
        n("h4", "Pinned candidate associations"),
        link("Case snapshot · " + data.id, "/api/v1/cases/" + data.id),
        n(
          "p",
          `${time(graph.window.start)} → ${time(graph.window.end)} · event-time window, ingestion fallback if unknown. Referenced decisions may occur later.`,
          "case-help",
        ),
        n(
          "p",
          "Dashed = low association confidence · solid = medium/high. Confidence describes an association or stored reference, never attack probability or causation.",
          "case-help",
        ),
      );
      if (graph.event_nodes_truncated || graph.decisions_truncated)
        result.append(
          n(
            "p",
            "Result truncated at the saved bounds · this snapshot is not a complete case or proof that other events do not exist",
            "case-status error",
          ),
        );
      const checks = n("div", undefined, "case-check-mount");
      result.append(checks);
      window.EdgeCaseChecks.attach(checks, data);
      const visual = n("div", undefined, "case-visual"),
        nodes = n("div", undefined, "case-node-list"),
        pager = n("div", undefined, "case-pager case-node-pager"),
        prev = n("button", "Previous", "quiet-button case-node-prev"),
        next = n("button", "Next", "quiet-button case-node-next");
      pager.append(prev, n("span"), next);
      prev.onclick = () => {
        nodePage--;
        drawNodes();
      };
      next.onclick = () => {
        nodePage++;
        drawNodes();
      };
      result.append(
        visual,
        n(
          "p",
          graph.nodes.length === 1
            ? "No linked candidates within these bounds; this does not mean no attack"
            : "Select a node to inspect both timestamps and typed association reasons",
          "case-help",
        ),
        nodes,
        pager,
        n("div", undefined, "case-node-evidence"),
        disclosure(
          "Case scope, source boundaries and pinned asset declarations",
          {
            specification: data.specification,
            content_hash: data.content_hash,
            version: graph.version,
            implementation_sha256: graph.implementation_sha256,
            source_high_water: graph.source_high_water,
            asset_context: graph.asset_context,
            late_arrival_policy: graph.late_arrival_policy,
            limits: graph.limits,
            scope: graph.scope,
          },
        ),
      );
      const exp = n("button", "Export case JSON", "quiet-button");
      exp.onclick = () => {
        const url = URL.createObjectURL(
          new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          }),
        );
        const a = n("a");
        a.href = url;
        a.download = `edgeguard-case-${data.id}.json`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      };
      result.append(exp);
      drawNodes();
      nodeDetail(graph.nodes.find((x) => x.id === graph.anchor));
    }
    async function load(id) {
      if (busy) return;
      const ticket = ++graphTicket;
      message("Loading pinned case…");
      try {
        const data = await api("/" + id);
        if (ticket !== graphTicket || !section.isConnected) return;
        render(data);
        message(
          "Saved membership is fixed · later arrivals require a new snapshot",
        );
      } catch (e) {
        message(e.message + " · retry from saved cases", true);
      }
    }
    form.onsubmit = async (event) => {
      event.preventDefault();
      if (busy) return;
      const key =
        sessionStorage.opkey ||
        prompt("Operation Key to save case snapshot")?.trim();
      if (!key) {
        message(
          "Operation Key not provided · nothing sent, draft retained",
          true,
        );
        return;
      }
      sessionStorage.opkey = key;
      pending ||= {
        id: uuid(),
        body: {
          anchor_kind: kind,
          anchor_id: row.id,
          minutes: Number(form.elements.minutes.value),
          declared_by: form.elements.author.value.trim(),
          rationale: form.elements.reason.value.trim(),
        },
      };
      sessionStorage.setItem(storageKey, JSON.stringify(pending));
      lock(true);
      message("Saving bounded case snapshot · no enforcement or AI judgement…");
      try {
        const data = await api("/" + pending.id, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-Operation-Key": key,
          },
          body: JSON.stringify(pending.body),
        });
        pending = null;
        sessionStorage.removeItem(storageKey);
        render(data);
        message(
          "Case saved · original evidence and previous cases remain unchanged",
        );
        listPage = 1;
        await list();
      } catch (error) {
        if ([403, 422].includes(error.status)) {
          pending = null;
          sessionStorage.removeItem(storageKey);
        }
        message(
          error.message +
            (pending
              ? " · retry same snapshot; input and UUID retained"
              : " · correct input and retry; draft retained"),
          true,
        );
      } finally {
        lock(false);
        await list().catch(() => {});
      }
    };
    $(".case-load").onclick = () =>
      list().catch((e) =>
        message(e.message + " · retry Load saved cases", true),
      );
    $(".case-previous").onclick = () => {
      if (!busy) {
        listPage = Math.max(1, listPage - 1);
        list().catch((e) => message(e.message, true));
      }
    };
    $(".case-next").onclick = () => {
      if (!busy) {
        listPage++;
        list().catch((e) => message(e.message, true));
      }
    };
    if (pending) {
      form.elements.minutes.value = pending.body.minutes;
      form.elements.author.value = pending.body.declared_by;
      form.elements.reason.value = pending.body.rationale;
      $(".case-create").open = true;
      lock(false);
      message("Unresolved save restored · retry case " + pending.id);
    } else
      message(
        "Public reads · creating a snapshot requires Operation Key and a declared purpose",
      );
    list().catch((e) => message(e.message + " · retry Load saved cases", true));
  }
  window.EdgeCases = { attach };
})();
