(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const $ = (id) => document.getElementById(id);
  const n = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (cls) node.className = cls;
    return node;
  };
  // Static application markup only. All API values below use textContent/value.
  $("assetsWorkspace").innerHTML = `
    <div class="intel-heading"><div><h3>Asset inventory</h3><p>ทะเบียนที่ผู้ดูแลยืนยัน · ผูก host, application และ service กับหลักฐาน</p></div><button id="assetNew" class="workspace-button">New asset</button></div>
    <p class="intel-scope">ชื่อผู้บันทึกเป็นข้อมูลที่กรอกเอง · การบันทึกใช้ Operation Key · ทะเบียนนี้ไม่ยืนยันว่าเครื่องออนไลน์หรือมีช่องโหว่</p>
    <div class="asset-columns">
      <section aria-labelledby="assetRegistryTitle"><h4 id="assetRegistryTitle">Registered assets</h4>
        <form id="assetFilters" class="asset-filters"><label>Search name / owner / software<input id="assetSearch" maxlength="120" type="search" /></label><label>Kind<select id="assetKindFilter"><option value="all">All kinds</option><option value="host">Host</option><option value="application">Application</option><option value="service">Service</option></select></label><label>Status<select id="assetStatusFilter"><option value="active">Active</option><option value="retired">Retired</option><option value="all">All statuses</option></select></label><button class="quiet-button">Search</button></form>
        <p id="assetListStatus" class="intel-status" role="status">Loading inventory…</p><div id="assetList" class="asset-list"></div>
        <div class="intel-pager"><button id="assetPrevious" class="quiet-button">Previous</button><span id="assetPage">—</span><button id="assetNext" class="quiet-button">Next</button></div>
      </section>
      <section aria-labelledby="assetEditorTitle"><div class="intel-heading"><h4 id="assetEditorTitle">New asset</h4><button id="assetReload" class="quiet-button" hidden>Reload latest revision</button></div>
        <p id="assetEditStatus" class="intel-status" role="status">กรอกข้อมูลและ bindings เพื่อบันทึก revision แรก</p>
        <form id="assetForm" class="asset-form">
          <fieldset><legend>Identity &amp; ownership</legend><div class="asset-fields">
            <label>Asset name<input id="assetName" required minlength="2" maxlength="120" /></label><label>Kind<select id="assetKind"><option value="host">Host</option><option value="application">Application</option><option value="service">Service</option></select></label>
            <label>Owner<input id="assetOwner" maxlength="120" /></label><label>Criticality<select id="assetCriticality"><option>unknown</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Status<select id="assetStatus"><option>active</option><option>retired</option></select></label><label>Parent host<select id="assetParent"><option value="">No parent host</option></select></label>
            <label>OS name<input id="assetOs" maxlength="120" /></label><label>OS version<input id="assetOsVersion" maxlength="100" /></label>
          </div></fieldset>
          <fieldset id="assetEndpointFields"><legend>Host bindings</legend><div class="asset-observed"><label>Observed Wazuh endpoint<select id="assetObserved"><option value="">Select evidence to prefill…</option></select></label><button id="assetObservedRefresh" type="button" class="quiet-button">Refresh observed</button></div><p id="assetObservedStatus" class="intel-scope" role="status"></p><div class="asset-fields"><label>Wazuh agent IDs · comma separated<input id="assetAgents" maxlength="200" placeholder="001, 002" /></label><label>Endpoint IPs · comma separated<input id="assetIps" maxlength="1000" placeholder="Endpoint addresses only" /></label></div><p class="intel-scope">Agent 000 คือ manager ใช้ผูกไม่ได้ · IP ที่ซ้ำในทะเบียนไม่ใช้เป็น unique identity</p></fieldset>
          <fieldset id="assetRouteFields" hidden><legend>Application / service bindings</legend><label>One route per line · host | router | path prefix<textarea id="assetRoutes" rows="3" maxlength="14000" placeholder="app.example.com | app@docker | /app"></textarea></label><p class="intel-scope">ตรงตาม host และ router ที่บันทึกไว้ ใช้ path prefix ที่เฉพาะที่สุด: /app จับ /app และ /app/… แต่ไม่จับ /application · ไม่ถอดรหัส URL เพื่อผูกตัวตน</p></fieldset>
          <fieldset><legend>Software declared by operator</legend><label>One product per line · vendor | product | version | CPE 2.3 (optional) | version scheme<textarea id="assetSoftware" rows="3" maxlength="28000" placeholder="Vendor | Product | 1.2.3 | cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:* | numeric_dot"></textarea></label><p class="intel-scope">CPE ต้องตรงกับผลิตภัณฑ์จริง · version scheme ใช้ unknown หรือ numeric_dot (ระบุเองสำหรับเลขคั่นจุด) · ข้อมูลนี้ยังไม่ยืนยันช่องโหว่</p></fieldset>
          <fieldset><legend>Revision record</legend><label>Declared by · self-reported label<input id="assetDeclaredBy" required minlength="2" maxlength="80" /></label><label>Reason / evidence for this change<textarea id="assetRationale" required minlength="8" maxlength="2000" rows="3"></textarea></label></fieldset>
          <button id="assetSave" class="workspace-button">Save new revision</button>
        </form>
        <button id="assetAssess" class="quiet-button" type="button" hidden>Check CVE applicability</button><details id="assetHistory"><summary>Revision history</summary><div id="assetHistoryItems"></div><div class="intel-pager"><button id="assetHistoryPrevious" class="quiet-button">Previous revisions</button><span id="assetHistoryPage">—</span><button id="assetHistoryNext" class="quiet-button">Next revisions</button></div></details>
      </section>
    </div>`;
  let page = 1,
    pages = 1,
    historyPage = 1,
    historyPages = 1,
    id,
    revision = 0,
    dirty = false,
    saving = false,
    conflict = false,
    retry,
    listAbort,
    detailAbort,
    hostRows = [],
    observedRows = [];
  function uuid() {
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    const h = [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  async function api(path, options = {}, signal) {
    const response = await fetch(prefix + "/api/v1/assets" + path, {
      ...options,
      signal: signal || AbortSignal.timeout(15000),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("Unexpected response · HTTP " + response.status);
    }
    if (!response.ok) {
      const detail = Array.isArray(data.detail)
        ? data.detail
            .map((e) => e.loc.slice(1).join(".") + ": " + e.msg)
            .join("; ")
        : data.detail;
      const error = new Error(detail || "HTTP " + response.status);
      error.status = response.status;
      throw error;
    }
    return data;
  }
  function status(text, error = false) {
    $("assetEditStatus").textContent = text;
    $("assetEditStatus").classList.toggle("error", error);
  }
  function focusEditor() {
    $("assetEditorTitle").tabIndex = -1;
    $("assetEditorTitle").focus({ preventScroll: true });
    $("assetEditorTitle").scrollIntoView({ block: "start" });
  }
  function scope() {
    const host = $("assetKind").value === "host";
    $("assetEndpointFields").hidden = !host;
    $("assetRouteFields").hidden = host;
    $("assetParent").disabled = host;
  }
  async function parents() {
    try {
      hostRows = (await api("/hosts")).items;
      const selected = $("assetParent").value;
      const none = n("option", "No parent host");
      none.value = "";
      $("assetParent").replaceChildren(
        none,
        ...hostRows.map((r) => {
          const option = n("option", `${r.name} · ${r.status}`);
          option.value = r.asset_id;
          return option;
        }),
      );
      if (selected && !hostRows.some((r) => r.asset_id === selected)) {
        const option = n("option", "Previously selected host · unavailable");
        option.value = selected;
        $("assetParent").append(option);
      }
      $("assetParent").value = selected;
    } catch (e) {
      status(
        "Parent hosts unavailable: " +
          e.message +
          ". Refresh inventory to retry.",
        true,
      );
    }
  }
  async function observed() {
    $("assetObservedRefresh").disabled = true;
    try {
      const data = await api("/observed");
      observedRows = data.items;
      const none = n("option", "Select evidence to prefill…");
      none.value = "";
      $("assetObserved").replaceChildren(
        none,
        ...observedRows.map((r, i) => {
          const option = n(
            "option",
            `${r.agent_id} · ${r.name || "unnamed"} · ${r.ip || "no IP"}`,
          );
          option.value = i;
          return option;
        }),
      );
      $("assetObservedStatus").textContent =
        `${observedRows.length} observed endpoints · latest retained evidence, not online status. Select to prefill; inspect before saving.`;
    } catch (e) {
      $("assetObservedStatus").textContent =
        "Observed endpoints unavailable: " + e.message;
    } finally {
      $("assetObservedRefresh").disabled = false;
    }
  }
  async function listing() {
    listAbort?.abort();
    const controller = (listAbort = new AbortController());
    $("assetPrevious").disabled = $("assetNext").disabled = true;
    $("assetListStatus").textContent = "Loading inventory…";
    try {
      const data = await api(
        "?" +
          new URLSearchParams({
            page,
            page_size: 10,
            q: $("assetSearch").value.trim(),
            kind: $("assetKindFilter").value,
            status: $("assetStatusFilter").value,
          }),
        {},
        controller.signal,
      );
      if (controller !== listAbort) return;
      page = data.page;
      pages = data.pages;
      $("assetPage").textContent = `${page} / ${pages}`;
      $("assetListStatus").classList.remove("error");
      $("assetListStatus").textContent =
        `${data.total} registered assets · current revisions`;
      $("assetList").replaceChildren(
        ...data.items.map((r) => {
          const button = n("button", undefined, "asset-entry");
          button.type = "button";
          button.setAttribute("aria-pressed", String(r.asset_id === id));
          button.append(
            n("strong", r.payload.name),
            n(
              "span",
              `${r.payload.kind} · ${r.payload.criticality} · ${r.payload.status}`,
            ),
            n(
              "small",
              `${r.payload.owner || "Owner not recorded"} · revision ${r.revision}`,
            ),
          );
          button.addEventListener("click", () => select(r.asset_id));
          return button;
        }),
      );
      if (!data.items.length)
        $("assetList").append(
          n(
            "p",
            "No assets match these filters. Use New asset to register a host, application or service.",
            "intel-scope",
          ),
        );
      $("assetPrevious").disabled = page <= 1;
      $("assetNext").disabled = page >= pages;
    } catch (e) {
      if (e.name !== "AbortError") {
        $("assetList").replaceChildren();
        $("assetListStatus").textContent =
          "Inventory unavailable: " + e.message + ". Search to retry.";
        $("assetListStatus").classList.add("error");
      }
    }
  }
  function newAsset() {
    if (saving || (dirty && !confirm("Discard unsaved asset draft?"))) return;
    detailAbort?.abort();
    id = uuid();
    revision = 0;
    retry = null;
    conflict = false;
    $("assetForm").reset();
    $("assetKind").disabled = false;
    $("assetSave").disabled = false;
    $("assetReload").hidden = true;
    $("assetHistory").hidden = true;
    $("assetAssess").hidden = true;
    $("assetEditorTitle").textContent = "New asset";
    dirty = false;
    scope();
    status("กรอกข้อมูลและ bindings เพื่อบันทึก revision แรก");
  }
  function lines(value, keys) {
    const entries = value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (entries.length > 20)
      throw new Error("Use at most 20 entries per binding/software field.");
    return entries.map((line, index) => {
      const values = line.split("|").map((part) => part.trim());
      if (values.length !== keys.length)
        throw new Error(`Line ${index + 1}: use ${keys.join(" | ")}.`);
      return Object.fromEntries(keys.map((key, index) => [key, values[index]]));
    });
  }
  function softwareRows(value) {
    const entries = value
      .split(/\r?\n/)
      .map((v) => v.trim())
      .filter(Boolean);
    if (entries.length > 20)
      throw new Error("Use at most 20 software entries.");
    return entries.map((line, index) => {
      const v = line.split("|").map((v) => v.trim());
      if (v.length < 3 || v.length > 5)
        throw new Error(
          `Software line ${index + 1}: vendor | product | version | optional CPE | optional scheme`,
        );
      return {
        vendor: v[0],
        product: v[1],
        version: v[2],
        cpe23: v[3] || "",
        version_scheme: v[4] || "unknown",
      };
    });
  }
  function fill(row) {
    const p = row.payload;
    revision = row.revision;
    for (const [field, value] of Object.entries({
      assetName: p.name,
      assetKind: p.kind,
      assetOwner: p.owner,
      assetCriticality: p.criticality,
      assetStatus: p.status,
      assetOs: p.os_name,
      assetOsVersion: p.os_version,
      assetAgents: p.agent_ids.join(", "),
      assetIps: p.ips.join(", "),
      assetRoutes: p.routes
        .map((r) => `${r.host} | ${r.router} | ${r.path_prefix}`)
        .join("\n"),
      assetSoftware: p.software
        .map(
          (r) =>
            `${r.vendor} | ${r.product} | ${r.version} | ${r.cpe23 || ""} | ${r.version_scheme || "unknown"}`,
        )
        .join("\n"),
      assetDeclaredBy: row.declared_by,
      assetRationale: "",
    }))
      $(field).value = value || "";
    if (
      p.parent_host_id &&
      ![...$("assetParent").options].some((o) => o.value === p.parent_host_id)
    ) {
      const option = n("option", "Mapped parent host");
      option.value = p.parent_host_id;
      $("assetParent").append(option);
    }
    $("assetParent").value = p.parent_host_id || "";
    $("assetKind").disabled = true;
    $("assetSave").disabled = false;
    $("assetEditorTitle").textContent = `${p.name} · revision ${revision}`;
    $("assetReload").hidden = false;
    $("assetHistory").hidden = false;
    $("assetAssess").hidden = false;
    dirty = false;
    conflict = false;
    retry = null;
    scope();
  }
  async function select(next, reload = false) {
    if (
      saving ||
      (dirty && !confirm("Discard unsaved draft and load the latest revision?"))
    )
      return;
    detailAbort?.abort();
    const controller = (detailAbort = new AbortController());
    $("assetSave").disabled = true;
    status("Loading asset revision…");
    try {
      await parents();
      const data = await api("/" + next + "?page=1", {}, controller.signal);
      if (controller !== detailAbort) return;
      id = next;
      historyPage = 1;
      fill(data.current);
      renderHistory(data);
      status(
        `${reload ? "Reloaded" : "Loaded"} revision ${revision} · ${new Date(data.current.created_at).toLocaleString()} · ${data.current.authentication}`,
      );
      await listing();
      focusEditor();
    } catch (e) {
      if (e.name !== "AbortError") {
        status(
          "Could not load asset: " + e.message + ". Select it again to retry.",
          true,
        );
        $("assetSave").disabled = conflict;
      }
    }
  }
  function renderHistory(data) {
    historyPage = data.page;
    historyPages = data.pages;
    $("assetHistoryPage").textContent = `${historyPage} / ${historyPages}`;
    $("assetHistoryPrevious").disabled = historyPage <= 1;
    $("assetHistoryNext").disabled = historyPage >= historyPages;
    $("assetHistoryItems").replaceChildren(
      ...data.items.map((r) => {
        const details = n("details");
        details.append(
          n(
            "summary",
            `Revision ${r.revision} · ${r.payload.status} · ${new Date(r.created_at).toLocaleString()}`,
          ),
          n("p", `${r.declared_by} (self-reported) · ${r.authentication}`),
          n("p", r.rationale),
          n("pre", JSON.stringify(r.payload, null, 2), "evidence-code"),
        );
        return details;
      }),
    );
  }
  async function history() {
    const assetId = id;
    $("assetHistoryPrevious").disabled = $("assetHistoryNext").disabled = true;
    try {
      const data = await api(`/${assetId}?page=${historyPage}`);
      if (id === assetId) renderHistory(data);
    } catch (e) {
      if (id === assetId) {
        status(
          "History unavailable: " +
            e.message +
            ". Reopen Revision history to retry.",
          true,
        );
        $("assetHistoryPrevious").disabled = historyPage <= 1;
        $("assetHistoryNext").disabled = historyPage >= historyPages;
      }
    }
  }
  const csv = (value) =>
    value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  $("assetForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (saving || conflict) return;
    try {
      const host = $("assetKind").value === "host";
      const payload = {
        name: $("assetName").value.trim(),
        kind: $("assetKind").value,
        owner: $("assetOwner").value.trim(),
        criticality: $("assetCriticality").value,
        status: $("assetStatus").value,
        os_name: $("assetOs").value.trim(),
        os_version: $("assetOsVersion").value.trim(),
        agent_ids: host ? csv($("assetAgents").value) : [],
        ips: host ? csv($("assetIps").value) : [],
        routes: host
          ? []
          : lines($("assetRoutes").value, ["host", "router", "path_prefix"]),
        software: softwareRows($("assetSoftware").value),
        parent_host_id: host ? null : $("assetParent").value || null,
      };
      const body = {
        payload,
        declared_by: $("assetDeclaredBy").value.trim(),
        rationale: $("assetRationale").value.trim(),
        expected_revision: revision,
      };
      const signature = JSON.stringify(body);
      if (!retry || retry.signature !== signature)
        retry = { signature, request_id: uuid() };
      let key = sessionStorage.getItem("opkey") || "";
      if (!key) {
        key =
          prompt("Operation Key for saving an asset revision")?.trim() || "";
        if (!key) {
          status("Save cancelled. Your draft is retained.");
          return;
        }
        sessionStorage.setItem("opkey", key);
      }
      saving = true;
      $("assetSave").disabled = true;
      $("assetForm").inert = true;
      status("Saving revision…");
      const data = await api("/" + id, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Operation-Key": key },
        body: JSON.stringify({ ...body, request_id: retry.request_id }),
      });
      fill(data.asset);
      historyPage = 1;
      await history();
      await Promise.all([listing(), parents()]);
      status(
        `Saved revision ${revision}${data.replayed ? " · retry recovered" : ""}${data.warnings?.length ? " · " + data.warnings.join(" · ") : ""}`,
      );
    } catch (e) {
      if (e.status === 403) sessionStorage.removeItem("opkey");
      if (e.status === 409 && e.message.startsWith("Asset changed."))
        conflict = true;
      status(
        e.message +
          (conflict
            ? " Draft retained. Reload latest revision before saving again."
            : " Draft retained. Retry Save new revision."),
        true,
      );
    } finally {
      saving = false;
      $("assetForm").inert = false;
      $("assetSave").disabled = conflict;
    }
  });
  $("assetObserved").addEventListener("change", () => {
    if ($("assetObserved").value === "") return;
    const r = observedRows[Number($("assetObserved").value)];
    if (!r) return;
    if (!$("assetName").value) $("assetName").value = r.name || "";
    $("assetAgents").value = r.agent_id;
    $("assetIps").value = r.ip || "";
    dirty = true;
    $("assetObservedStatus").textContent =
      `Prefilled from evidence last seen ${new Date(r.last_seen).toLocaleString()}. Inspect mappings before saving; not current online status.`;
  });
  $("assetNew").addEventListener("click", () => {
    $("assetAssess").addEventListener("click", () => {
      if (dirty) {
        status(
          "Save or reload this draft before checking the stored revision.",
          true,
        );
        return;
      }
      window.EdgeKnowledge.selectAsset(id);
    });
    newAsset();
    focusEditor();
  });
  $("assetForm").addEventListener("input", () => {
    dirty = true;
    if (!saving && !conflict)
      status(`Unsaved draft · based on revision ${revision}`);
  });
  $("assetKind").addEventListener("change", scope);
  window.addEventListener("beforeunload", (event) => {
    if (dirty) {
      event.preventDefault();
      event.returnValue = "";
    }
  });
  $("assetReload").addEventListener("click", () => select(id, true));
  $("assetObservedRefresh").addEventListener("click", observed);
  $("assetFilters").addEventListener("submit", (event) => {
    event.preventDefault();
    page = 1;
    listing();
  });
  $("assetPrevious").addEventListener("click", () => {
    if (page > 1) {
      page--;
      listing();
    }
  });
  $("assetNext").addEventListener("click", () => {
    if (page < pages) {
      page++;
      listing();
    }
  });
  $("assetHistoryPrevious").addEventListener("click", () => {
    if (historyPage > 1) {
      historyPage--;
      history();
    }
  });
  $("assetHistoryNext").addEventListener("click", () => {
    if (historyPage < historyPages) {
      historyPage++;
      history();
    }
  });
  $("assetHistory").addEventListener("toggle", () => {
    if ($("assetHistory").open && revision) history();
  });
  $("assetAssess").addEventListener("click", () => {
    if (dirty) {
      status(
        "Save or reload this draft before checking the stored revision.",
        true,
      );
      return;
    }
    window.EdgeKnowledge.selectAsset(id);
  });
  newAsset();
  window.EdgeAssets = {
    refresh: async () => {
      await Promise.all([listing(), parents(), observed()]);
    },
  };
})();
