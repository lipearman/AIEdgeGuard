(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const $ = (id) => document.getElementById("eval" + id);
  const root = document.getElementById("evaluationWorkspace");
  const n = (tag, text, cls) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = String(text);
    if (cls) element.className = cls;
    return element;
  };
  const date = (value) =>
    value
      ? new Date(value)
          .toISOString()
          .replace("T", " ")
          .replace(/\.\d+Z$/, " UTC")
      : "—";
  const uuid = () => {
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    const h = [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  root.innerHTML = `
    <div class="eval-collector" aria-live="polite"><p id="evalCollector">Loading collector continuity…</p><p id="evalSince" class="eval-help"></p></div>
    <p class="eval-help">ประเมินเฉพาะปริมาณ HTTP ต่อ host/router · label เป็นข้อมูลที่ผู้ดูแลระบุ · ช่วงข้อมูลขาดและ label ที่ยังไม่ทราบจะไม่ถูกนับเป็นข้อมูลปกติ · ไม่มีการเปลี่ยนกฎหรือบล็อกอัตโนมัติ</p>
    <p id="evalNotice" class="eval-status" role="status"></p>
    <div class="eval-columns"><aside aria-labelledby="evalDatasetsTitle">
      <h3 id="evalDatasetsTitle">Dataset snapshots</h3><p class="eval-help">ข้อมูลตรึงตามเวลาที่สร้าง · เลือกเพื่อดู windows และติดป้ายกำกับ</p>
      <div id="evalDatasets" class="eval-list"></div><div class="eval-pager"><button id="evalDatasetPrev" class="quiet-button">Previous</button><span id="evalDatasetPage">—</span><button id="evalDatasetNext" class="quiet-button">Next</button></div>
      <details id="evalCreate" class="eval-create"><summary>Create snapshot</summary><p class="eval-help">ช่วงเวลา UTC ตรงทุก 5 นาที · ยาว 5 ชั่วโมง–7 วัน · สิ้นสุดก่อนเวลาปัจจุบันอย่างน้อย 10 นาที · collector coverage ไม่ใช่หลักประกันว่า upstream ส่ง log ครบ</p>
        <details><summary>Choose observed host / router</summary><div id="evalSegments" class="eval-list"></div><div class="eval-pager"><button id="evalSegmentPrev" class="quiet-button">Previous</button><span id="evalSegmentPage">—</span><button id="evalSegmentNext" class="quiet-button">Next</button></div><p id="evalSegmentStatus" class="eval-status" role="status"></p></details>
        <form id="evalCreateForm"><fieldset id="evalCreateFields" class="eval-form"><label>Exact HTTP host<input id="evalHost" required maxlength="255" placeholder="Host from retained traffic" /></label><label>Exact router · may be empty<input id="evalRouter" maxlength="255" placeholder="RouterName from access log" /></label>
          <label>Start · UTC<input id="evalStart" type="datetime-local" step="300" required /></label><label>End · UTC<input id="evalEnd" type="datetime-local" step="300" required /></label><label>Declared by · self-reported<input id="evalCreator" required minlength="2" maxlength="80" autocomplete="off" /></label><label>Scope / evidence<textarea id="evalCreateReason" rows="3" required minlength="8" maxlength="2000"></textarea></label></fieldset>
          <button id="evalCreateSave" class="workspace-button">Create immutable snapshot</button></form><p id="evalCreateStatus" class="eval-status" role="status">การเขียนข้อมูลใช้ Operation Key</p>
      </details>
    </aside><section aria-labelledby="evalSelectionTitle"><h3 id="evalSelectionTitle">Select a dataset</h3><p id="evalSelectionSummary" class="eval-help">ยังไม่มีชุดข้อมูลที่เลือก สร้าง snapshot จาก traffic ที่เก็บไว้ หรือเลือกชุดข้อมูลทางซ้าย</p><div id="evalSelectionMeta"></div>
      <div id="evalSelected" hidden><p id="evalReadiness" class="eval-status"></p>
        <table class="eval-table eval-windows"><caption class="sr-only">Frozen HTTP windows and latest operator labels</caption><thead><tr><th>Window · UTC</th><th>Requests / errors</th><th>Coverage</th><th>Latest label</th><th>Action</th></tr></thead><tbody id="evalWindows"></tbody></table>
        <div class="eval-pager"><button id="evalWindowPrev" class="quiet-button">Previous</button><span id="evalWindowPage">—</span><button id="evalWindowNext" class="quiet-button">Next</button></div>
        <section id="evalLabelEditor" class="eval-labels" hidden aria-labelledby="evalLabelTitle"><h3 id="evalLabelTitle">Window label</h3><p id="evalLabelSaved" class="eval-help"></p>
          <form id="evalLabelForm"><fieldset id="evalLabelFields" class="eval-form"><div class="eval-two"><label>Verdict<select id="evalVerdict"><option value="unknown">Unknown · ยังไม่ทราบ</option><option value="normal">Normal · มีหลักฐานว่าเป็นปกติ</option><option value="lab_attack">Lab attack · ยืนยันการทดสอบที่อนุญาต</option></select></label><label>Declared by · self-reported<input id="evalLabelAuthor" required minlength="2" maxlength="80" autocomplete="off" /></label></div><label>Reason / supporting evidence<textarea id="evalLabelReason" required minlength="8" maxlength="2000" rows="3"></textarea></label></fieldset>
          <div class="eval-actions"><button id="evalLabelSave" class="workspace-button">Append label revision</button><button id="evalLabelReload" type="button" class="quiet-button">Reload latest revision</button></div></form><p id="evalLabelStatus" class="eval-status" role="status"></p>
          <details id="evalHistory"><summary>Label revision history</summary><div id="evalHistoryItems"></div><div class="eval-pager"><button id="evalHistoryPrev" class="quiet-button">Previous</button><span id="evalHistoryPage">—</span><button id="evalHistoryNext" class="quiet-button">Next</button></div></details>
        </section>
      </div>
    </section></div>
    <section id="evalReplay" class="eval-replay" hidden aria-labelledby="evalReplayTitle"><h3 id="evalReplayTitle">Chronological replay</h3><p class="eval-help">Train 60% / calibration 20% / test 20% · ทุก training window ต้อง coverage ครบและมี label Normal · พารามิเตอร์คงที่ ไม่มีการเลือกโมเดลหรือเปลี่ยน threshold ของระบบจริง</p>
      <div class="eval-actions"><button id="evalRun" class="workspace-button">Run CPU comparison</button><button id="evalExportDataset" class="quiet-button">Export dataset JSON</button></div><p id="evalRunStatus" class="eval-status" role="status"></p>
      <label>Saved replay reports<select id="evalRuns"><option value="">Select a saved report…</option></select></label><div class="eval-pager"><button id="evalRunPrev" class="quiet-button">Previous</button><span id="evalRunPage">—</span><button id="evalRunNext" class="quiet-button">Next</button></div>
      <div id="evalReport"></div>
    </section>`;
  let dataset,
    selectedWindow = null,
    report,
    listingPage = 1,
    segmentPage = 1,
    windowPage = 1,
    historyPage = 1,
    runPage = 1;
  let selectionTicket = 0,
    listTicket = 0,
    segmentTicket = 0,
    reportTicket = 0,
    labelRevision = 0,
    labelConflict = false,
    busy = false,
    initialized = false;
  let createRetry, labelRetry, labelDataset, runRetry;
  const pagers = new Map();
  const pendingKey = "edgeguard.evaluation.pending";
  try {
    const saved = JSON.parse(sessionStorage.getItem(pendingKey) || "{}");
    createRetry = saved.create;
    labelRetry = saved.label;
    labelDataset = saved.labelDataset;
    runRetry = saved.run;
  } catch {
    /* corrupt session state is not used */
  }
  const persist = () =>
    sessionStorage.setItem(
      pendingKey,
      JSON.stringify({
        create: createRetry,
        label: labelRetry,
        labelDataset,
        run: runRetry,
      }),
    );
  const status = (name, text, error = false) => {
    $(name).textContent = text;
    $(name).classList.toggle("error", error);
  };
  async function api(path, options = {}) {
    const response = await fetch(prefix + "/api/v1/evaluation" + path, {
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
          : "Invalid request · check fields (HTTP " + response.status + ")",
      );
      error.status = response.status;
      if (response.status === 403) sessionStorage.removeItem("opkey");
      throw error;
    }
    return data;
  }
  function key() {
    const value =
      sessionStorage.opkey ||
      prompt("Operation Key for evaluation writes")?.trim();
    if (value) sessionStorage.opkey = value;
    return value;
  }
  async function write(path, method, payload) {
    const value = key();
    if (!value) {
      const error = new Error(
        "Operation Key not provided · nothing sent, draft retained",
      );
      error.cancelled = true;
      throw error;
    }
    return api(path, {
      method,
      headers: { "Content-Type": "application/json", "X-Operation-Key": value },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
    });
  }
  function pager(name, page, total, size) {
    pagers.set(name, [page, total, size]);
    $(name + "Page").textContent =
      `${page} / ${Math.max(1, Math.ceil(total / size))} · ${total} items`;
    $(name + "Prev").disabled = busy || page <= 1;
    $(name + "Next").disabled = busy || page * size >= total;
  }
  function lock(value) {
    busy = value;
    $("CreateSave").disabled = value;
    $("CreateFields").disabled = value || !!createRetry;
    $("LabelFields").disabled = value || !!labelRetry;
    $("LabelSave").disabled = value || labelConflict;
    $("LabelReload").disabled = value;
    $("Run").disabled = value;
    $("Runs").disabled = value;
    root.querySelectorAll(".eval-item").forEach((el) => {
      el.disabled = value || (!!createRetry && !!el.closest("#evalSegments"));
    });
    root.querySelectorAll("#evalWindows button").forEach((el) => {
      el.disabled = value;
    });
    for (const [name, args] of pagers) pager(name, ...args);
  }
  function link(text, path) {
    const a = n("a", text);
    a.href = prefix + "/api/v1/evaluation" + path;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    return a;
  }
  function jsonDetails(title, data) {
    const d = n("details");
    d.append(
      n("summary", title),
      n("pre", JSON.stringify(data, null, 2), "eval-code"),
    );
    return d;
  }
  function exportJson(data, filename) {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
    );
    const a = n("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function loadList() {
    const ticket = ++listTicket;
    const data = await api(`/datasets?page=${listingPage}&page_size=10`);
    if (ticket !== listTicket) return;
    $("Datasets").replaceChildren();
    if (!data.items.length)
      $("Datasets").append(
        n(
          "p",
          "ยังไม่มี snapshot · สร้างได้จากข้อมูลที่เก็บไว้ ผลวัดจะยังไม่พร้อมจนกว่าจะมี coverage และ label ครบ",
          "eval-help",
        ),
      );
    data.items.forEach((item) => {
      const button = n("button", item.specification.host, "eval-item");
      button.type = "button";
      button.append(
        n("span", item.specification.router || "(empty router)"),
        n(
          "span",
          date(item.specification.start) + " → " + date(item.specification.end),
        ),
      );
      button.setAttribute("aria-current", String(dataset?.id === item.id));
      button.disabled = busy;
      button.onclick = () =>
        selectDataset(item.id).catch((e) => status("Notice", e.message, true));
      $("Datasets").append(button);
    });
    pager("Dataset", listingPage, data.total, 10);
    if (!initialized && !data.total) $("Create").open = true;
  }
  async function loadSegments() {
    const ticket = ++segmentTicket,
      requested = segmentPage;
    try {
      const data = await api(`/segments?page=${segmentPage}&page_size=10`);
      if (ticket !== segmentTicket || requested !== segmentPage) return;
      $("Segments").replaceChildren();
      data.items.forEach((item) => {
        const button = n("button", item.host, "eval-item");
        button.type = "button";
        button.append(
          n(
            "span",
            `${item.router || "(empty router)"} · ${item.requests} retained requests`,
          ),
        );
        button.disabled = busy || !!createRetry;
        button.onclick = () => {
          $("Host").value = item.host;
          $("Router").value = item.router;
          status(
            "SegmentStatus",
            "Selected exact host/router · review time range and evidence before creating",
          );
        };
        $("Segments").append(button);
      });
      pager("Segment", segmentPage, data.total, 10);
      status(
        "SegmentStatus",
        data.items.length
          ? "Retained observations only · not verified assets"
          : "No retained host/router observations on this page",
      );
    } catch (e) {
      status(
        "SegmentStatus",
        e.message + " · enter exact values manually or refresh",
        true,
      );
    }
  }
  function latestLabels() {
    return new Map(
      (dataset?.labels || []).map((label) => [label.window_index, label]),
    );
  }
  function renderWindows() {
    if (!dataset) return;
    const windows = dataset.snapshot.windows,
      labels = latestLabels(),
      trainEnd = Math.floor(windows.length * 0.6);
    const ready = windows
      .slice(0, trainEnd)
      .filter(
        (w) => w.eligible && labels.get(w.index)?.label === "normal",
      ).length;
    status(
      "Readiness",
      `Training readiness: ${ready} / ${trainEnd} windows · ${windows.filter((w) => w.eligible).length} / ${windows.length} have complete collector coverage & retention evidence`,
    );
    $("Windows").replaceChildren();
    const size = matchMedia("(max-width: 600px)").matches ? 4 : 8;
    windowPage = Math.min(
      windowPage,
      Math.max(1, Math.ceil(windows.length / size)),
    );
    windows.slice((windowPage - 1) * size, windowPage * size).forEach((w) => {
      const tr = n(
        "tr",
        undefined,
        w.index === selectedWindow ? "eval-selected" : "",
      );
      const values = [
        date(w.start) + ` · #${w.index}`,
        `${w.requests} / ${w.errors}`,
        w.eligible
          ? "Eligible · 300s"
          : `Excluded · ${w.collector_covered_seconds}s / retention unknown`,
        labels.get(w.index)?.label || "Unknown · unreviewed",
      ];
      values.forEach((value, i) => {
        const td = n("td", value);
        td.dataset.label = [
          "Window · UTC",
          "Requests / errors",
          "Coverage",
          "Latest label",
        ][i];
        tr.append(td);
      });
      const cell = n("td"),
        button = n("button", "Label #" + w.index, "quiet-button");
      button.type = "button";
      button.disabled = busy;
      button.onclick = () => openWindow(w.index);
      cell.append(button);
      cell.dataset.label = "Action";
      tr.append(cell);
      $("Windows").append(tr);
    });
    pager("Window", windowPage, windows.length, size);
  }
  async function selectDataset(id, preserve = false) {
    if (busy) return;
    if (
      (runRetry && runRetry.dataset !== id) ||
      (labelRetry && labelDataset !== id)
    ) {
      status(
        "Notice",
        "Retry the unresolved write on its original dataset before switching",
        true,
      );
      return;
    }
    if (
      !preserve &&
      selectedWindow !== null &&
      ($("LabelReason").value.trim() || labelRetry)
    ) {
      status(
        "Notice",
        "มี label draft ค้างอยู่ · บันทึกหรือกด Clear draft ก่อนเปลี่ยนชุดข้อมูล",
        true,
      );
      return;
    }
    const ticket = ++selectionTicket;
    status("Notice", "Loading immutable dataset…");
    const data = await api("/datasets/" + encodeURIComponent(id));
    if (ticket !== selectionTicket) return;
    dataset = data;
    report = undefined;
    reportTicket++;
    runPage = 1;
    if (!preserve) {
      selectedWindow = null;
      windowPage = 1;
      $("LabelEditor").hidden = true;
    }
    $("Selected").hidden = false;
    $("Replay").hidden = false;
    $("SelectionTitle").textContent = data.specification.host;
    $("SelectionSummary").textContent =
      `${data.specification.router || "(empty router)"} · ${date(data.specification.start)} → ${date(data.specification.end)}`;
    $("SelectionMeta").replaceChildren(
      link("Immutable dataset · " + data.id, "/datasets/" + data.id),
      jsonDetails("Dataset scope, author and SHA-256", {
        specification: data.specification,
        content_hash: data.content_hash,
        created_at: data.created_at,
        scope: data.snapshot.scope,
      }),
    );
    $("Report").replaceChildren();
    status(
      "RunStatus",
      "Select a saved report or run a new comparison · existing reports retain their label revisions",
    );
    renderWindows();
    await Promise.all([loadRuns(), loadList()]);
    status(
      "Notice",
      "Dataset loaded · raw traffic and previous reports remain unchanged",
    );
  }
  function openWindow(index) {
    if (busy || (selectedWindow !== null && $("LabelReason").value.trim())) {
      status("LabelStatus", "บันทึกหรือ Clear draft ก่อนเปลี่ยน window", true);
      return;
    }
    selectedWindow = index;
    historyPage = 1;
    labelConflict = false;
    const saved = latestLabels().get(index);
    labelRevision = saved?.revision || 0;
    $("LabelTitle").textContent =
      `Window #${index} · ${date(dataset.snapshot.windows[index].start)}`;
    $("LabelSaved").textContent = saved
      ? `Saved revision ${saved.revision} · ${saved.label} · ${saved.declared_by} · ${date(saved.created_at)} · ${saved.rationale}`
      : "No saved label · Unknown until explicitly reviewed";
    $("Verdict").value = saved?.label || "unknown";
    $("LabelReason").value = "";
    $("LabelEditor").hidden = false;
    $("LabelSave").disabled = false;
    status(
      "LabelStatus",
      "Append a separate operator annotation · shared key does not verify the declared name",
    );
    renderWindows();
    loadHistory().catch((e) => status("LabelStatus", e.message, true));
  }
  async function loadHistory() {
    if (selectedWindow === null) return;
    const identity = dataset.id,
      index = selectedWindow,
      requested = historyPage;
    const data = await api(
      `/datasets/${identity}/labels/${index}?page=${requested}`,
    );
    if (
      identity !== dataset.id ||
      index !== selectedWindow ||
      requested !== historyPage
    )
      return;
    $("HistoryItems").replaceChildren(
      ...data.items.map((item) =>
        n(
          "p",
          `Revision ${item.revision} · ${item.label} · ${item.declared_by} · ${date(item.created_at)} · ${item.rationale}`,
        ),
      ),
    );
    if (!data.items.length)
      $("HistoryItems").append(n("p", "No label revisions"));
    pager("History", historyPage, data.total, 50);
  }
  async function loadRuns() {
    const identity = dataset.id,
      requested = runPage;
    const data = await api(
      `/datasets/${identity}/runs?page=${requested}&page_size=10`,
    );
    if (dataset.id !== identity || runPage !== requested) return;
    $("Runs").replaceChildren(n("option", "Select a saved report…"));
    data.items.forEach((item) => {
      const option = n(
        "option",
        `${date(item.created_at)} · ${item.state} · ${item.id}`,
      );
      option.value = item.id;
      $("Runs").append(option);
    });
    pager("Run", runPage, data.total, 10);
  }
  function renderReport(data) {
    report = data;
    const r = data.report,
      target = $("Report");
    target.replaceChildren();
    target.append(
      n(
        "h4",
        r.state === "replayed"
          ? "Replay comparison · descriptive results"
          : "Not ready for evaluation",
      ),
    );
    target.append(
      n(
        "p",
        r.reason ||
          "Rates describe this operator-labeled sample only. Correlated windows and limited traffic scope do not establish general detection accuracy.",
        "eval-help",
      ),
    );
    target.append(link("Pinned report · " + data.id, "/runs/" + data.id));
    if (r.metrics) {
      target.append(
        n(
          "p",
          "TP = attack flagged · FP = normal flagged · TN = normal unflagged · FN = attack missed. Rates require ≥5 attack and ≥20 normal eligible windows per split; this floor is not statistical validation.",
          "eval-help",
        ),
      );
      for (const split of ["test", "calibration"]) {
        target.append(
          n(
            "h4",
            split === "test"
              ? "Held-out test windows"
              : "Calibration windows · no parameter tuning",
          ),
        );
        for (const method of ["median_mad", "ewma"]) {
          const m = r.metrics[split][method],
            group = n("div");
          group.append(
            n(
              "p",
              method === "ewma"
                ? "EWMA · λ 0.2 / k 3"
                : "Frozen median / MAD baseline",
            ),
          );
          const table = n("table", undefined, "eval-table"),
            head = n("thead"),
            hr = n("tr"),
            body = n("tbody"),
            row = n("tr");
          for (const [title, value] of [
            ["TP", m.tp],
            ["FP", m.fp],
            ["TN", m.tn],
            ["FN", m.fn],
            ["Excluded", m.excluded],
          ]) {
            hr.append(n("th", title));
            row.append(n("td", value));
          }
          head.append(hr);
          body.append(row);
          table.append(head, body);
          group.append(table);
          group.append(
            n(
              "p",
              m.recall === null || m.false_positive_rate === null
                ? "Rates withheld · insufficient labeled data"
                : `Recall ${(100 * m.recall).toFixed(1)}% · False-positive rate ${(100 * m.false_positive_rate).toFixed(1)}% · descriptive only`,
              "eval-help",
            ),
          );
          target.append(group);
        }
      }
    }
    target.append(
      jsonDetails("Pinned labels, parameters, code hash and predictions", r),
    );
    const exportButton = n(
      "button",
      "Export pinned report JSON",
      "quiet-button",
    );
    exportButton.onclick = () =>
      exportJson(data, `edgeguard-replay-${data.id}.json`);
    target.append(exportButton);
  }
  $("CreateForm").onsubmit = async (e) => {
    e.preventDefault();
    if (busy) return;
    if (labelRetry || runRetry || $("LabelReason").value.trim()) {
      status(
        "CreateStatus",
        "Resolve the current label draft or pending replay first",
        true,
      );
      return;
    }
    if (!createRetry) {
      const start = new Date($("Start").value + "Z"),
        end = new Date($("End").value + "Z");
      if (
        ![start, end].every((d) => Number.isFinite(+d) && +d % 300000 === 0) ||
        end - start < 18000000 ||
        end - start > 604800000 ||
        +end > Date.now() - 600000
      ) {
        status(
          "CreateStatus",
          "ใช้ช่วง UTC ตรงทุก 5 นาที ยาว 5 ชั่วโมง–7 วัน และสิ้นสุดอย่างน้อย 10 นาทีก่อนเวลาปัจจุบัน",
          true,
        );
        return;
      }
      createRetry = {
        id: uuid(),
        payload: {
          host: $("Host").value.trim(),
          router: $("Router").value.trim(),
          start: start.toISOString(),
          end: end.toISOString(),
          declared_by: $("Creator").value.trim(),
          rationale: $("CreateReason").value.trim(),
        },
      };
    }
    persist();
    lock(true);
    status(
      "CreateStatus",
      "Saving snapshot · retry uses the same UUID and input…",
    );
    try {
      const result = await write(
        "/datasets/" + createRetry.id,
        "PUT",
        createRetry.payload,
      );
      createRetry = undefined;
      lock(false);
      listingPage = 1;
      $("Create").open = false;
      await selectDataset(result.id);
      status("CreateStatus", "Snapshot saved");
    } catch (error) {
      if ([403, 422].includes(error.status) || error.cancelled)
        createRetry = undefined;
      status(
        "CreateStatus",
        error.message +
          (createRetry
            ? " · Retry same snapshot; fields locked to preserve input"
            : " · draft retained"),
        true,
      );
    } finally {
      persist();
      lock(false);
      $("CreateSave").textContent = createRetry
        ? "Retry same snapshot"
        : "Create immutable snapshot";
    }
  };
  $("LabelForm").onsubmit = async (e) => {
    e.preventDefault();
    if (busy || labelConflict || selectedWindow === null) return;
    labelRetry ||= {
      window_index: selectedWindow,
      expected_revision: labelRevision,
      label: $("Verdict").value,
      declared_by: $("LabelAuthor").value.trim(),
      rationale: $("LabelReason").value.trim(),
      request_id: uuid(),
    };
    labelDataset = dataset.id;
    persist();
    lock(true);
    status("LabelStatus", "Saving append-only revision…");
    try {
      const saved = await write(
        `/datasets/${dataset.id}/labels`,
        "POST",
        labelRetry,
      );
      labelRetry = undefined;
      labelRevision = saved.revision;
      $("LabelReason").value = "";
      dataset.labels = dataset.labels
        .filter((l) => l.window_index !== selectedWindow)
        .concat(saved);
      $("LabelSaved").textContent =
        `Saved revision ${saved.revision} · ${saved.label} · ${saved.declared_by} · ${date(saved.created_at)} · ${saved.rationale}`;
      status(
        "LabelStatus",
        "Label saved · existing replay reports keep their original label revisions",
      );
      renderWindows();
      await loadHistory();
    } catch (error) {
      if ([403, 422].includes(error.status) || error.cancelled)
        labelRetry = undefined;
      if (error.status === 409) {
        labelConflict = true;
        labelRetry = undefined;
      }
      status(
        "LabelStatus",
        error.message +
          (labelConflict
            ? " · Reload latest revision, review your retained draft, then resubmit"
            : " · draft retained; retry the same request"),
        true,
      );
    } finally {
      persist();
      lock(false);
      $("LabelSave").textContent = labelRetry
        ? "Retry same label revision"
        : "Append label revision";
    }
  };
  $("LabelReload").onclick = async () => {
    if (busy || selectedWindow === null) return;
    if (labelRetry) {
      status(
        "LabelStatus",
        "Retry the unresolved save before reloading; request UUID retained",
        true,
      );
      return;
    }
    try {
      const fresh = await api("/datasets/" + dataset.id);
      dataset.labels = fresh.labels;
      const saved = latestLabels().get(selectedWindow);
      labelRevision = saved?.revision || 0;
      labelConflict = false;
      $("LabelSaved").textContent = saved
        ? `Saved revision ${saved.revision} · ${saved.label} · ${saved.declared_by} · ${saved.rationale}`
        : "No saved label";
      $("LabelSave").disabled = false;
      renderWindows();
      await loadHistory();
      status(
        "LabelStatus",
        "Latest revision loaded · draft preserved; review before resubmitting",
      );
    } catch (error) {
      status("LabelStatus", error.message, true);
    }
  };
  const clear = n("button", "Clear draft", "quiet-button");
  clear.type = "button";
  clear.onclick = () => {
    if (labelRetry) {
      status(
        "LabelStatus",
        "Retry unresolved save before clearing its UUID",
        true,
      );
      return;
    }
    $("LabelReason").value = "";
    status("LabelStatus", "Draft cleared");
  };
  $("LabelReload").after(clear);
  $("Run").onclick = async () => {
    if (busy || !dataset) return;
    if (labelRetry || $("LabelReason").value.trim()) {
      status(
        "RunStatus",
        "Save or clear the label draft first · replay uses saved revisions only",
        true,
      );
      return;
    }
    runRetry ||= { id: uuid(), dataset: dataset.id };
    persist();
    lock(true);
    status(
      "RunStatus",
      "Running CPU comparison · no traffic generation or defense action…",
    );
    try {
      const saved = await write(
        `/datasets/${dataset.id}/runs/${runRetry.id}`,
        "POST",
      );
      runRetry = undefined;
      renderReport(saved);
      runPage = 1;
      await loadRuns();
      $("Runs").value = saved.id;
      status(
        "RunStatus",
        "Saved immutable report · label changes require a new replay",
      );
    } catch (error) {
      if (error.cancelled) runRetry = undefined;
      status(
        "RunStatus",
        error.message +
          (runRetry ? " · Retry returns the same pinned run" : ""),
        true,
      );
    } finally {
      persist();
      lock(false);
      $("Run").textContent = runRetry
        ? "Retry same replay"
        : "Run CPU comparison";
    }
  };
  $("Runs").onchange = async () => {
    if (!$("Runs").value) return;
    const ticket = ++reportTicket,
      identity = dataset.id;
    try {
      const saved = await api("/runs/" + $("Runs").value);
      if (ticket === reportTicket && dataset.id === identity)
        renderReport(saved);
    } catch (error) {
      status("RunStatus", error.message + " · reselect report to retry", true);
    }
  };
  $("ExportDataset").onclick = () =>
    dataset && exportJson(dataset, `edgeguard-dataset-${dataset.id}.json`);
  function pageButtons(name, get, set, load) {
    for (const [suffix, delta] of [
      ["Prev", -1],
      ["Next", 1],
    ])
      $(name + suffix).onclick = () => {
        if (busy) return;
        set(Math.max(1, get() + delta));
        load().catch((e) => status("Notice", e.message, true));
      };
  }
  pageButtons(
    "Dataset",
    () => listingPage,
    (v) => (listingPage = v),
    loadList,
  );
  pageButtons(
    "Segment",
    () => segmentPage,
    (v) => (segmentPage = v),
    loadSegments,
  );
  pageButtons(
    "History",
    () => historyPage,
    (v) => (historyPage = v),
    loadHistory,
  );
  pageButtons(
    "Run",
    () => runPage,
    (v) => (runPage = v),
    loadRuns,
  );
  pageButtons(
    "Window",
    () => windowPage,
    (v) => (windowPage = v),
    async () => renderWindows(),
  );
  async function refresh() {
    const results = await Promise.allSettled([
      api("/status"),
      loadList(),
      loadSegments(),
    ]);
    if (results[0].status === "fulfilled") {
      const data = results[0].value;
      status(
        "Collector",
        `Collector: ${data.state} · last tick ${date(data.latest_tick)}`,
        data.state !== "collecting",
      );
      $("Since").textContent =
        `Continuity available since ${date(data.first_tick)} · historic gaps remain unknown`;
    } else
      status(
        "Collector",
        "Collector status unavailable · refresh to retry",
        true,
      );
    if (results[1].status === "rejected")
      status("Notice", results[1].reason.message + " · refresh to retry", true);
    if (!initialized) {
      if (createRetry) {
        const p = createRetry.payload;
        for (const [name, value] of Object.entries({
          Host: p.host,
          Router: p.router,
          Start: p.start.slice(0, 16),
          End: p.end.slice(0, 16),
          Creator: p.declared_by,
          CreateReason: p.rationale,
        }))
          $(name).value = value;
        $("Create").open = true;
        $("CreateSave").textContent = "Retry same snapshot";
        status(
          "CreateStatus",
          "Unresolved snapshot restored · retry uses the original UUID and input",
        );
      }
      const pendingDataset = labelRetry ? labelDataset : runRetry?.dataset;
      if (pendingDataset) {
        try {
          await selectDataset(pendingDataset);
          if (labelRetry) {
            openWindow(labelRetry.window_index);
            $("Verdict").value = labelRetry.label;
            $("LabelAuthor").value = labelRetry.declared_by;
            $("LabelReason").value = labelRetry.rationale;
            $("LabelSave").textContent = "Retry same label revision";
            status(
              "LabelStatus",
              "Unresolved label restored · retry the same request UUID",
            );
          }
          if (runRetry) {
            $("Run").textContent = "Retry same replay";
            status(
              "RunStatus",
              "Unresolved replay restored · retry the same run UUID",
            );
          }
        } catch (error) {
          status(
            "Notice",
            error.message +
              " · pending UUID retained; reload to retry recovery",
            true,
          );
        }
      }
      lock(false);
    }
    initialized = true;
  }
  window.addEventListener("beforeunload", (event) => {
    if (busy || $("LabelReason").value.trim()) {
      event.preventDefault();
      event.returnValue = "";
    }
  });
  window.EdgeEvaluation = { refresh };
})();
