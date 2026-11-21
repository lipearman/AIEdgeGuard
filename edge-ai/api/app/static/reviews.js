(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const $ = (id) => document.getElementById(id);
  const node = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = String(text);
    if (cls) n.className = cls;
    return n;
  };
  const labels = {
    true_positive: "True Positive",
    false_positive: "False Positive",
    unknown: "Unknown",
  };
  let controller,
    statsBusy = false;
  const date = (value) => new Date(value).toLocaleString();
  function uuid() {
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  async function api(path, options = {}, signal) {
    const response = await fetch(prefix + "/api/v1/reviews" + path, {
      ...options,
      signal: signal || AbortSignal.timeout(15000),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("Unexpected review response · HTTP " + response.status);
    }
    if (!response.ok) {
      const error = new Error(
        typeof data.detail === "string"
          ? data.detail
          : "Review request failed · HTTP " + response.status,
      );
      error.status = response.status;
      throw error;
    }
    return data;
  }
  async function refreshStats() {
    if (statsBusy) return;
    statsBusy = true;
    try {
      const data = await api("/stats");
      if (
        !Number.isInteger(data.memory_ready) ||
        !Number.isInteger(data.eligible) ||
        !Number.isInteger(data.unreviewed)
      )
        throw new Error("Review statistics are incomplete. Refresh to retry.");
      $("reviewMemoryStatus").textContent =
        `${data.memory_ready.toLocaleString()} ready / ${data.eligible.toLocaleString()} eligible reviewed TP · ${data.unreviewed.toLocaleString()} unreviewed`;
      $("reviewMemoryCounts").textContent =
        `True Positive ${data.true_positive} · False Positive ${data.false_positive} · Unknown ${data.unknown}. ${data.identity_scope}`;
      $("reviewMemoryStatus").classList.remove("error");
    } catch (error) {
      $("reviewMemoryStatus").textContent =
        "Reviewed memory unavailable: " + error.message;
      $("reviewMemoryStatus").classList.add("error");
      $("reviewMemoryCounts").textContent = "";
    } finally {
      statsBusy = false;
    }
  }
  function attach(parent, row) {
    controller?.abort();
    controller = new AbortController();
    const signal = controller.signal;
    const section = node("section", undefined, "review-section"),
      status = node("p", "Loading analyst review…", "review-status"),
      scope = node(
        "p",
        "Reviewer labels are self-declared. Operation Key authorizes saving; review does not edit raw evidence, AI output, pending approvals or IP bans.",
        "payload-note",
      ),
      form = node("form", undefined, "review-form"),
      history = node("details", undefined, "review-history"),
      historyBody = node("div");
    section.append(node("h3", "Analyst review"), status, scope);
    parent.append(section);
    if (row.analysis?.reviewed_memory_sources?.length) {
      const sources = node("div", undefined, "review-sources");
      sources.append(
        node("p", "Reviewed memory referenced by this stored analysis:"),
      );
      row.analysis.reviewed_memory_sources.forEach((source) => {
        if (!Number.isSafeInteger(source.review_id) || source.review_id <= 0)
          return;
        const a = node(
          "a",
          `${source.alert_id} · review #${source.review_id} / revision ${source.review_revision}`,
        );
        a.href = prefix + "/api/v1/reviews/history/" + source.review_id;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        sources.append(a);
      });
      section.append(sources);
    }
    const field = (title, element, name) => {
      element.name = name;
      const label = node("label", title);
      label.append(element);
      return label;
    };
    const verdict = node("select");
    Object.entries(labels).forEach(([value, label]) => {
      const option = node("option", label);
      option.value = value;
      verdict.append(option);
    });
    verdict.value = "unknown";
    const reviewer = node("input");
    reviewer.type = "text";
    reviewer.required = true;
    reviewer.minLength = 2;
    reviewer.maxLength = 80;
    reviewer.autocomplete = "off";
    const rationale = node("textarea");
    rationale.required = true;
    rationale.minLength = 8;
    rationale.maxLength = 2000;
    rationale.placeholder = "หลักฐานที่ตรวจและเหตุผลของ revision นี้";
    const attackType = node("input");
    attackType.type = "text";
    attackType.maxLength = 160;
    attackType.placeholder = "Blank = original AI classification";
    const severity = node("select");
    ["", "low", "medium", "high", "critical"].forEach((value) => {
      const option = node("option", value || "Keep original severity");
      option.value = value;
      severity.append(option);
    });
    const fields = node("div", undefined, "review-fields");
    fields.append(
      field("Reviewer label · self-declared", reviewer, "reviewer_label"),
      field("Verdict", verdict, "verdict"),
    );
    const corrections = node("div", undefined, "review-fields");
    corrections.append(
      field(
        "Corrected attack type · optional",
        attackType,
        "corrected_attack_type",
      ),
      field("Corrected severity · optional", severity, "corrected_severity"),
    );
    const save = node("button", "Append review revision", "workspace-button"),
      reload = node("button", "Reload latest", "quiet-button");
    save.type = "submit";
    reload.type = "button";
    const controls = node("div", undefined, "review-controls");
    controls.append(save, reload);
    form.append(
      fields,
      corrections,
      field("Review rationale · required", rationale, "rationale"),
      controls,
    );
    section.append(form);
    history.append(node("summary", "Append-only review history"), historyBody);
    section.append(history);
    let revision = null,
      page = 1,
      pages = 1,
      busy = false,
      conflict = false,
      dirty = false,
      pending = null,
      readSequence = 0;
    const editable = [verdict, reviewer, rationale, attackType, severity];
    function lock() {
      if (busy)
        historyBody
          .querySelectorAll("button")
          .forEach((button) => (button.disabled = true));
      save.disabled = busy || revision === null || conflict;
      reload.disabled = busy;
      editable.forEach((e) => (e.disabled = busy || revision === null));
    }
    form.addEventListener("input", () => {
      dirty = true;
      pending = null;
    });
    form.addEventListener("change", () => {
      dirty = true;
      pending = null;
    });
    async function load() {
      const seq = ++readSequence;
      busy = true;
      lock();
      try {
        const data = await api("/" + row.id + "?page=" + page, {}, signal);
        if (signal.aborted || seq !== readSequence) return;
        if (
          !Number.isInteger(data.revision) ||
          !data.memory ||
          !Array.isArray(data.items)
        )
          throw new Error(
            "Review response is incomplete. Reload latest to retry.",
          );
        revision = data.revision;
        page = data.page;
        pages = data.pages;
        conflict = false;
        status.classList.remove("error");
        const memoryLabel =
          {
            ready: "ready for retrieval",
            pending_embedding: "awaiting embedding",
            analysis_pending: "waiting for AI analysis",
            excluded: "excluded from retrieval",
          }[data.memory.state] || "unavailable";
        status.textContent = `${data.current ? labels[data.current.verdict] : "Unreviewed"} · revision ${data.revision} · memory ${memoryLabel}`;
        if (!dirty && data.current) {
          verdict.value = data.current.verdict;
          attackType.value = data.current.corrected_attack_type;
          severity.value = data.current.corrected_severity;
        }
        const entries = data.items.map((item) => {
          const article = node("article");
          article.append(
            node(
              "strong",
              `Revision ${item.revision} · ${labels[item.verdict]}`,
            ),
            node(
              "small",
              `${item.reviewer_label} · self-declared · ${date(item.created_at)} · ${item.authentication === "shared_operation_key" ? "authorized by shared key" : "development access without key"}`,
            ),
            node("p", item.rationale),
            node(
              "small",
              `Classification: ${item.corrected_attack_type || "original AI"} · Severity: ${item.corrected_severity || "original"}`,
            ),
          );
          return article;
        });
        const pager = node("div", undefined, "review-controls"),
          previous = node("button", "Previous", "quiet-button"),
          next = node("button", "Next", "quiet-button");
        previous.type = next.type = "button";
        previous.disabled = page <= 1;
        next.disabled = page >= pages;
        previous.addEventListener("click", () => {
          page--;
          load();
        });
        next.addEventListener("click", () => {
          page++;
          load();
        });
        pager.append(
          previous,
          node("span", `${data.total} revisions · ${page} / ${pages}`),
          next,
        );
        historyBody.replaceChildren(
          ...entries,
          ...(!entries.length ? [node("p", "No analyst reviews yet.")] : []),
          pager,
        );
      } catch (error) {
        if (error.name !== "AbortError") {
          status.textContent = "Review unavailable: " + error.message;
          status.classList.add("error");
          revision = null;
        }
      } finally {
        if (seq === readSequence) {
          busy = false;
          lock();
        }
      }
    }
    reload.addEventListener("click", () => {
      pending = null;
      page = 1;
      load();
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy || revision === null || conflict || !form.reportValidity())
        return;
      const body = {
        verdict: verdict.value,
        reviewer_label: reviewer.value.trim(),
        rationale: rationale.value.trim(),
        corrected_attack_type: attackType.value.trim(),
        corrected_severity: severity.value,
        expected_revision: revision,
        request_id: pending?.request_id || uuid(),
      };
      pending = body;
      const key =
        sessionStorage.opkey ||
        prompt("ใส่ Operation Key เพื่อบันทึก analyst review:");
      if (!key) return;
      sessionStorage.opkey = key;
      busy = true;
      lock();
      status.textContent = "Saving review revision…";
      status.classList.remove("error");
      try {
        const data = await api(
          "/" + row.id,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Operation-Key": key,
            },
            body: JSON.stringify(body),
          },
          signal,
        );
        if (signal.aborted) return;
        pending = null;
        dirty = false;
        rationale.value = "";
        page = 1;
        await load();
        status.textContent += ` · Saved revision ${data.review.revision}${data.replayed ? " (retry confirmed)" : ""}`;
        window.dispatchEvent(new CustomEvent("edge-review-saved"));
      } catch (error) {
        if (error.name !== "AbortError") {
          status.textContent =
            error.status === 409
              ? error.message +
                " Your draft is retained; reload latest to continue."
              : "Review not confirmed: " +
                error.message +
                " · retry to confirm the save; your draft is retained.";
          status.classList.add("error");
          if (error.status === 409) conflict = true;
          if (error.status === 403) sessionStorage.removeItem("opkey");
        }
      } finally {
        busy = false;
        lock();
      }
    });
    lock();
    load();
  }
  $("reviewStatsRefresh").addEventListener("click", refreshStats);
  window.EdgeReviews = {
    attach,
    refreshStats,
    cancel: () => controller?.abort(),
  };
})();
