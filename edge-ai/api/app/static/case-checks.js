(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const n = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
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
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  async function api(path, options = {}) {
    const response = await fetch(prefix + "/api/v1/case-checks" + path, {
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
          : "Check fields · HTTP " + response.status,
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
      prompt("Operation Key for case check / review")?.trim();
    if (value) sessionStorage.opkey = value;
    return value;
  }
  const link = (text, path) => {
    const a = n("a", text);
    a.href = prefix + "/api/v1/case-checks" + path;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    return a;
  };
  const details = (title, value) => {
    const d = n("details");
    d.append(
      n("summary", title),
      n("pre", JSON.stringify(value, null, 2), "case-code"),
    );
    return d;
  };
  function attach(parent, caseRecord) {
    const root = n("details", undefined, "case-checks");
    root.innerHTML = `<summary>Evidence consistency &amp; analyst review</summary><div class="case-checks-inner">
      <p class="case-help">ตัวตรวจเทียบกับหลักฐานที่ยังเก็บอยู่ ไม่ได้ยืนยันความแท้ของเซนเซอร์ ตัวตน หรือ causal attack chain · ไม่มี LLM หรือคำสั่งตอบสนอง</p>
      <details class="check-create"><summary>Run retained-evidence check</summary><form class="check-form"><fieldset class="case-form"><label>Declared by · self-reported<input name="author" required minlength="2" maxlength="80" autocomplete="off" /></label><label>Check purpose<textarea name="reason" required minlength="8" maxlength="2000" rows="3"></textarea></label></fieldset><button class="workspace-button check-save">Save consistency check</button></form></details>
      <p class="check-status check-save-status" role="status">การบันทึกใช้ Operation Key</p><label>Saved checks<select class="check-reports"><option value="">Select a pinned check…</option></select></label><div class="case-pager check-pager"><button class="quiet-button check-prev">Previous</button><span>—</span><button class="quiet-button check-next">Next</button></div><p class="check-status check-list-status" role="status"></p><div class="check-result"></div>
      <section class="case-check-review"><h4>Operator review</h4><p class="case-help">ความเห็นแยกจากผลตรวจและ case เดิม · ชื่อผู้ตรวจระบุเองด้วย shared key จึงยังไม่ใช่ independent identity หรือ second-person approval</p><p class="check-review-saved case-help">No saved review</p>
        <form class="check-review-form"><fieldset class="case-form"><label>Association verdict<select name="verdict"><option value="needs_more_evidence">Needs more evidence</option><option value="supported_association">Supported association · ไม่ยืนยันการโจมตี</option><option value="disputed">Disputed</option></select></label><label>Reviewer label · self-reported<input name="author" required minlength="2" maxlength="80" autocomplete="off" /></label><label>Review rationale<textarea name="reason" required minlength="8" maxlength="2000" rows="3"></textarea></label></fieldset><div class="case-actions"><button class="workspace-button check-review-save">Append review revision</button><button type="button" class="quiet-button check-review-reload">Reload latest review</button><button type="button" class="quiet-button check-review-clear">Clear draft</button></div></form>
        <p class="check-status check-review-status" role="status">เลือก check ที่บันทึกแล้วก่อนให้ความเห็น</p><details><summary>Review revision history</summary><div class="check-review-history"></div><div class="case-pager review-pager"><button class="quiet-button review-prev">Previous</button><span>—</span><button class="quiet-button review-next">Next</button></div></details>
      </section></div>`;
    parent.append(root);
    const reloadChecks = n("button", "Reload checks", "quiet-button");
    reloadChecks.type = "button";
    root.querySelector(".check-list-status").before(reloadChecks);
    const $ = (selector) => root.querySelector(selector),
      form = $(".check-form"),
      reviewForm = $(".check-review-form");
    const storeKey = "edgeguard.case-check.pending." + caseRecord.id;
    let pendingCheck,
      pendingReview,
      current,
      checkPage = 1,
      reviewPage = 1,
      findingPage = 1,
      revision,
      conflict = false,
      busy = false,
      reportLoading = false,
      readTicket = 0,
      listTicket = 0,
      reviewTicket = 0;
    try {
      const pending = JSON.parse(sessionStorage.getItem(storeKey) || "{}");
      pendingCheck = pending.check;
      pendingReview = pending.review;
    } catch {
      /* invalid session values not used */
    }
    const persist = () =>
      sessionStorage.setItem(
        storeKey,
        JSON.stringify({ check: pendingCheck, review: pendingReview }),
      );
    const message = (selector, text, error = false) => {
      const e = $(selector);
      e.textContent = text;
      e.classList.toggle("error", error);
    };
    const pages = new Map();
    function pager(selector, page, total, size) {
      pages.set(selector, [page, total, size]);
      const e = $(selector);
      e.querySelector("span").textContent =
        `${page} / ${Math.max(1, Math.ceil(total / size))} · ${total} items`;
      const buttons = e.querySelectorAll("button");
      buttons[0].disabled = busy || page <= 1;
      buttons[1].disabled = busy || page * size >= total;
    }
    function lock(value) {
      busy = value;
      reloadChecks.disabled = value || reportLoading;
      form.querySelector("fieldset").disabled = value || !!pendingCheck;
      reviewForm.querySelector("fieldset").disabled = value || !!pendingReview;
      $(".check-save").disabled = value || reportLoading;
      $(".check-review-save").disabled =
        value ||
        reportLoading ||
        conflict ||
        !current ||
        revision === undefined ||
        !!pendingCheck;
      $(".check-reports").disabled = value || reportLoading || !!pendingReview;
      $(".check-review-reload").disabled = value;
      $(".check-review-clear").disabled = value;
      $(".check-save").textContent = pendingCheck
        ? "Retry same consistency check"
        : "Save consistency check";
      $(".check-review-save").textContent = pendingReview
        ? "Retry same review revision"
        : "Append review revision";
      for (const [selector, args] of pages) pager(selector, ...args);
    }
    function restoreSelector() {
      const select = $(".check-reports");
      if (
        current &&
        !Array.from(select.options).some(
          (option) => option.value === current.id,
        )
      ) {
        const option = n("option", "Pinned current check · " + current.id);
        option.value = current.id;
        select.append(option);
      }
      select.value = current?.id || "";
    }
    async function loadChecks() {
      const ticket = ++listTicket,
        requested = checkPage;
      try {
        const data = await api(`?case_id=${caseRecord.id}&page=${requested}`);
        if (ticket !== listTicket || !root.isConnected) return;
        const select = $(".check-reports");
        select.replaceChildren(n("option", "Select a pinned check…"));
        data.items.forEach((item) => {
          const o = n(
            "option",
            `${date(item.created_at)} · ${item.state} · ${item.id}`,
          );
          o.value = item.id;
          select.append(o);
        });
        restoreSelector();
        pager(".check-pager", requested, data.total, 10);
        message(
          ".check-list-status",
          data.total
            ? "Reports describe retained evidence as of their saved check time"
            : "No saved checks · absence of a check does not establish an intact case",
        );
      } catch (e) {
        message(
          ".check-list-status",
          e.message + " · reopen case or refresh history",
          true,
        );
        $(".check-prev").disabled = true;
        $(".check-next").disabled = true;
      }
    }
    function renderFindings() {
      const report = current.report,
        items = [
          ...(report.nodes || []).map((x) => ({
            label: x.node,
            state: x.state,
            text:
              (x.issues || []).join(" · ") ||
              "Pinned facts agree with retained source",
          })),
          ...(report.edges || []).map((x) => ({
            label: `Edge #${x.index} · ${x.type} · ${x.from} → ${x.to}`,
            state: x.state,
            text: x.reason,
          })),
          ...(report.assets || []).map((x) => ({
            label: `Asset ${x.asset_id} · revision ${x.revision}`,
            state: x.state,
            text: x.scope,
          })),
        ];
      const target = $(".check-findings");
      target.replaceChildren();
      items.slice((findingPage - 1) * 6, findingPage * 6).forEach((item) => {
        const d = n("div", undefined, "case-check-finding");
        d.append(
          n("p", item.label),
          n("p", item.state, "case-help"),
          n("p", item.text, "case-help"),
        );
        target.append(d);
      });
      pager(".finding-pager", findingPage, items.length, 6);
    }
    function render(data) {
      current = data;
      restoreSelector();
      findingPage = 1;
      const r = data.report,
        target = $(".check-result");
      target.replaceChildren();
      const state = n("p", r.state, "check-state");
      state.dataset.problem = String(
        r.state !== "consistent_with_retained_evidence",
      );
      target.append(
        n("h4", "Pinned consistency result"),
        state,
        n(
          "p",
          `Checked ${date(r.checked_at)} · retained sources may have changed since this report`,
          "case-help",
        ),
        link("Check snapshot · " + data.id, "/" + data.id),
        n(
          "p",
          "Matching retained facts do not prove source authenticity, a causal attack, independent reviewer identity or permission to act.",
          "case-help",
        ),
      );
      if (r.reason) target.append(n("p", r.reason, "case-help"));
      target.append(
        n(
          "p",
          r.case_hash_matches
            ? "Case content hash matches the pinned graph"
            : "Case content hash does not match · inspect before relying on this case",
          "case-help",
        ),
      );
      const findings = n("div", undefined, "check-findings"),
        pg = n("div", undefined, "case-pager finding-pager"),
        prev = n("button", "Previous", "quiet-button"),
        next = n("button", "Next", "quiet-button");
      pg.append(prev, n("span"), next);
      prev.onclick = () => {
        findingPage = Math.max(1, findingPage - 1);
        renderFindings();
      };
      next.onclick = () => {
        findingPage++;
        renderFindings();
      };
      target.append(
        findings,
        pg,
        details("Pinned check provenance and complete findings", r),
      );
      const exp = n("button", "Export check JSON", "quiet-button");
      exp.onclick = () => {
        const url = URL.createObjectURL(
          new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          }),
        );
        const a = n("a");
        a.href = url;
        a.download = `edgeguard-case-check-${data.id}.json`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      };
      target.append(exp);
      renderFindings();
      lock(busy);
    }
    async function selectCheck(id) {
      restoreSelector();
      if (busy || reportLoading) return;
      if (pendingReview || reviewForm.elements.reason.value.trim()) {
        message(
          ".check-review-status",
          "Save or Clear draft before changing the pinned check",
          true,
        );
        return;
      }
      const ticket = ++readTicket;
      reportLoading = true;
      lock(busy);
      message(
        ".check-save-status",
        "Loading requested check · existing report remains pinned until loading succeeds",
      );
      try {
        const data = await api("/" + id);
        if (ticket !== readTicket || !root.isConnected) return;
        render(data);
        message(
          ".check-save-status",
          "Pinned check loaded · report and review target now match the selected check",
        );
        message(
          ".check-review-status",
          "Review will reference this exact saved check, not a newly recomputed result",
        );
      } catch (e) {
        restoreSelector();
        message(
          ".check-save-status",
          e.message + " · reselect report to retry",
          true,
        );
      } finally {
        if (ticket === readTicket) {
          reportLoading = false;
          lock(busy);
        }
      }
    }
    async function loadReviews(reload = false) {
      const ticket = ++reviewTicket,
        requested = reviewPage;
      const data = await api(`/reviews/${caseRecord.id}?page=${requested}`);
      if (ticket !== reviewTicket || !root.isConnected) return;
      if (revision === undefined || reload) {
        revision = data.revision;
        conflict = false;
        const latest = data.items[0];
        $(".check-review-saved").textContent = latest
          ? `Saved revision ${latest.revision} · ${latest.verdict} · ${latest.reviewer_label} · check ${latest.check_id} · ${latest.rationale}`
          : "No saved review";
      }
      $(".check-review-history").replaceChildren(
        ...data.items.map((item) =>
          details(
            `Revision ${item.revision} · ${item.verdict} · ${item.reviewer_label}`,
            item,
          ),
        ),
      );
      pager(".review-pager", requested, data.total, 10);
      lock(busy);
    }
    form.onsubmit = async (event) => {
      event.preventDefault();
      if (busy || reportLoading) return;
      if (pendingReview || reviewForm.elements.reason.value.trim()) {
        message(
          ".check-save-status",
          "Resolve the review draft before creating another check",
          true,
        );
        return;
      }
      const auth = key();
      if (!auth) {
        message(
          ".check-save-status",
          "Operation Key not provided · nothing sent, draft retained",
          true,
        );
        return;
      }
      pendingCheck ||= {
        id: uuid(),
        body: {
          case_id: caseRecord.id,
          declared_by: form.elements.author.value.trim(),
          rationale: form.elements.reason.value.trim(),
        },
      };
      persist();
      lock(true);
      message(
        ".check-save-status",
        "Checking retained evidence · no external or LLM call…",
      );
      try {
        const data = await api("/" + pendingCheck.id, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-Operation-Key": auth,
          },
          body: JSON.stringify(pendingCheck.body),
        });
        pendingCheck = undefined;
        render(data);
        checkPage = 1;
        await loadChecks();
        message(
          ".check-save-status",
          "Saved immutable consistency report · original case unchanged",
        );
      } catch (e) {
        if ([403, 422].includes(e.status)) pendingCheck = undefined;
        message(
          ".check-save-status",
          e.message +
            " · retry retains original UUID/input where outcome is unknown",
          true,
        );
      } finally {
        persist();
        lock(false);
      }
    };
    reviewForm.onsubmit = async (event) => {
      event.preventDefault();
      if (
        busy ||
        reportLoading ||
        conflict ||
        !current ||
        revision === undefined
      )
        return;
      const auth = key();
      if (!auth) {
        message(
          ".check-review-status",
          "Operation Key not provided · nothing sent, draft retained",
          true,
        );
        return;
      }
      pendingReview ||= {
        check_id: current.id,
        expected_revision: revision,
        verdict: reviewForm.elements.verdict.value,
        reviewer_label: reviewForm.elements.author.value.trim(),
        rationale: reviewForm.elements.reason.value.trim(),
        request_id: uuid(),
      };
      persist();
      lock(true);
      message(".check-review-status", "Saving separate operator annotation…");
      try {
        const saved = await api("/reviews/" + caseRecord.id, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Operation-Key": auth,
          },
          body: JSON.stringify(pendingReview),
        });
        pendingReview = undefined;
        revision = saved.revision;
        reviewForm.elements.reason.value = "";
        reviewPage = 1;
        await loadReviews(true);
        message(
          ".check-review-status",
          "Review saved · no graph, policy or model result was changed",
        );
      } catch (e) {
        if ([403, 422].includes(e.status)) pendingReview = undefined;
        if (e.status === 409) {
          pendingReview = undefined;
          conflict = true;
        }
        message(
          ".check-review-status",
          e.message +
            (conflict
              ? " · Reload latest review, inspect retained draft, then resubmit"
              : " · draft and pending request retained"),
          true,
        );
      } finally {
        persist();
        lock(false);
      }
    };
    $(".check-reports").onchange = () =>
      $(".check-reports").value && selectCheck($(".check-reports").value);
    $(".check-review-reload").onclick = async () => {
      if (busy) return;
      if (pendingReview) {
        message(
          ".check-review-status",
          "Retry unresolved review before reloading its revision",
          true,
        );
        return;
      }
      reviewPage = 1;
      try {
        await loadReviews(true);
        message(
          ".check-review-status",
          "Latest revision loaded · draft retained; inspect before resubmitting",
        );
      } catch (e) {
        message(".check-review-status", e.message, true);
      }
    };
    $(".check-review-clear").onclick = () => {
      if (pendingReview) {
        message(
          ".check-review-status",
          "Retry unresolved review before discarding its UUID",
          true,
        );
        return;
      }
      reviewForm.elements.reason.value = "";
      message(".check-review-status", "Draft cleared");
    };
    $(".check-prev").onclick = () => {
      if (!busy) {
        checkPage = Math.max(1, checkPage - 1);
        loadChecks();
      }
    };
    $(".check-next").onclick = () => {
      if (!busy) {
        checkPage++;
        loadChecks();
      }
    };
    $(".review-prev").onclick = () => {
      if (!busy) {
        reviewPage = Math.max(1, reviewPage - 1);
        loadReviews().catch((e) =>
          message(".check-review-status", e.message, true),
        );
      }
    };
    $(".review-next").onclick = () => {
      if (!busy) {
        reviewPage++;
        loadReviews().catch((e) =>
          message(".check-review-status", e.message, true),
        );
      }
    };
    reloadChecks.onclick = () => {
      if (!busy) loadChecks();
    };
    $(".check-review-saved").textContent = "Loading saved review…";
    (async () => {
      await Promise.allSettled([
        loadChecks(),
        loadReviews().catch((e) =>
          message(
            ".check-review-status",
            e.message + " · Reload latest review to retry",
            true,
          ),
        ),
      ]);
      if (pendingCheck) {
        form.elements.author.value = pendingCheck.body.declared_by;
        form.elements.reason.value = pendingCheck.body.rationale;
        $(".check-create").open = true;
        root.open = true;
        message(
          ".check-save-status",
          "Unresolved check restored · retry the same UUID",
        );
      }
      if (pendingReview) {
        try {
          const saved = await api("/" + pendingReview.check_id);
          if (root.isConnected) {
            render(saved);
            reviewForm.elements.verdict.value = pendingReview.verdict;
            reviewForm.elements.author.value = pendingReview.reviewer_label;
            reviewForm.elements.reason.value = pendingReview.rationale;
            root.open = true;
            message(
              ".check-review-status",
              "Unresolved review restored · retry the original request UUID",
            );
          }
        } catch (e) {
          message(
            ".check-review-status",
            e.message + " · pending UUID retained",
            true,
          );
        }
      }
      lock(false);
    })();
  }
  window.EdgeCaseChecks = { attach };
})();
