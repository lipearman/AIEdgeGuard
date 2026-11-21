(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const $ = (id) => document.getElementById(id);
  const n = (tag, value, cls) => {
    const node = document.createElement(tag);
    if (value !== undefined) node.textContent = String(value);
    if (cls) node.className = cls;
    return node;
  };
  let catalogPage = 1,
    catalogPages = 1,
    catalogAbort,
    feedBusy = false,
    behaviorBusy = false,
    investigationAbort;
  const date = (value) => (value ? new Date(value).toLocaleString() : "never");
  async function api(path, options = {}, signal) {
    const response = await fetch(prefix + path, {
      ...options,
      signal:
        signal ||
        AbortSignal.timeout(options.method === "POST" ? 75000 : 15000),
    });
    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("Unexpected API response · HTTP " + response.status);
    }
    if (!response.ok)
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : "HTTP " + response.status,
      );
    return data;
  }
  function cveLink(id) {
    const a = n("a", id);
    a.href = "https://www.cve.org/CVERecord?id=" + encodeURIComponent(id);
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    return a;
  }
  async function feed() {
    if (feedBusy) return;
    feedBusy = true;
    try {
      const data = await api("/api/v1/intelligence/status");
      $("intelFeedStatus").classList.remove("error");
      $("intelFeedStatus").textContent =
        `${data.state.toUpperCase()} · ${data.record_count || 0} KEVs · updated ${date(data.last_success)} · ${data.automatic ? "automatic daily refresh" : "automatic refresh off"}${data.error ? " · " + data.error : ""}`;
      if (data.state !== "current") $("intelFeedStatus").classList.add("error");
      $("intelFeedStatus").title =
        (data.source_url || "No successful source yet") +
        " · version " +
        (data.version || "—");
    } catch (error) {
      $("intelFeedStatus").textContent = "Feed unavailable: " + error.message;
      $("intelFeedStatus").classList.add("error");
    } finally {
      feedBusy = false;
    }
  }
  async function catalog() {
    catalogAbort?.abort();
    const controller = new AbortController();
    catalogAbort = controller;
    $("intelPrevious").disabled = true;
    $("intelNext").disabled = true;
    $("intelPage").textContent = "Loading catalog…";
    try {
      const data = await api(
        "/api/v1/intelligence/vulnerabilities?" +
          new URLSearchParams({
            q: $("intelSearch").value.trim(),
            page: catalogPage,
            page_size: 10,
          }),
        {},
        controller.signal,
      );
      if (catalogAbort !== controller) return;
      catalogPage = data.page;
      catalogPages = data.pages;
      const entries = data.items.map((row) => {
        const article = n("article", undefined, "intel-entry");
        article.append(
          cveLink(row.cve),
          n("h4", row.title),
          n("p", `${row.vendor} · ${row.product} · added ${row.date_added}`),
        );
        const details = n("details");
        details.append(
          n("summary", "Description & CISA required action"),
          n("p", row.description),
          n("p", row.required_action),
          n(
            "p",
            `CISA due date ${row.due_date} · ransomware ${row.ransomware}`,
          ),
        );
        article.append(details);
        return article;
      });
      $("intelCatalog").replaceChildren(
        ...(entries.length
          ? entries
          : [
              n(
                "p",
                "No catalog entries match. Check feed status or clear search.",
                "intel-scope",
              ),
            ]),
      );
      $("intelPage").textContent =
        `${data.total.toLocaleString()} entries · ${catalogPage} / ${catalogPages}`;
      $("intelPrevious").disabled = catalogPage <= 1;
      $("intelNext").disabled = catalogPage >= catalogPages;
    } catch (error) {
      if (error.name !== "AbortError") {
        $("intelCatalog").replaceChildren(
          n("p", "Catalog unavailable: " + error.message, "intel-status error"),
        );
        $("intelPage").textContent = "Unavailable";
      }
    }
  }
  async function behavior() {
    if (behaviorBusy) return;
    behaviorBusy = true;
    $("behaviorRefresh").disabled = true;
    try {
      const data = await api("/api/v1/investigation/behavior");
      $("behaviorStatus").classList.toggle("error", data.state !== "available");
      $("behaviorStatus").textContent =
        `${data.state.toUpperCase()} · window ${date(data.window_start)} → ${date(data.window_end)} · latest collected ${date(data.latest_request)}`;
      const rows = data.items.map((row) => {
        const line = n("div", undefined, "behavior-row");
        const key = n("div");
        key.append(
          n("strong", row.host || "Unknown host"),
          n("small", row.router || "No router"),
          n("small", row.reason),
        );
        const state = n("div");
        state.append(
          n(
            "strong",
            {
              unusual: "Unusual volume",
              warming_up: "Warming up",
              within_baseline: "Within baseline",
            }[row.state] || row.state,
          ),
          n("small", "investigation signal"),
        );
        const count = n("div");
        count.append(
          n("strong", row.current + " requests"),
          n("small", "latest complete window"),
        );
        const baseline = n("div");
        baseline.append(
          n(
            "strong",
            row.baseline_median === null
              ? "Warming up"
              : "Median " + row.baseline_median,
          ),
          n("small", "score " + (row.robust_score ?? "—")),
        );
        line.append(key, state, count, baseline);
        return line;
      });
      $("behaviorResults").replaceChildren(
        ...(rows.length
          ? rows
          : [
              n(
                "p",
                "No retained traffic for the baseline window.",
                "intel-scope",
              ),
            ]),
        n("p", data.method + " " + data.scope, "intel-scope"),
      );
    } catch (error) {
      $("behaviorStatus").textContent =
        "Baseline unavailable: " + error.message;
      $("behaviorStatus").classList.add("error");
      $("behaviorResults").replaceChildren();
    } finally {
      behaviorBusy = false;
      $("behaviorRefresh").disabled = false;
    }
  }
  function attach(parent, kind, row) {
    const section = n("section", undefined, "investigation-section"),
      button = n(
        "button",
        "Investigate timeline & evidence",
        "workspace-button",
      ),
      results = n("div", undefined, "investigation-results");
    button.type = "button";
    section.append(
      n("h3", "Investigation"),
      n(
        "p",
        "Candidate links use recorded identities and a ±15-minute window. Shared proxy IPs do not establish a common attacker.",
        "payload-note",
      ),
      button,
      results,
    );
    parent.append(section);
    let page = 1;
    async function load() {
      investigationAbort?.abort();
      investigationAbort = new AbortController();
      const controller = investigationAbort;
      button.disabled = true;
      results.replaceChildren(n("p", "Loading linked evidence…"));
      try {
        const data = await api(
          `/api/v1/investigation/timeline/${kind}/${row.id}?page=${page}`,
          {},
          controller.signal,
        );
        if (controller !== investigationAbort) return;
        const children = [n("p", data.scope, "payload-note")];
        if (data.asset_context) {
          const context = data.asset_context;
          children.push(
            n("h4", "Mapped asset context"),
            n("p", context.scope, "payload-note"),
          );
          for (const asset of [context.asset, context.parent_host].filter(
            Boolean,
          )) {
            children.push(
              n(
                "p",
                `${asset.payload.name} · ${asset.payload.kind} · owner ${asset.payload.owner || "not recorded"} · ${asset.payload.criticality} · revision ${asset.revision} · mapped ${date(asset.mapped_at)}`,
              ),
            );
            const details = n("details");
            details.append(
              n("summary", "Operator-declared asset metadata"),
              n("pre", JSON.stringify(asset, null, 2), "evidence-code"),
            );
            children.push(details);
          }
          if (!context.asset)
            children.push(
              n(
                "p",
                "No unambiguous active asset mapping found. Register bindings in Assets; missing mapping does not mean no attack.",
              ),
            );
          if (context.match_reasons.length)
            children.push(n("p", context.match_reasons.join(" · ")));
          context.warnings.forEach((warning) =>
            children.push(n("p", warning, "payload-note")),
          );
        }
        if (data.inspection) {
          children.push(
            n("h4", "Decoded target & query"),
            n("pre", data.inspection.decoded_target, "evidence-code"),
            n("p", data.inspection.scope),
            n(
              "p",
              "Syntax hints: " +
                (data.inspection.signals.join(", ") || "none matched"),
            ),
          );
          if (data.inspection.truncated)
            children.push(
              n("p", "Preview truncated at 16 KB / 100 query fields."),
            );
        }
        children.push(
          n("h4", "CVE evidence"),
          n(
            "p",
            "Observed in source: " +
              (data.evidence_cves.join(", ") || "none") +
              " · AI-only mentions (unverified): " +
              (data.analysis_only_cves.join(", ") || "none"),
          ),
        );
        data.known_exploited.forEach((kev) => {
          const p = n("p");
          p.append(
            cveLink(kev.cve),
            document.createTextNode(
              " · CISA KEV: " + kev.title + " · " + kev.required_action,
            ),
          );
          children.push(p);
        });
        children.push(
          n(
            "p",
            `KEV snapshot: ${data.intelligence_status?.state || "unavailable"} · last fetched ${date(data.intelligence_status?.last_success)}. KEV membership is not proof this asset is vulnerable or this event exploited that CVE.`,
            "payload-note",
          ),
          n("h4", "Candidate incident timeline"),
        );
        if (!data.items.length)
          children.push(
            n(
              "p",
              "No related incidents identified from available keys. Capture gaps, proxy peers or missing host identity can prevent matching.",
            ),
          );
        data.items.forEach((event) => {
          const div = n("article", undefined, "candidate-event");
          div.append(
            n("strong", event.reason),
            n(
              "small",
              `${date(event.created_at)} · ${event.source} · ${event.severity} · #${event.id}`,
            ),
            n("p", event.match_reasons.join(" · ")),
            n(
              "small",
              [event.endpoint, event.attack_type, event.mitre_id]
                .filter(Boolean)
                .join(" · "),
            ),
          );
          const link = n("a", "Open incident JSON");
          link.href = prefix + "/api/v1/dashboard/data/incidents/" + event.id;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          div.append(link);
          children.push(div);
        });
        children.push(n("h4", "Policy / response evidence"));
        if (!data.decisions.length)
          children.push(
            n(
              "p",
              kind === "requests"
                ? "Response decisions are keyed to incidents. Open a linked incident to inspect its decisions."
                : "No stored decisions for this incident.",
            ),
          );
        data.decisions.forEach((d) => {
          const details = n("details");
          details.append(
            n("summary", `#${d.id} · ${d.action} · ${d.status}`),
            n("p", d.policy_reason),
            n("pre", JSON.stringify(d, null, 2), "evidence-code"),
          );
          children.push(details);
        });
        if (data.decisions_truncated)
          children.push(
            n(
              "p",
              "Latest 20 decisions shown; see Decision history for earlier records.",
            ),
          );
        const pager = n("div", undefined, "intel-pager"),
          previous = n("button", "Previous", "quiet-button"),
          next = n("button", "Next", "quiet-button");
        previous.disabled = page <= 1;
        next.disabled = !data.has_more;
        previous.addEventListener("click", () => {
          page--;
          load();
        });
        next.addEventListener("click", () => {
          page++;
          load();
        });
        pager.append(previous, n("span", "Timeline page " + page), next);
        children.push(pager);
        results.replaceChildren(...children);
      } catch (error) {
        if (error.name !== "AbortError")
          results.replaceChildren(
            n(
              "p",
              "Investigation unavailable: " +
                error.message +
                " · retry using the button above.",
              "intel-status error",
            ),
          );
      } finally {
        if (controller === investigationAbort) button.disabled = false;
      }
    }
    button.addEventListener("click", () => {
      page = 1;
      load();
    });
  }
  $("intelSearchForm").addEventListener("submit", (event) => {
    event.preventDefault();
    catalogPage = 1;
    catalog();
  });
  $("intelPrevious").addEventListener("click", () => {
    catalogPage--;
    catalog();
  });
  $("intelNext").addEventListener("click", () => {
    catalogPage++;
    catalog();
  });
  $("behaviorRefresh").addEventListener("click", behavior);
  $("intelSync").addEventListener("click", async () => {
    const key =
      sessionStorage.opkey || prompt("ใส่ Operation Key เพื่ออัปเดต catalog:");
    if (!key) return;
    sessionStorage.opkey = key;
    $("intelSync").disabled = true;
    $("intelFeedStatus").textContent = "Updating public KEV snapshot…";
    try {
      const data = await api("/api/v1/intelligence/sync", {
        method: "POST",
        headers: { "X-Operation-Key": key },
      });
      await feed();
      catalogPage = 1;
      await catalog();
      if (data.status !== "updated") {
        $("intelFeedStatus").textContent =
          data.status + " · " + (data.error || "another sync is running");
        $("intelFeedStatus").classList.add("error");
      }
    } catch (error) {
      $("intelFeedStatus").textContent = error.message;
      $("intelFeedStatus").classList.add("error");
      if (error.message.includes("operation key"))
        sessionStorage.removeItem("opkey");
    } finally {
      $("intelSync").disabled = false;
    }
  });
  window.EdgeIntelligence = {
    refresh: () =>
      Promise.all([
        feed(),
        catalog(),
        behavior(),
        window.EdgeReviews.refreshStats(),
      ]),
    attach,
    cancelInvestigation: () => investigationAbort?.abort(),
  };
})();
