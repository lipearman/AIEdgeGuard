(() => {
  const n = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  };
  const percent = (value) =>
    Number.isFinite(value) ? (100 * value).toFixed(1) + "%" : "Unavailable";
  const label = (state) =>
    ({
      candidate_input_change: "Candidate input-distribution change",
      no_candidate_under_fixed_rules: "No candidate under these fixed rules",
      partial_feature_coverage:
        "Partial feature coverage · no complete comparison",
      insufficient_coverage: "Insufficient eligible coverage",
      invalid_volume_features: "Invalid volume features",
      baseline_not_ready: "Training baseline not ready",
      invalid_baseline_features: "Invalid training features",
      descriptive_only: "Descriptive comparison only",
      candidate_change: "Candidate change",
      missing_or_invalid_features: "Missing / invalid error features",
      insufficient_requests: "Too few requests for error share",
    })[state] || state;
  function render(parent, data) {
    const root = n("section", undefined, "drift-section");
    root.setAttribute("aria-label", "Input drift and data coverage");
    parent.append(root);
    root.append(
      n("h4", "Input drift & data coverage"),
      n(
        "p",
        "เปรียบเทียบข้อมูลกับ training ที่ตรึงไว้ ไม่ใช่ผลยืนยัน model drift หรือการโจมตี · ไม่มีการเปลี่ยน threshold หรือ retrain อัตโนมัติ",
        "eval-help",
      ),
    );
    if (!data) {
      root.append(
        n(
          "p",
          "Not recorded for this saved replay · run a new comparison to capture drift; original report remains unchanged",
          "eval-help",
        ),
      );
      return;
    }
    if (data.state !== "descriptive_only") {
      root.append(
        n("p", label(data.state), "eval-status"),
        n("p", data.reason, "eval-help"),
      );
      return;
    }
    const columns = n("div", undefined, "drift-columns");
    root.append(columns);
    for (const split of ["test", "calibration"]) {
      const d = data.comparisons[split],
        section = n("section", undefined, "drift-period"),
        q = d.comparison_quality,
        b = d.baseline_quality;
      section.append(
        n(
          "h5",
          split === "test" ? "Held-out test inputs" : "Calibration inputs",
        ),
        n(
          "p",
          label(d.state),
          d.state === "no_candidate_under_fixed_rules"
            ? "eval-help"
            : "drift-attention",
        ),
        n(
          "p",
          `Baseline ${b.eligible_windows}/${b.total_windows} eligible windows · comparison ${q.eligible_windows}/${q.total_windows} (${percent(q.eligible_fraction)}) · excluded ${q.excluded_windows}`,
          "eval-help",
        ),
        n(
          "p",
          `Comparison labels: normal ${q.label_context.normal || 0}, lab attack ${q.label_context.lab_attack || 0}, unknown ${q.label_context.unknown || 0} · all eligible traffic is compared, not just normal traffic`,
          "eval-help",
        ),
      );
      if (d.volume) {
        const v = d.volume,
          e = d.error_share,
          details = n("details"),
          dl = n("dl");
        details.append(n("summary", "Volume & observed error-share details"));
        for (const [title, value] of [
          ["Volume rule", label(v.state)],
          ["ECDF distance D", v.ecdf_distance],
          ["Median · baseline", v.baseline_median],
          ["Median · comparison", v.comparison_median],
          [
            "Median ratio",
            v.median_ratio === null
              ? "Undefined at zero baseline"
              : Number(v.median_ratio).toFixed(2) + "×",
          ],
          [
            "Zero-window share",
            `${percent(v.baseline_zero_share)} → ${percent(v.comparison_zero_share)}`,
          ],
          ["Observed ≥400 share", label(e.state)],
        ]) {
          dl.append(n("dt", title), n("dd", value));
        }
        if (e.baseline_share !== undefined) {
          dl.append(
            n("dt", "Share · baseline → comparison"),
            n(
              "dd",
              `${percent(e.baseline_share)} → ${percent(e.comparison_share)}`,
            ),
            n("dt", "Signed share change"),
            n("dd", (100 * e.share_delta).toFixed(1) + " percentage points"),
          );
        }
        if (e.reason)
          dl.append(n("dt", "Error-share limitation"), n("dd", e.reason));
        details.append(
          dl,
          n(
            "p",
            "ECDF distance is descriptive: no p-value or statistical-significance claim. Counts and adjacent windows can be correlated; stored unknown statuses can bias error share.",
            "eval-help",
          ),
        );
        section.append(details);
        if (
          e.state === "missing_or_invalid_features" ||
          e.state === "insufficient_requests"
        )
          section.append(
            n(
              "p",
              label(e.state) +
                " · volume results do not fill missing error information",
              "eval-help",
            ),
          );
      } else section.append(n("p", d.reason, "eval-help"));
      section.append(
        n(
          "p",
          "Traffic mix, lab activity, attacks, seasonality or logging changes can explain a signal. This is not a detector-performance verdict.",
          "eval-help",
        ),
      );
      columns.append(section);
    }
    const metadata = n("details");
    metadata.append(
      n("summary", "Frozen drift rules & scope"),
      n(
        "pre",
        JSON.stringify(
          {
            version: data.version,
            implementation_sha256: data.implementation_sha256,
            parameters: data.parameters,
            split_indices: data.split_indices,
            scope: data.scope,
          },
          null,
          2,
        ),
        "eval-code",
      ),
    );
    root.append(metadata);
  }
  window.EdgeDrift = { render };
})();
