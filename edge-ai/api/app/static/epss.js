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
  const date = (value) => (value ? new Date(value).toLocaleString() : "never");
  const percent = (value) =>
    new Intl.NumberFormat(undefined, {
      style: "percent",
      maximumSignificantDigits: 4,
    }).format(Number(value));
  let sequence = 0,
    busy = false;
  function status(text, error = false) {
    $("epssStatus").textContent = text;
    $("epssStatus").classList.toggle("error", error);
  }
  function render(data) {
    const children = [
      n("h4", data.cve),
      n(
        "p",
        `Lookup ${data.state} · last success ${date(data.last_success)} · last attempt ${date(data.last_attempt)}`,
      ),
    ];
    if (data.error) children.push(n("p", data.error, "intel-status error"));
    if (["not_scored", "stale_not_scored"].includes(data.state))
      children.push(
        n(
          "p",
          "Last successful lookup returned no score. Missing EPSS does not mean zero likelihood or no vulnerability.",
        ),
      );
    if (data.score) {
      const score = data.score;
      if (
        ![score.epss, score.percentile].every(
          (v) =>
            v !== null &&
            v !== "" &&
            Number.isFinite(Number(v)) &&
            Number(v) >= 0 &&
            Number(v) <= 1,
        )
      )
        throw new Error("Invalid cached EPSS score. Retry lookup.");
      children.push(
        n(
          "p",
          `Probability ${percent(score.epss)} · percentile rank ${percent(score.percentile)} · ${score.state.toUpperCase()}`,
          "epss-score",
        ),
        n(
          "p",
          `Score date ${score.score_date} · fetched ${date(score.fetched_at)} · FIRST API ${score.api_version} (not EPSS model version)`,
        ),
      );
      if (score.state !== "current")
        children.push(
          n(
            "p",
            "Retained earlier score: stale, refresh failed, or latest lookup has no score. Inspect dates before using it.",
            "payload-note",
          ),
        );
      if (Number.isSafeInteger(score.snapshot_id) && score.snapshot_id > 0) {
        const link = n("a", "Open stored score snapshot #" + score.snapshot_id);
        link.href =
          prefix + "/api/v1/intelligence/epss/snapshots/" + score.snapshot_id;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        children.push(link);
      }
    } else
      children.push(
        n(
          "p",
          data.state === "never_fetched"
            ? "No cached lookup. Fetch from FIRST with the Operation Key to request this CVE."
            : "No stored score available. Missing data is not evidence of safety.",
        ),
      );
    const source = n("a", "Source: FIRST EPSS · " + data.cve);
    source.href =
      "https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(data.cve);
    source.target = "_blank";
    source.rel = "noopener noreferrer";
    children.push(source, n("p", data.scope, "intel-scope"));
    $("epssResult").replaceChildren(...children);
  }
  async function load(fetchNew = false) {
    if (busy) return;
    const cve = $("epssCve").value.trim().toUpperCase();
    $("epssCve").value = cve;
    if (!/^CVE-\d{4}-\d{4,19}$/.test(cve)) {
      status("Use one complete CVE ID, e.g. CVE-2024-4577.", true);
      $("epssCve").focus();
      return;
    }
    let key = "";
    if (fetchNew) {
      key =
        sessionStorage.opkey ||
        prompt("Operation Key for fetching a FIRST EPSS score")?.trim() ||
        "";
      if (!key) {
        status("Fetch cancelled; CVE retained.");
        return;
      }
      sessionStorage.opkey = key;
    }
    const ticket = ++sequence;
    busy = true;
    $("epssFetch").disabled = $("epssView").disabled = true;
    $("epssCve").readOnly = true;
    $("epssResult").replaceChildren();
    status(fetchNew ? "Fetching FIRST EPSS…" : "Reading local EPSS cache…");
    try {
      const response = await fetch(
        prefix + "/api/v1/intelligence/epss/" + encodeURIComponent(cve),
        {
          method: fetchNew ? "POST" : "GET",
          headers: fetchNew ? { "X-Operation-Key": key } : {},
          signal: AbortSignal.timeout(25000),
        },
      );
      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error("Unexpected response · HTTP " + response.status);
      }
      if (!response.ok) {
        if (response.status === 403) sessionStorage.removeItem("opkey");
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "EPSS lookup failed · HTTP " + response.status,
        );
      }
      if (ticket !== sequence) return;
      render(fetchNew ? data.result : data);
      status(
        `${fetchNew ? data.action : "local cache"} · ${(fetchNew ? data.result : data).state}`,
        fetchNew && data.action === "failed",
      );
    } catch (e) {
      status(
        e.message +
          " · Retry View cached score; Fetch requires the Operation Key.",
        true,
      );
    } finally {
      busy = false;
      $("epssFetch").disabled = $("epssView").disabled = false;
      $("epssCve").readOnly = false;
    }
  }
  $("epssForm").addEventListener("submit", (event) => {
    event.preventDefault();
    load();
  });
  $("epssFetch").addEventListener("click", () => load(true));
  window.EdgeEpss = {
    select: (cve) => {
      if (busy) return;
      $("epssCve").value = cve;
      $("epssCve").focus({ preventScroll: true });
      $("epssTitle").scrollIntoView({ block: "start" });
      load();
    },
  };
})();
