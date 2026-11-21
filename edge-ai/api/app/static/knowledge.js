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
  const date = (v) => (v ? new Date(v).toLocaleString() : "never");
  $("knowledgeWorkspace").innerHTML = `
    <p class="intel-scope">ข่าวกรองเป็นข้อมูลประกอบ ไม่ใช่หลักฐานว่าเกิด exploit หรือคำสั่งบล็อก · ผู้ดูแลระบุ CPE/version ใน Assets และตรวจเงื่อนไขเพิ่มเติมก่อนตัดสินใจ</p>
    <div class="knowledge-columns"><section aria-labelledby="sourceNvdTitle"><h3 id="sourceNvdTitle">NVD CVE &amp; declared products</h3>
      <form id="sourceNvdForm" class="source-form"><label>CVE ID<input id="sourceCve" required maxlength="28" placeholder="CVE-2024-4577" /></label><div class="source-actions"><button id="sourceNvdView" class="quiet-button">View cached NVD</button><button id="sourceNvdFetch" type="button" class="workspace-button">Fetch NVD</button></div></form>
      <p id="sourceNvdStatus" class="intel-status" role="status">ระบุ CVE หรือเลือก Inspect NVD จากรายการ KEV</p><div id="sourceNvdResult"></div>
      <section class="source-assessment" aria-labelledby="sourceAssessmentTitle"><h3 id="sourceAssessmentTitle">Declared product assessment</h3><p class="intel-scope">ใช้ข้อมูล CPE/version ที่ผู้ดูแลระบุในทะเบียน · ผล candidate ไม่ใช่การยืนยันช่องโหว่ และ no-match ไม่ใช่การยืนยันว่าเครื่องปลอดภัย</p>
        <label>Registered asset<select id="sourceAsset"><option value="">Select a registered asset…</option></select></label><div class="source-actions"><button id="sourceAssetsMore" class="quiet-button">Load assets</button><button id="sourceAssetReload" class="quiet-button">Reload selected asset</button><a href="#assets">Open Asset inventory</a></div><p id="sourceAssetStatus" class="intel-status" role="status">ทะเบียนอาจยังไม่ครบ ใช้ Assets เพื่อยืนยัน CPE และ version scheme</p>
        <form id="sourceAssessmentForm" class="source-form"><label>Declared by · self-reported<input id="sourceAuthor" required minlength="2" maxlength="80" /></label><label>Reason / evidence<textarea id="sourceRationale" required minlength="8" maxlength="2000" rows="3"></textarea></label><button id="sourceAssess" class="workspace-button">Save assessment</button></form>
        <p id="sourceAssessmentStatus" class="intel-status" role="status">การบันทึกผลใช้ Operation Key และเก็บ revision/snapshot ที่ตรวจ</p><div id="sourceAssessmentResult"></div>
        <details id="sourceAssessmentHistory"><summary>Saved assessment history</summary><div id="sourceHistoryItems"></div><div class="intel-pager"><button id="sourceHistoryPrevious" class="quiet-button">Previous</button><span id="sourceHistoryPage">—</span><button id="sourceHistoryNext" class="quiet-button">Next</button></div></details>
      </section>
    </section><section aria-labelledby="sourceCatalogTitle"><h3 id="sourceCatalogTitle">Retained source catalogs</h3><p class="intel-scope">MITRE ตรวจอัปเดตรายสัปดาห์ · DROP รายวัน · แสดง freshness และข้อผิดพลาดตามจริง · ไม่มีการนำรายการไปบล็อกอัตโนมัติ</p><div id="sourceFeeds"></div>
      <section class="source-techniques" aria-labelledby="sourceTechniquesTitle"><h3 id="sourceTechniquesTitle">MITRE ATT&amp;CK techniques</h3><form id="sourceTechniqueForm" class="source-form"><label>Technique / name / tactic<input id="sourceTechniqueQuery" maxlength="120" placeholder="T1190, credential-access…" /></label><button class="quiet-button">Search techniques</button></form><p id="sourceTechniqueStatus" class="intel-status" role="status">Loading techniques…</p><div id="sourceTechniques"></div><div class="intel-pager"><button id="sourceTechniquePrevious" class="quiet-button">Previous</button><span id="sourceTechniquePage">—</span><button id="sourceTechniqueNext" class="quiet-button">Next</button></div><p class="intel-scope">MITRE ATT&amp;CK® · ไม่ใช่รายการรับรอง detection coverage · <a href="static/licenses/mitre-attack.txt" target="_blank" rel="noopener noreferrer">MITRE copyright &amp; license</a></p></section>
      <section class="source-ip" aria-labelledby="sourceIpTitle"><h3 id="sourceIpTitle">IP range reputation</h3><form id="sourceIpForm" class="source-form"><label>IPv4 / IPv6 address<input id="sourceIp" required maxlength="80" placeholder="Observed IP address" /></label><button class="quiet-button">Look up retained DROP</button></form><p id="sourceIpStatus" class="intel-status" role="status">ค้นในข้อมูลที่เก็บในเครื่องเท่านั้น ไม่ส่ง IP ไปยังผู้ให้บริการ</p><div id="sourceIpResult"></div></section>
    </section></div>`;
  let nvdBusy = false,
    assessmentBusy = false,
    assetPage = 0,
    assetPages = 1,
    selectedAsset,
    assetTicket = 0,
    techPage = 1,
    techPages = 1,
    techAbort,
    historyPage = 1,
    historyPages = 1,
    retry,
    loaded = false;
  const assetOptions = new Map();
  const assessmentLabel = (state) =>
    ({
      candidate_affected: "Candidate match · verify applicability",
      needs_review: "Needs review",
      needs_environment_review: "Environment review needed",
      no_match_in_declared_products: "No match in declared products",
    })[state] || state;
  const uuid = () => {
    const b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  const status = (id, text, error = false) => {
    $(id).textContent = text;
    $(id).classList.toggle("error", error);
  };
  async function api(path, options = {}, signal) {
    const response = await fetch(prefix + "/api/v1" + path, {
      ...options,
      signal:
        signal ||
        AbortSignal.timeout(options.method === "POST" ? 90000 : 20000),
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
          : "Request failed · HTTP " + response.status,
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
      prompt("Operation Key for saving / fetching source data")?.trim() ||
      "";
    if (value) sessionStorage.opkey = value;
    return value;
  }
  function link(label, path) {
    const a = n("a", label);
    a.href = prefix + path;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    return a;
  }
  function disclosure(label, value) {
    const d = n("details");
    d.append(
      n("summary", label),
      n("pre", JSON.stringify(value, null, 2), "evidence-code"),
    );
    return d;
  }
  function sourceHeader(result) {
    const div = n("div", undefined, "source-provenance");
    div.append(
      n(
        "p",
        `${result.provider} · ${result.state} · last success ${date(result.last_success)} · publisher modified ${date(result.published_at)}`,
      ),
    );
    if (result.error) div.append(n("p", result.error, "intel-status error"));
    if (result.snapshot_id)
      div.append(
        link(
          "Stored source snapshot #" + result.snapshot_id,
          "/api/v1/knowledge/snapshots/" + result.snapshot_id,
        ),
      );
    return div;
  }
  async function nvd(fetchNew = false) {
    if (nvdBusy) return;
    const cve = $("sourceCve").value.trim().toUpperCase();
    $("sourceCve").value = cve;
    if (!/^CVE-\d{4}-\d{4,19}$/.test(cve)) {
      status("sourceNvdStatus", "Use one complete CVE ID.", true);
      return;
    }
    let operation = "";
    if (fetchNew) {
      operation = key();
      if (!operation) {
        status("sourceNvdStatus", "Fetch cancelled; CVE retained.");
        return;
      }
    }
    nvdBusy = true;
    $("sourceNvdFetch").disabled = $("sourceNvdView").disabled = true;
    $("sourceCve").readOnly = true;
    $("sourceNvdResult").replaceChildren();
    status(
      "sourceNvdStatus",
      fetchNew ? "Fetching NVD…" : "Reading retained NVD…",
    );
    try {
      let action = "local cache";
      if (fetchNew) {
        const update = await api("/knowledge/refresh/nvd/" + cve, {
          method: "POST",
          headers: { "X-Operation-Key": operation },
        });
        action = update.action;
      }
      const data = await api("/knowledge/nvd/" + cve);
      const children = [sourceHeader(data)];
      const record = data.payload?.record;
      if (record) {
        children.push(
          n("h4", record.id),
          n("p", `${record.vulnStatus} · modified ${record.lastModified}`),
        );
        const description = record.descriptions.find((x) => x.lang === "en");
        children.push(
          n("p", description?.value || "English description not supplied"),
        );
        children.push(
          disclosure(
            "NVD metrics / CVSS (not exploitation probability)",
            record.metrics || {},
          ),
          disclosure(
            "NVD applicability configurations",
            record.configurations || [],
          ),
        );
      } else
        children.push(
          n(
            "p",
            data.snapshot_id
              ? "NVD returned no record. Missing data is not a clean result."
              : "No retained NVD record. Fetch this CVE with the Operation Key.",
          ),
        );
      children.push(
        n(
          "p",
          data.payload?.notice ||
            "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
          "intel-scope",
        ),
      );
      $("sourceNvdResult").replaceChildren(...children);
      status(
        "sourceNvdStatus",
        action + " · " + data.state,
        action === "failed",
      );
    } catch (e) {
      status(
        "sourceNvdStatus",
        e.message + " · Retry cached read or Fetch NVD.",
        true,
      );
    } finally {
      nvdBusy = false;
      $("sourceNvdFetch").disabled = $("sourceNvdView").disabled = false;
      $("sourceCve").readOnly = false;
    }
  }
  async function feeds() {
    try {
      const data = await api("/knowledge/status");
      $("sourceFeeds").replaceChildren(
        ...data.items.map((row) => {
          const section = n("div", undefined, "source-feed");
          section.append(
            n(
              "h4",
              row.provider === "mitre"
                ? "MITRE ATT&CK Enterprise"
                : row.provider === "drop4"
                  ? "Spamhaus DROP IPv4"
                  : "Spamhaus DROP IPv6",
            ),
            sourceHeader(row),
          );
          const payload = row.payload || {};
          if (payload.copyright)
            section.append(
              n(
                "p",
                `${payload.copyright} · publisher date ${payload.publisher_date}`,
                "intel-scope",
              ),
            );
          if (payload.notice)
            section.append(n("p", payload.notice, "intel-scope"));
          if (payload.terms) {
            const terms = n("a", "Publisher terms");
            terms.href =
              "https://www.spamhaus.org/blocklists/drop-fair-use-policy/";
            terms.target = "_blank";
            terms.rel = "noopener noreferrer";
            section.append(terms);
          }
          const button = n("button", "Refresh " + row.provider, "quiet-button");
          button.addEventListener("click", async () => {
            const operation = key();
            if (!operation) return;
            button.disabled = true;
            try {
              const update = await api(
                "/knowledge/refresh/" + row.provider + "/catalog",
                { method: "POST", headers: { "X-Operation-Key": operation } },
              );
              await feeds();
              if (row.provider === "mitre") await techniques();
              if (update.action === "failed")
                status(
                  "sourceTechniqueStatus",
                  "Source refresh failed; retained snapshot remains visible.",
                  true,
                );
            } catch (e) {
              button.disabled = false;
              button.after(n("p", e.message, "intel-status error"));
            }
          });
          section.append(button);
          return section;
        }),
      );
    } catch (e) {
      $("sourceFeeds").replaceChildren(
        n(
          "p",
          "Sources unavailable: " +
            e.message +
            " · Refresh the dashboard to retry.",
          "intel-status error",
        ),
      );
    }
  }
  async function techniques() {
    techAbort?.abort();
    const controller = (techAbort = new AbortController());
    $("sourceTechniquePrevious").disabled = $("sourceTechniqueNext").disabled =
      true;
    try {
      const data = await api(
        "/knowledge/techniques?" +
          new URLSearchParams({
            q: $("sourceTechniqueQuery").value.trim(),
            page: techPage,
            page_size: 5,
          }),
        {},
        controller.signal,
      );
      if (controller !== techAbort) return;
      techPage = data.page;
      techPages = data.pages;
      $("sourceTechniquePage").textContent = `${techPage} / ${techPages}`;
      status(
        "sourceTechniqueStatus",
        `${data.total} techniques · ${data.source.state}`,
      );
      $("sourceTechniques").replaceChildren(
        ...data.items.map((row) => {
          const article = n("article", undefined, "source-technique");
          article.append(
            n("h4", row.id + " · " + row.name),
            n("p", row.tactics.join(" · ")),
            n(
              "p",
              `Technique version ${row.version} · modified ${row.modified}`,
            ),
            disclosure("Technique description", row.description),
          );
          const a = n("a", "MITRE reference");
          a.href =
            "https://attack.mitre.org/techniques/" +
            row.id.replace(".", "/") +
            "/";
          a.target = "_blank";
          a.rel = "noopener noreferrer";
          article.append(a);
          return article;
        }),
      );
      if (!data.items.length)
        $("sourceTechniques").append(
          n(
            "p",
            "No retained techniques match; check catalog freshness and search.",
            "intel-scope",
          ),
        );
      $("sourceTechniquePrevious").disabled = techPage <= 1;
      $("sourceTechniqueNext").disabled = techPage >= techPages;
    } catch (e) {
      if (e.name !== "AbortError") {
        status(
          "sourceTechniqueStatus",
          "Techniques unavailable: " + e.message,
          true,
        );
        $("sourceTechniques").replaceChildren();
      }
    }
  }
  async function assetsMore() {
    if (assetPage >= assetPages) return;
    $("sourceAssetsMore").disabled = true;
    try {
      const data = await api(
        "/assets?" +
          new URLSearchParams({
            page: assetPage + 1,
            page_size: 50,
            status: "active",
            kind: "all",
          }),
      );
      assetPage = data.page;
      assetPages = data.pages;
      for (const row of data.items) {
        if (!assetOptions.has(row.asset_id)) {
          const option = n(
            "option",
            row.payload.name + " · " + row.payload.kind,
          );
          option.value = row.asset_id;
          $("sourceAsset").append(option);
        }
        assetOptions.set(row.asset_id, row);
      }
      status(
        "sourceAssetStatus",
        `${assetOptions.size} loaded / ${data.total} active assets · select one to load its current revision`,
      );
    } catch (e) {
      status(
        "sourceAssetStatus",
        "Assets unavailable: " + e.message + " · Load assets to retry.",
        true,
      );
    } finally {
      $("sourceAssetsMore").disabled = assetPage >= assetPages;
    }
  }
  async function selectAsset(id) {
    if (assessmentBusy) return;
    const ticket = ++assetTicket;
    selectedAsset = null;
    status("sourceAssetStatus", "Loading selected asset revision…");
    try {
      const data = await api("/assets/" + id);
      if (ticket !== assetTicket) return;
      selectedAsset = data.current;
      if (!assetOptions.has(id)) {
        const option = n(
          "option",
          selectedAsset.payload.name + " · " + selectedAsset.payload.kind,
        );
        option.value = id;
        $("sourceAsset").append(option);
      }
      assetOptions.set(id, selectedAsset);
      $("sourceAsset").value = id;
      status(
        "sourceAssetStatus",
        `${selectedAsset.payload.name} · revision ${selectedAsset.revision} · ${selectedAsset.payload.software.length} declared products. Checks require explicit CPE and version scheme.`,
      );
      historyPage = 1;
      await history();
    } catch (e) {
      if (ticket === assetTicket)
        status(
          "sourceAssetStatus",
          e.message + " · Reload selected asset to retry.",
          true,
        );
    }
  }
  function renderAssessment(row) {
    $("sourceAssessmentResult").replaceChildren(
      n("h4", `Assessment #${row.id} · ${assessmentLabel(row.report.state)}`),
      n(
        "p",
        `${row.cve} · asset revision ${row.asset_revision} · ${row.declared_by} (self-reported) · ${date(row.created_at)}`,
      ),
      n("p", "Saved reason / evidence: " + row.rationale),
      n("p", row.report.scope, "intel-scope"),
      link("Stored immutable assessment", "/api/v1/applicability/" + row.id),
      link(
        "NVD source snapshot #" + row.nvd_snapshot_id,
        "/api/v1/knowledge/snapshots/" + row.nvd_snapshot_id,
      ),
      disclosure("Product results, criteria & uncertainty", row.report),
    );
  }
  async function history() {
    const id = selectedAsset?.asset_id;
    if (!id) return;
    $("sourceHistoryPrevious").disabled = $("sourceHistoryNext").disabled =
      true;
    try {
      const data = await api(`/applicability/asset/${id}?page=${historyPage}`);
      if (selectedAsset?.asset_id !== id) return;
      historyPage = data.page;
      historyPages = data.pages;
      $("sourceHistoryPage").textContent = `${historyPage} / ${historyPages}`;
      $("sourceHistoryItems").replaceChildren(
        ...data.items.map((row) => {
          const button = n(
            "button",
            `#${row.id} · ${row.cve} · revision ${row.asset_revision} · ${assessmentLabel(row.report.state)}`,
            "quiet-button",
          );
          button.addEventListener("click", () => renderAssessment(row));
          return button;
        }),
      );
      if (!data.items.length)
        $("sourceHistoryItems").append(
          n("p", "No saved assessments for this asset.", "intel-scope"),
        );
      $("sourceHistoryPrevious").disabled = historyPage <= 1;
      $("sourceHistoryNext").disabled = historyPage >= historyPages;
    } catch (e) {
      status(
        "sourceAssessmentStatus",
        "History unavailable: " +
          e.message +
          " · Reload selected asset to retry.",
        true,
      );
    }
  }
  $("sourceAssessmentForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (assessmentBusy) return;
    if (!selectedAsset) {
      status(
        "sourceAssessmentStatus",
        "Select and load a registered asset first.",
        true,
      );
      return;
    }
    const cve = $("sourceCve").value.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,19}$/.test(cve)) {
      status(
        "sourceAssessmentStatus",
        "Enter a complete CVE ID and fetch its NVD record first.",
        true,
      );
      return;
    }
    const body = {
      asset_id: selectedAsset.asset_id,
      asset_revision: selectedAsset.revision,
      cve,
      declared_by: $("sourceAuthor").value.trim(),
      rationale: $("sourceRationale").value.trim(),
    };
    const signature = JSON.stringify(body);
    if (!retry || retry.signature !== signature)
      retry = { signature, request_id: uuid() };
    const operation = key();
    if (!operation) return;
    assessmentBusy = true;
    $("sourceAssessmentForm").inert = true;
    $("sourceAsset").disabled = $("sourceAssetReload").disabled = true;
    status("sourceAssessmentStatus", "Saving revision-bound assessment…");
    try {
      const data = await api("/applicability", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Operation-Key": operation,
        },
        body: JSON.stringify({ ...body, request_id: retry.request_id }),
      });
      renderAssessment(data.assessment);
      retry = null;
      status(
        "sourceAssessmentStatus",
        `Saved assessment #${data.assessment.id}${data.replayed ? " · retry recovered" : ""}`,
      );
      await history();
    } catch (e) {
      status(
        "sourceAssessmentStatus",
        e.message +
          " · Draft retained; reload the selected asset if its revision changed.",
        true,
      );
    } finally {
      assessmentBusy = false;
      $("sourceAssessmentForm").inert = false;
      $("sourceAsset").disabled = $("sourceAssetReload").disabled = false;
    }
  });
  $("sourceNvdForm").addEventListener("submit", (e) => {
    e.preventDefault();
    nvd();
  });
  $("sourceNvdFetch").addEventListener("click", () => nvd(true));
  $("sourceAssetsMore").addEventListener("click", assetsMore);
  $("sourceAsset").addEventListener("change", () => {
    if ($("sourceAsset").value) selectAsset($("sourceAsset").value);
    else {
      selectedAsset = null;
      status(
        "sourceAssetStatus",
        "Select a registered asset before assessment.",
      );
    }
  });
  $("sourceAssetReload").addEventListener("click", () => {
    if ($("sourceAsset").value) selectAsset($("sourceAsset").value);
  });
  $("sourceTechniqueForm").addEventListener("submit", (e) => {
    e.preventDefault();
    techPage = 1;
    techniques();
  });
  $("sourceTechniquePrevious").addEventListener("click", () => {
    if (techPage > 1) {
      techPage--;
      techniques();
    }
  });
  $("sourceTechniqueNext").addEventListener("click", () => {
    if (techPage < techPages) {
      techPage++;
      techniques();
    }
  });
  $("sourceHistoryPrevious").addEventListener("click", () => {
    if (historyPage > 1) {
      historyPage--;
      history();
    }
  });
  $("sourceHistoryNext").addEventListener("click", () => {
    if (historyPage < historyPages) {
      historyPage++;
      history();
    }
  });
  $("sourceIpForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = e.submitter;
    button.disabled = true;
    $("sourceIpResult").replaceChildren();
    try {
      const data = await api(
        "/knowledge/ip?" +
          new URLSearchParams({ value: $("sourceIp").value.trim() }),
      );
      $("sourceIpResult").replaceChildren(
        sourceHeader(data.source),
        n(
          "p",
          data.matches.length
            ? data.matches.map((x) => x.cidr + " · " + x.sblid).join("; ")
            : "Not listed in this retained snapshot (or no snapshot). This does not mean safe.",
        ),
        n("p", data.scope, "intel-scope"),
      );
      status("sourceIpStatus", data.ip + " · " + data.source.state);
    } catch (error) {
      status("sourceIpStatus", error.message + " · Retry lookup.", true);
    } finally {
      button.disabled = false;
    }
  });
  function attachProvenance(parent, analysis) {
    const section = n("section", undefined, "source-analysis-provenance");
    section.append(n("h3", "Analysis provenance"));
    if (analysis.execution_provenance)
      section.append(
        disclosure(
          "Prompt/model execution metadata",
          analysis.execution_provenance,
        ),
      );
    else
      section.append(
        n("p", "Not recorded for this historical analysis.", "payload-note"),
      );
    const citations = analysis.source_citations || [];
    if (citations.length)
      section.append(
        n(
          "p",
          "Retained catalog references for source identifiers; not proof the event used these techniques or exploited a CVE.",
          "payload-note",
        ),
      );
    for (const citation of citations) {
      const p = n(
        "p",
        `${citation.provider} · ${citation.identifier} · ${citation.state} · ${citation.scope}`,
      );
      if (
        Number.isSafeInteger(citation.snapshot_id) &&
        citation.snapshot_id > 0
      )
        p.append(
          document.createTextNode(" · "),
          link(
            "Snapshot #" + citation.snapshot_id,
            "/api/v1/knowledge/snapshots/" + citation.snapshot_id,
          ),
        );
      section.append(p);
    }
    parent.append(section);
  }
  window.EdgeKnowledge = {
    refresh: async () => {
      await Promise.all([
        feeds(),
        techniques(),
        loaded ? Promise.resolve() : assetsMore(),
      ]);
      loaded = true;
    },
    selectCve: (cve) => {
      $("sourceCve").value = cve;
      location.hash = "sources";
      nvd();
    },
    selectAsset: (id) => {
      location.hash = "sources";
      selectAsset(id);
    },
    attachProvenance,
  };
})();
