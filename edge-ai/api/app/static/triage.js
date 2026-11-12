(() => {
  const prefix =
    location.pathname.match(/^\/(AIEdgeGuard|aiedge)(?=\/|$)/)?.[0] || "";
  const $ = (id) => document.getElementById(id);
  const text = (tag, value, cls) => {
    const n = document.createElement(tag);
    n.textContent = value;
    if (cls) n.className = cls;
    return n;
  };
  let selected = null,
    page = 1,
    pages = 1,
    snapshot = null,
    queueAbort,
    streamAbort,
    payloadAbort,
    busy = false,
    active = false,
    loaded = false,
    configLoaded = false;
  const status = (message, error = false) => {
    $("triageStreamStatus").textContent = message;
    $("triageStreamStatus").classList.toggle("error", error);
  };
  async function api(path, signal) {
    const response = await fetch(prefix + "/api/v1/ai" + path, {
      signal: signal || AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      let data;
      try {
        data = await response.json();
      } catch {}
      throw new Error(
        typeof data?.detail === "string"
          ? data.detail
          : "HTTP " + response.status,
      );
    }
    return response.json();
  }
  function controls() {
    $("triageStart").disabled = !selected || busy;
    $("triageStop").disabled = !busy;
    ["triageLanguage", "triageModel", "triageHostname", "triageBypass"].forEach(
      (id) => ($(id).disabled = busy),
    );
    $("triageInspect").disabled = !selected || busy;
  }
  function stop() {
    streamAbort?.abort();
  }
  async function models() {
    $("triageConfigStatus").textContent = "Loading installed models…";
    try {
      const data = await api("/config");
      const current = $("triageModel").value;
      const entries = [...new Set([data.default_model, ...data.models])];
      $("triageModel").replaceChildren(
        ...entries.map((model) => {
          const o = text(
            "option",
            model + (model === data.default_model ? " · server default" : ""),
          );
          o.value = model;
          return o;
        }),
      );
      if (entries.includes(current)) $("triageModel").value = current;
      else $("triageModel").value = data.default_model;
      $("triageConfigStatus").textContent =
        "Local Ollama · cache " +
        data.cache_ttl / 60 +
        " min · model selection applies to this session only";
      configLoaded = true;
    } catch (error) {
      $("triageConfigStatus").textContent =
        error.message +
        " · Reload models to retry. Server default remains available.";
    }
  }
  async function loadQueue(reset = false) {
    if (reset) {
      page = 1;
      snapshot = null;
    }
    queueAbort?.abort();
    queueAbort = new AbortController();
    const controller = queueAbort;
    $("triageSync").disabled = true;
    $("triagePrevious").disabled = true;
    $("triageNext").disabled = true;
    $("triageQueueStatus").textContent = "Loading Wazuh queue…";
    try {
      const query = new URLSearchParams({
        page,
        page_size: 10,
        min_level: $("triageLevel").value,
      });
      if (snapshot !== null) query.set("snapshot", snapshot);
      const data = await api("/queue?" + query, controller.signal);
      if (controller !== queueAbort) return;
      page = data.page;
      pages = data.pages;
      snapshot = data.snapshot;
      const list = data.items.map((row) => {
        const button = text("button", "", "triage-alert");
        button.type = "button";
        button.setAttribute("aria-pressed", String(selected?.id === row.id));
        button.dataset.incidentId = row.id;
        button.append(
          text(
            "span",
            "LVL " + row.level,
            "record-badge " +
              (row.level >= 12
                ? "critical"
                : row.level >= 8
                  ? "high"
                  : "medium"),
          ),
          text(
            "span",
            "Rule #" +
              (row.rule_id || "—") +
              (row.mitre?.length ? " · " + row.mitre.join(", ") : ""),
            "triage-rule",
          ),
          text("strong", row.reason),
          text(
            "small",
            (row.hostname || "Unknown host") +
              " · " +
              new Date(row.created_at).toLocaleString(),
          ),
        );
        button.addEventListener("click", () => select(row));
        return button;
      });
      if (!list.length)
        list.push(
          text(
            "p",
            "ไม่มี Wazuh alert ในระดับนี้ ลองเลือก 5 · All ingested หรือกด Sync queue",
            "triage-status",
          ),
        );
      $("triageQueue").replaceChildren(...list);
      $("triageQueueStatus").textContent =
        data.total.toLocaleString() +
        " alerts · priority ordered by rule level, then newest";
      $("triagePage").textContent = page + " / " + pages;
      $("triagePrevious").disabled = page <= 1;
      $("triageNext").disabled = page >= pages;
      loaded = true;
    } catch (error) {
      if (error.name !== "AbortError") {
        $("triageQueue").replaceChildren();
        $("triageQueueStatus").textContent =
          "โหลดคิวไม่ได้: " + error.message + " · Sync queue เพื่อลองใหม่";
        $("triagePage").textContent = "Unavailable";
      }
    } finally {
      if (controller === queueAbort) $("triageSync").disabled = false;
    }
  }
  function select(row) {
    stop();
    payloadAbort?.abort();
    selected = row;
    $("triageModelInfo").textContent = "Not generated · local Ollama";
    document
      .querySelectorAll(".triage-alert")
      .forEach((button) =>
        button.setAttribute(
          "aria-pressed",
          String(Number(button.dataset.incidentId) === row.id),
        ),
      );
    $("triageSelection").textContent =
      row.alert_id + " · " + (row.hostname || "Unknown host");
    $("triageHostname").value = "";
    $("triageReport").textContent =
      "Selected: " + row.reason + "\n\nกด Stream analysis เพื่อสร้างรายงาน";
    $("triagePayload").open = false;
    $("triagePayloadBody").textContent =
      "Inspect cleaned payload เพื่อดูข้อมูลที่จะส่งให้ Ollama";
    $("triagePayloadStats").textContent = "";
    status("Ready · recommendations only");
    controls();
  }
  async function inspect() {
    if (!selected) return;
    payloadAbort?.abort();
    payloadAbort = new AbortController();
    const controller = payloadAbort;
    $("triagePayload").open = true;
    $("triagePayloadBody").textContent = "Loading cleaned context…";
    try {
      const data = await api(
        "/payload/" +
          selected.id +
          "?" +
          new URLSearchParams({ hostname: $("triageHostname").value.trim() }),
        controller.signal,
      );
      if (controller !== payloadAbort) return;
      showPayload(data);
    } catch (error) {
      if (error.name !== "AbortError")
        $("triagePayloadBody").textContent = error.message;
    }
  }
  function showPayload(data) {
    $("triagePayloadBody").textContent = JSON.stringify(data.payload, null, 2);
    $("triagePayloadStats").textContent =
      `Original event ${data.original_bytes.toLocaleString()} B → model context ${data.cleaned_bytes.toLocaleString()} B · ${data.note}`;
  }
  async function start() {
    if (!selected || busy) return;
    const id = selected.id;
    busy = true;
    controls();
    streamAbort = new AbortController();
    const controller = streamAbort;
    $("triageReport").textContent = "";
    $("triageModelInfo").textContent = "Connecting · awaiting model metadata";
    status("Connecting to local Ollama…");
    let timer = setTimeout(() => controller.abort("timeout"), 240000),
      terminal = false;
    try {
      const response = await fetch(prefix + "/api/v1/ai/triage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        signal: controller.signal,
        body: JSON.stringify({
          incident_id: id,
          language: $("triageLanguage").value,
          model: $("triageModel").value,
          hostname: $("triageHostname").value.trim(),
          bypass_cache: $("triageBypass").checked,
        }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "HTTP " + response.status,
        );
      }
      if (!response.headers.get("content-type")?.includes("text/event-stream"))
        throw new Error("Unexpected stream response");
      const reader = response.body.getReader(),
        decoder = new TextDecoder();
      let buffer = "";
      const consume = (block) => {
        const lines = block.split("\n"),
          event = lines
            .find((line) => line.startsWith("event:"))
            ?.slice(6)
            .trim();
        const raw = lines
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!raw) return;
        const data = JSON.parse(raw);
        if (event === "meta") {
          showPayload(data);
          $("triageModelInfo").textContent =
            `${data.model} · ${data.language.toUpperCase()} · ${data.cached ? "Redis cached" : "Live generation"}`;
          status(
            `${data.cached ? "Cache hit" : "Streaming"} · ${data.model} · ${data.language.toUpperCase()}`,
          );
        }
        if (event === "token")
          $("triageReport").append(document.createTextNode(data.text));
        if (event === "done") {
          terminal = true;
          status(
            `${data.cached ? "Cached report" : "Completed"} · ${data.generated_at}${data.cache_saved === false ? " · cache unavailable" : ""}`,
          );
        }
        if (event === "error") throw new Error(data.message);
      };
      while (true) {
        const { done, value } = await reader.read();
        buffer += decoder
          .decode(value || new Uint8Array(), { stream: !done })
          .replace(/\r\n/g, "\n");
        let boundary;
        while ((boundary = buffer.indexOf("\n\n")) !== -1) {
          consume(buffer.slice(0, boundary));
          buffer = buffer.slice(boundary + 2);
        }
        if (done) break;
      }
      if (!terminal)
        throw new Error(
          "Stream interrupted; report incomplete. Retry analysis.",
        );
    } catch (error) {
      controller.abort();
      if (selected?.id === id && active)
        status(
          controller.signal.reason === "timeout"
            ? "Analysis timed out; retry."
            : error.name === "AbortError"
              ? "Stopped · partial report, not complete"
              : error.message,
          true,
        );
    } finally {
      clearTimeout(timer);
      busy = false;
      controls();
    }
  }
  $("triageSync").addEventListener("click", () => loadQueue(true));
  $("triageLevel").addEventListener("change", () => loadQueue(true));
  $("triagePrevious").addEventListener("click", () => {
    page--;
    loadQueue();
  });
  $("triageNext").addEventListener("click", () => {
    page++;
    loadQueue();
  });
  $("triageStart").addEventListener("click", start);
  $("triageStop").addEventListener("click", stop);
  $("triageInspect").addEventListener("click", inspect);
  $("triageReloadModels").addEventListener("click", models);
  $("triageSettingsToggle").addEventListener("click", () => {
    const show = $("triageSettings").hidden;
    $("triageSettings").hidden = !show;
    $("triageSettingsToggle").setAttribute("aria-expanded", String(show));
    if (show && !configLoaded) models();
  });
  ["triageLanguage", "triageModel"].forEach((id) =>
    $(id).addEventListener("change", () => {
      if (selected) {
          $("triageModelInfo").textContent = "Not generated · settings changed";
        $("triageReport").textContent =
          "Settings changed · กด Stream analysis เพื่อสร้างรายงานใหม่";
        status("Ready · settings changed");
      }
    }),
  );
  $("triageHostname").addEventListener("input", () => {
    payloadAbort?.abort();
    $("triagePayloadBody").textContent =
      "Hostname hint changed · Inspect cleaned payload เพื่อดู context ใหม่";
    $("triagePayloadStats").textContent = "";
    if (selected) status("Hostname hint changed · rerun analysis to apply");
  });
  window.EdgeTriage = {
    open() {
      active = true;
      if (!loaded) loadQueue();
    },
    leave() {
      active = false;
      stop();
      payloadAbort?.abort();
    },
  };
})();
