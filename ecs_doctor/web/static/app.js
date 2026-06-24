let _evtSource = null;

/* ── Tab switching ────────────────────────────────────────── */
function switchTab(tabId, btn) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("tab-" + tabId).classList.add("active");
  btn.classList.add("active");
}

/* ── Stream helpers ───────────────────────────────────────── */
function _setStreamStatus(state) {
  const status = document.getElementById("stream-status");
  const btn    = document.getElementById("stream-toggle");
  if (!status) return;
  const map = {
    idle:       ["Not started", "stream-status",            "Start Streaming"],
    connecting: ["Connecting…", "stream-status connecting", "Stop"],
    live:       ["Live",        "stream-status live",       "Stop"],
    ended:      ["Ended",       "stream-status",            "Start Streaming"],
    error:      ["Error",       "stream-status error",      "Retry"],
  };
  const [text, cls, btnText] = map[state] || map.idle;
  status.textContent = text;
  status.className   = cls;
  if (btn) btn.textContent = btnText;
}

function toggleStream() {
  if (_evtSource) {
    stopStream();
  } else {
    const report = document.querySelector(".report");
    if (!report) return;
    startStream(report.dataset.cluster, report.dataset.service, report.dataset.region);
  }
}

function startStream(cluster, service, region) {
  const output  = document.getElementById("log-output");
  const profile = document.getElementById("profile")?.value || "";
  if (!output) return;

  output.textContent = "";
  _setStreamStatus("connecting");

  const params = new URLSearchParams({ cluster, service, region });
  if (profile) params.set("profile", profile);
  _evtSource = new EventSource(`/api/stream-logs?${params}`);

  _evtSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.error) {
      output.textContent += `[error] ${data.error}\n`;
      _setStreamStatus("error");
      _evtSource.close(); _evtSource = null;
      return;
    }
    if (data.info) {
      output.textContent += `[info] ${data.info}\n`;
      _setStreamStatus("ended");
      _evtSource.close(); _evtSource = null;
      return;
    }
    _setStreamStatus("live");
    output.textContent += `[${data.container}] ${data.message}\n`;
    output.scrollTop = output.scrollHeight;
  };

  _evtSource.onerror = () => {
    output.textContent += "\n[stream ended]\n";
    _setStreamStatus("ended");
    _evtSource.close(); _evtSource = null;
  };
}

function stopStream() {
  if (_evtSource) { _evtSource.close(); _evtSource = null; }
  _setStreamStatus("ended");
}
