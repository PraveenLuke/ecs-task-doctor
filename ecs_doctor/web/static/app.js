let _evtSource = null;

function startStream(cluster, service, region) {
  const panel = document.getElementById("stream-panel");
  const output = document.getElementById("log-output");

  panel.style.display = "block";
  output.textContent = "";

  const url = `/api/stream-logs?cluster=${encodeURIComponent(cluster)}&service=${encodeURIComponent(service)}&region=${encodeURIComponent(region)}`;
  _evtSource = new EventSource(url);

  _evtSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.error) {
      output.textContent += `[error] ${data.error}\n`;
      return;
    }
    output.textContent += `[${data.container}] ${data.message}\n`;
    output.scrollTop = output.scrollHeight;
  };

  _evtSource.onerror = () => {
    output.textContent += "\n[stream ended]\n";
    _evtSource.close();
  };
}

function stopStream() {
  if (_evtSource) { _evtSource.close(); _evtSource = null; }
}
