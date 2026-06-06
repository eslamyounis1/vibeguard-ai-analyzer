(function () {
  const vscode = acquireVsCodeApi();
  const messagesEl = document.getElementById("messages");
  const inputEl = document.getElementById("input");
  const sendBtn = document.getElementById("send");
  const insertBtn = document.getElementById("insert");
  const scanBtn = document.getElementById("scan");
  const configLine = document.getElementById("config-line");

  let lastCode = "";

  function appendMessage(className, html) {
    const div = document.createElement("div");
    div.className = "msg " + className;
    div.innerHTML = html;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  sendBtn.addEventListener("click", () => {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = "";
    vscode.postMessage({ type: "send", text });
  });

  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      sendBtn.click();
    }
  });

  insertBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "insert", code: lastCode });
  });

  scanBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "scan" });
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg.type) {
      case "config":
        configLine.textContent = `${msg.provider}:${msg.model} @ ${msg.orchestrator}`;
        break;
      case "user":
        appendMessage("user", escapeHtml(msg.content));
        break;
      case "status":
        appendMessage("status", escapeHtml(msg.content));
        break;
      case "error":
        appendMessage("error", escapeHtml(msg.content));
        break;
      case "assistant": {
        const res = msg.response;
        lastCode = res.code || "";
        insertBtn.disabled = !lastCode;
        scanBtn.disabled = !lastCode;
        const status = res.clean
          ? "✓ Passed VibeGuard security rules"
          : `⚠ ${res.findings.length} rule violation(s)`;
        let html =
          `<div class="meta">${escapeHtml(status)}</div>` +
          `<pre><code>${escapeHtml(lastCode)}</code></pre>`;
        if (res.findings && res.findings.length) {
          html += '<ul class="findings">';
          for (const f of res.findings) {
            const tag = f.owasp ? ` (${f.owasp})` : "";
            html += `<li>[${escapeHtml(f.rule_id)}] ${escapeHtml(f.message)}${escapeHtml(tag)}</li>`;
          }
          html += "</ul>";
        }
        appendMessage("assistant", html);
        break;
      }
    }
  });

  vscode.postMessage({ type: "ready" });
})();
