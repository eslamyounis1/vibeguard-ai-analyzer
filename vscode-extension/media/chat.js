(function () {
  const vscode = acquireVsCodeApi();
  const messagesEl = document.getElementById("messages");
  const emptyState = document.getElementById("empty-state");
  const inputEl = document.getElementById("input");
  const sendBtn = document.getElementById("send");
  const insertBtn = document.getElementById("insert");
  const scanBtn = document.getElementById("scan");
  const clearBtn = document.getElementById("clear-btn");
  const configLine = document.getElementById("config-line");

  let lastCode = "";
  let lastUserText = "";
  let statusEl = null; // reference to the current "Generating…" bubble

  // ── Helpers ──────────────────────────────────────────────────────────────

  function showEmptyState(show) {
    if (emptyState) {
      emptyState.style.display = show ? "" : "none";
    }
  }

  function appendMessage(className, html) {
    showEmptyState(false);
    const div = document.createElement("div");
    div.className = "msg " + className;
    div.innerHTML = html;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return div;
  }

  function removeStatusEl() {
    if (statusEl && statusEl.parentNode) {
      statusEl.parentNode.removeChild(statusEl);
    }
    statusEl = null;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function selectText(el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    if (sel) {
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }

  // ── Send ─────────────────────────────────────────────────────────────────

  function sendMessage() {
    const text = inputEl.value.trim();
    if (!text) return;
    lastUserText = text;
    inputEl.value = "";
    sendBtn.disabled = true;
    vscode.postMessage({ type: "send", text });
  }

  sendBtn.addEventListener("click", sendMessage);

  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      sendMessage();
    }
  });

  insertBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "insert", code: lastCode });
  });

  scanBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "scan" });
  });

  // ── Clear chat ────────────────────────────────────────────────────────────

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      // Remove all message bubbles but keep #empty-state in the DOM
      const msgs = messagesEl.querySelectorAll(".msg");
      msgs.forEach((m) => m.remove());
      showEmptyState(true);
      insertBtn.disabled = true;
      scanBtn.disabled = true;
      sendBtn.disabled = false;
      lastCode = "";
      lastUserText = "";
      statusEl = null;
      vscode.postMessage({ type: "clear" });
    });
  }

  // ── Event delegation for copy and retry buttons ───────────────────────────

  messagesEl.addEventListener("click", (e) => {
    const btn = e.target;
    if (!btn) return;

    if (btn.classList.contains("copy-btn")) {
      const wrapper = btn.closest(".code-wrapper");
      const codeEl = wrapper ? wrapper.querySelector("code") : null;
      if (codeEl) {
        const text = codeEl.textContent || "";
        if (navigator.clipboard) {
          navigator.clipboard.writeText(text).then(() => {
            btn.textContent = "Copied!";
            setTimeout(() => { btn.textContent = "Copy"; }, 1500);
          }).catch(() => selectText(codeEl));
        } else {
          selectText(codeEl);
        }
      }
    } else if (btn.classList.contains("retry-btn")) {
      if (lastUserText) {
        inputEl.value = lastUserText;
        sendMessage();
      }
    }
  });

  // ── Message handler ───────────────────────────────────────────────────────

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg.type) {

      case "config":
        configLine.textContent = `${msg.provider}:${msg.model} @ ${msg.orchestrator}`;
        break;

      case "history-restored": {
        if (msg.count > 0) {
          showEmptyState(false);
          const div = document.createElement("div");
          div.className = "msg history-note";
          div.textContent = `↩ Restored ${msg.count} message(s) from previous session.`;
          messagesEl.appendChild(div);
          if (msg.lastCode) {
            lastCode = msg.lastCode;
            insertBtn.disabled = false;
            scanBtn.disabled = false;
          }
        }
        break;
      }

      case "user":
        appendMessage("user", escapeHtml(msg.content));
        break;

      case "status":
        // Replace any previous loading bubble with the new one
        removeStatusEl();
        statusEl = appendMessage("status loading", escapeHtml(msg.content));
        break;

      case "error": {
        removeStatusEl();
        sendBtn.disabled = false;
        const retryHtml = lastUserText
          ? `<br><button class="retry-btn">Retry</button>`
          : "";
        appendMessage("error", escapeHtml(msg.content) + retryHtml);
        break;
      }

      case "assistant": {
        removeStatusEl();
        sendBtn.disabled = false;
        const res = msg.response;
        lastCode = res.code || "";
        insertBtn.disabled = !lastCode;
        scanBtn.disabled = !lastCode;

        const statusText = res.clean
          ? "✓ Passed VibeGuard security rules"
          : `⚠ ${res.findings.length} rule violation(s)`;

        const codeId = "code-" + String(Date.now()) + "-" + String(Math.random()).slice(2, 7);
        let html =
          `<div class="meta">${escapeHtml(statusText)}</div>` +
          `<div class="code-wrapper">` +
          `<pre><code id="${escapeHtml(codeId)}">${escapeHtml(lastCode)}</code></pre>` +
          `<button class="copy-btn" aria-label="Copy code to clipboard">Copy</button>` +
          `</div>`;

        if (res.findings && res.findings.length) {
          html += '<ul class="findings">';
          for (const f of res.findings) {
            const tag = f.owasp ? ` (${f.owasp})` : "";
            html += `<li>[${escapeHtml(f.rule_id)}] ${escapeHtml(f.message)}${escapeHtml(tag)}</li>`;
          }
          html += "</ul>";
        }
        appendMessage("assistant", html);

        // Apply Python syntax highlighting after the element is in the DOM
        if (window.pyHighlight && lastCode) {
          const codeEl = document.getElementById(codeId);
          if (codeEl) {
            codeEl.innerHTML = window.pyHighlight.highlight(lastCode);
          }
        }
        break;
      }
    }
  });

  vscode.postMessage({ type: "ready" });
})();
