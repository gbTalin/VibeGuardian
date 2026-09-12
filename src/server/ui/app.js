/* Guardian-Unit-Penetration-Testing Agent dashboard client.
   No framework, no build step, no dependencies. The page is served from
   localhost under a strict CSP that forbids inline script and any external
   origin, which is easiest to honour by simply not needing either. */

const TOKEN = new URLSearchParams(location.search).get("token") || "";
const $ = (id) => document.getElementById(id);

const state = {
  status: null,
  result: null,
  diff: null,
  selected: null,
  filter: "all",
  browsePath: null,
};

/* ---------------------------------------------------------------- helpers */

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]
  );
}

async function api(path, options = {}) {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(`${path}${sep}token=${encodeURIComponent(TOKEN)}`, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json();
}

function showError(message) {
  const box = document.createElement("div");
  box.className = "error";
  box.textContent = message;
  const host = $("view-scan");
  host.insertBefore(box, host.firstChild);
  setTimeout(() => box.remove(), 9000);
}

/* ------------------------------------------------------------------ boot */

async function boot() {
  if (!TOKEN) {
    document.body.innerHTML =
      '<div style="padding:3rem;text-align:center;font-family:sans-serif">' +
      "<h1>Missing access token</h1>" +
      "<p>Open the full URL that Guardian-Unit-Penetration-Testing Agent printed in your terminal.</p></div>";
    return;
  }
  try {
    state.status = await api("/api/status");
  } catch (err) {
    showError(err.message);
    return;
  }
  const s = state.status;

  $("version").textContent = `v${s.version} · local security review`;
  $("path").value = s.defaultRoot;
  state.browsePath = s.defaultRoot;
  $("scanner-count").textContent = `${s.ruleCount} checks across ${s.scanners.length} scanners. No model or network required.`;
  updatePrivacy(s.privacy, s.provider.kind);

  const agentsOk = s.provider.ok && s.agents.length > 0;
  $("opt-agents").disabled = !agentsOk;
  $("agents-hint").textContent = agentsOk
    ? `${s.agents.length} agents ready via ${s.provider.model}.`
    : s.agents.length === 0
      ? "No agent definitions found on this machine."
      : "No model configured yet. Set one up under the Agents tab.";

  renderAgents();
  renderHistory();
  renderChecks();
}

function updatePrivacy(text, kind) {
  $("privacy-text").textContent = text;
  $("privacy-pill").classList.toggle("is-remote", kind !== "none" && kind !== "ollama");
}

/* ------------------------------------------------------------------ tabs */

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("is-active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("is-active"));
    tab.classList.add("is-active");
    $(`view-${tab.dataset.view}`).classList.add("is-active");
  });
});

/* ------------------------------------------------------------------ scan */

$("run").addEventListener("click", runScan);
$("rescan").addEventListener("click", runScan);

async function runScan() {
  const path = $("path").value.trim();
  if (!path) return showError("Choose a folder first.");

  $("setup").hidden = true;
  $("results").hidden = true;
  $("progress").hidden = false;
  $("bar-fill").style.width = "0%";
  $("progress-msg").textContent = "Starting…";
  state.selected = null;

  const body = JSON.stringify({
    path,
    agents: $("opt-agents").checked,
  });

  // The scan streams progress over SSE. fetch + a reader is used rather than
  // EventSource because EventSource cannot issue a POST.
  let res;
  try {
    res = await fetch(`/api/scan?token=${encodeURIComponent(TOKEN)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
  } catch (err) {
    return finishWithError(err.message);
  }
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: res.statusText }));
    return finishWithError(e.error);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() || "";

    for (const frame of frames) {
      const evMatch = /^event: (.+)$/m.exec(frame);
      const dataMatch = /^data: (.+)$/m.exec(frame);
      if (!evMatch || !dataMatch) continue;
      let payload;
      try {
        payload = JSON.parse(dataMatch[1]);
      } catch {
        continue;
      }

      if (evMatch[1] === "progress") {
        $("progress-msg").textContent = payload.message;
        if (typeof payload.fraction === "number") {
          $("bar-fill").style.width = `${Math.round(payload.fraction * 100)}%`;
        }
      } else if (evMatch[1] === "done") {
        state.result = payload.result;
        state.diff = payload.diff;
        $("progress").hidden = true;
        renderResults();
        refreshStatusQuietly();
      } else if (evMatch[1] === "error") {
        finishWithError(payload.message);
      }
    }
  }
}

function finishWithError(message) {
  $("progress").hidden = true;
  $("setup").hidden = false;
  showError(message || "The scan failed.");
}

async function refreshStatusQuietly() {
  try {
    state.status = await api("/api/status");
    renderHistory();
  } catch { /* history is a convenience */ }
}

/* --------------------------------------------------------------- results */

function renderResults() {
  const r = state.result;
  $("results").hidden = false;

  const counts = SEV_ORDER.reduce((acc, s) => ({ ...acc, [s]: 0 }), {});
  for (const f of r.findings) counts[f.severity]++;
  const open = r.findings.filter((f) => f.status === "open");

  // Posture. Deliberately not a score out of 100: a number like that gets
  // screenshotted into a board deck and read as a guarantee.
  let label, detail, tone;
  if (counts.critical > 0) {
    label = "Act now";
    detail = `${counts.critical} critical ${counts.critical === 1 ? "issue needs" : "issues need"} attention today.`;
    tone = "tone-critical";
  } else if (counts.high > 0) {
    label = "Fix this week";
    detail = `${counts.high} high-severity ${counts.high === 1 ? "issue" : "issues"}. No criticals.`;
    tone = "tone-warn";
  } else if (counts.medium > 0) {
    label = "Worth cleaning up";
    detail = `${counts.medium} medium ${counts.medium === 1 ? "issue" : "issues"}. Nothing urgent.`;
    tone = "tone-warn";
  } else {
    label = "Nothing found";
    detail = "No issues matched the rules that ran. That is not the same as being secure — read what was covered below.";
    tone = "tone-ok";
  }
  $("posture").className = `posture ${tone}`;
  $("posture-label").textContent = label;
  $("posture-detail").textContent = `${detail} Scanned ${r.coverage.filesScanned.toLocaleString()} files in ${(r.durationMs / 1000).toFixed(1)}s.`;

  for (const [id, fmt] of [["dl-md", "md"], ["dl-sarif", "sarif"], ["dl-json", "json"]]) {
    $(id).href = `/api/report/${r.scanId}.${fmt}?token=${encodeURIComponent(TOKEN)}`;
  }

  // Change since the last scan.
  const d = state.diff;
  if (d && d.previousScanId) {
    $("diff").hidden = false;
    $("diff").innerHTML =
      `Since the last scan of this folder: <b>${d.resolved}</b> no longer detected, ` +
      `<b>${d.introduced}</b> new, <b>${d.persisting}</b> still open. ` +
      `<span style="opacity:.75">“No longer detected” means the rule stopped matching, which is weaker than “fixed correctly”.</span>`;
  } else {
    $("diff").hidden = true;
  }

  // Filters.
  const filters = $("filters");
  filters.innerHTML = "";
  const addChip = (key, text, n) => {
    const b = document.createElement("button");
    b.className = `chip${state.filter === key ? " is-on" : ""}`;
    b.innerHTML = `${esc(text)}<span class="n">${n}</span>`;
    b.addEventListener("click", () => {
      state.filter = key;
      renderResults();
    });
    filters.appendChild(b);
  };
  addChip("all", "All", r.findings.length);
  for (const s of SEV_ORDER) if (counts[s] > 0) addChip(s, s[0].toUpperCase() + s.slice(1), counts[s]);
  if (open.length !== r.findings.length) addChip("open", "Open only", open.length);

  // List.
  const list = $("finding-list");
  list.innerHTML = "";
  const visible = r.findings.filter((f) => {
    if (state.filter === "all") return true;
    if (state.filter === "open") return f.status === "open";
    return f.severity === state.filter;
  });

  if (visible.length === 0) {
    list.innerHTML = '<li style="cursor:default;color:var(--text-3)">Nothing matches this filter.</li>';
  }
  for (const f of visible) {
    const li = document.createElement("li");
    li.className = (state.selected === f.id ? "is-active " : "") + (f.status !== "open" ? "is-closed" : "");
    li.innerHTML =
      `<span class="sev sev-${f.severity}">${f.severity}</span>` +
      `<span><span class="f-title">${esc(f.title)}</span>` +
      `<span class="f-loc">${esc(f.location ? `${f.location.file}:${f.location.startLine}` : f.ruleId)}</span></span>`;
    li.addEventListener("click", () => {
      state.selected = f.id;
      renderResults();
    });
    list.appendChild(li);
  }

  renderDetail(r.findings.find((f) => f.id === state.selected) || visible[0] || null);
  renderCoverage(r);
}

function renderDetail(f) {
  const el = $("detail");
  if (!f) {
    el.innerHTML = '<div class="detail-empty">Select a finding to see the detail.</div>';
    return;
  }
  state.selected = f.id;

  const provLabel = {
    deterministic: "Deterministic rule",
    hybrid: "Rule + agent review",
    "llm-assisted": "Agent analysis",
  }[f.provenance];

  const tags = [
    `<span class="tag prov-${f.provenance}">${esc(provLabel)}</span>`,
    `<span class="tag">confidence: ${esc(f.confidence)}</span>`,
    `<span class="tag">${esc(f.ruleId)}</span>`,
    ...(f.mappings.cwe || []).map((x) => `<span class="tag">${esc(x)}</span>`),
    ...(f.mappings.owasp || []).map((x) => `<span class="tag">OWASP ${esc(x)}</span>`),
    ...(f.mappings.owaspLlm || []).map((x) => `<span class="tag">OWASP ${esc(x)}</span>`),
    ...(f.mappings.compliance || []).slice(0, 4).map((x) => `<span class="tag">${esc(x)}</span>`),
  ].join("");

  const block = (label, inner) => `<div class="block"><div class="block-label">${label}</div>${inner}</div>`;

  let html =
    `<h2><span class="sev sev-${f.severity}">${f.severity}</span> ${esc(f.title)}</h2>` +
    (f.location
      ? `<div class="f-loc" style="margin-bottom:.4rem">${esc(f.location.file)}:${f.location.startLine}</div>`
      : "") +
    `<div class="meta">${tags}</div>` +
    block("What is wrong", `<p>${esc(f.description)}</p>`) +
    block("What an attacker does with it", `<p>${esc(f.exploit)}</p>`);

  if (f.location && f.location.snippet) {
    html += block("Evidence", `<pre class="snippet">${esc(f.location.snippet)}</pre>`);
  }

  html += block(
    "How to fix it",
    `<p>${esc(f.remediation.summary)}</p><ol class="steps">${f.remediation.steps
      .map((s) => `<li>${esc(s)}</li>`)
      .join("")}</ol>`
  );

  if (f.remediation.outOfBandAction) {
    html += `<div class="block"><div class="callout"><strong>This needs an action outside the code.</strong> ${esc(
      f.remediation.outOfBandAction
    )}</div></div>`;
  }

  if (f.remediation.codeFix) {
    const cf = f.remediation.codeFix;
    if (cf.before) html += block("Before", `<pre class="fix">${esc(cf.before)}</pre>`);
    html += block(
      "After",
      `<div class="copy-row"><span></span><button class="btn-ghost copy-btn" data-copy="${esc(
        cf.after
      )}">Copy</button></div><pre class="fix">${esc(cf.after)}</pre>`
    );
  }

  if (f.agentReview) {
    const a = f.agentReview;
    html += `<div class="block"><div class="callout agent"><strong>${esc(a.agent)}</strong> reviewed this with ${esc(
      a.model
    )} and judged it <strong>${esc(a.verdict)}</strong>.<br>${esc(
      a.reasoning
    )}<br><em style="opacity:.8;font-size:.85em">Advisory only. The rule-based finding above stands regardless of this verdict.</em></div></div>`;
  }

  html +=
    `<div class="triage">` +
    ["open", "fixed", "false-positive", "suppressed"]
      .map(
        (s) =>
          `<button class="btn-ghost${f.status === s ? " is-on" : ""}" data-triage="${s}"${
            f.status === s ? ' style="border-color:var(--accent);color:var(--accent)"' : ""
          }>${s === "open" ? "Open" : s === "fixed" ? "Mark fixed" : s === "false-positive" ? "Not a real issue" : "Accept the risk"}</button>`
      )
      .join("") +
    `</div>`;

  el.innerHTML = html;

  el.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(b.dataset.copy);
        b.textContent = "Copied";
        setTimeout(() => (b.textContent = "Copy"), 1500);
      } catch {
        b.textContent = "Select the text above";
      }
    })
  );

  el.querySelectorAll("[data-triage]").forEach((b) =>
    b.addEventListener("click", async () => {
      const status = b.dataset.triage;
      try {
        await api("/api/triage", {
          method: "POST",
          body: JSON.stringify({
            findingId: f.id,
            targetId: state.result.target.id,
            status,
          }),
        });
        f.status = status;
        renderResults();
      } catch (err) {
        showError(err.message);
      }
    })
  );
}

function renderCoverage(r) {
  const cov = r.coverage;
  const skipRows = Object.entries(cov.skipReasons)
    .sort((a, b) => b[1] - a[1])
    .map(([reason, n]) => `<li>${esc(reason)}: ${n.toLocaleString()}</li>`)
    .join("");

  $("coverage").innerHTML =
    `<h3>What this scan actually covered</h3>` +
    `<div class="cov-grid">` +
    `<div class="cov-stat"><div class="n">${cov.filesScanned.toLocaleString()}</div><div class="l">files examined</div></div>` +
    `<div class="cov-stat"><div class="n">${cov.filesSkipped.toLocaleString()}</div><div class="l">files skipped</div></div>` +
    `<div class="cov-stat"><div class="n">${cov.scannersRun.length}</div><div class="l">checks run</div></div>` +
    `<div class="cov-stat"><div class="n">${(r.durationMs / 1000).toFixed(1)}s</div><div class="l">elapsed</div></div>` +
    `</div>` +
    (cov.scannersSkipped.length
      ? `<h3>Checks that did not run</h3><ul>${cov.scannersSkipped
          .map((s) => `<li><code>${esc(s.name)}</code> — ${esc(s.reason)}</li>`)
          .join("")}</ul>`
      : "") +
    (skipRows ? `<h3>Why files were skipped</h3><ul>${skipRows}</ul>` : "") +
    `<h3>What this scan did not cover</h3>` +
    `<ul>${cov.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` +
    (r.warnings.length
      ? `<h3>Warnings</h3><ul>${r.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`
      : "");
}

/* ---------------------------------------------------------------- checks */

async function renderChecks() {
  let data;
  try {
    data = await api("/api/rules");
  } catch {
    return;
  }
  $("checks-body").innerHTML = data.scanners
    .map(
      (s) =>
        `<h3>${esc(s.title)} <span class="tag">${esc(s.name)}</span></h3>` +
        `<p class="hint" style="margin-bottom:.6rem">${esc(s.description)}</p>` +
        `<table class="rule-table"><thead><tr><th>Rule</th><th>Severity</th><th>What it catches</th></tr></thead><tbody>` +
        s.rules
          .map(
            (r) =>
              `<tr><td class="id">${esc(r.id)}</td>` +
              `<td><span class="sev sev-${r.severity}">${r.severity}</span></td>` +
              `<td><strong style="color:var(--text);font-weight:500">${esc(r.title)}</strong><br>${esc(r.threat)}</td></tr>`
          )
          .join("") +
        `</tbody></table>`
    )
    .join("");
}

/* ---------------------------------------------------------------- agents */

function renderAgents() {
  const s = state.status;
  $("agents-body").innerHTML = s.agents.length
    ? s.agents
        .map(
          (a) =>
            `<div class="agent-card"><div class="n">${esc(a.emoji || "")} ${esc(a.name)}</div>` +
            `<div class="d">${esc(a.description)}</div></div>`
        )
        .join("")
    : `<p class="hint">No agent definitions found. Guardian-Unit-Penetration-Testing Agent looks in <code>~/.guardian-unit/agents</code> and in the <code>security/</code> folder of an agency-agents checkout.</p>`;

  $("provider-box").innerHTML =
    `<strong>Model</strong>` +
    `<p class="hint" style="margin:.3rem 0 0">${esc(s.provider.describe)}</p>` +
    `<p class="hint" style="color:${s.provider.ok ? "var(--ok)" : "var(--text-3)"}">${esc(s.provider.detail)}</p>` +
    `<div class="row">` +
    `<select id="prov-kind">` +
    ["none", "ollama", "anthropic", "openai"]
      .map(
        (k) =>
          `<option value="${k}"${s.provider.kind === k ? " selected" : ""}>${
            { none: "None (fully offline)", ollama: "Ollama (local, offline)", anthropic: "Anthropic (your key)", openai: "OpenAI (your key)" }[k]
          }</option>`
      )
      .join("") +
    `</select>` +
    `<input type="text" id="prov-model" placeholder="model name" value="${esc(s.provider.model || "")}" style="width:240px" />` +
    `<button class="btn-primary" id="prov-save">Save</button>` +
    `</div>` +
    `<p class="hint">Guardian-Unit-Penetration-Testing Agent never stores an API key. Keys are read from the environment at the moment of the call.</p>`;

  $("prov-save").addEventListener("click", async () => {
    try {
      const out = await api("/api/provider", {
        method: "POST",
        body: JSON.stringify({ kind: $("prov-kind").value, model: $("prov-model").value.trim() }),
      });
      updatePrivacy(out.privacy, $("prov-kind").value);
      await boot();
      showError(out.detail);
    } catch (err) {
      showError(err.message);
    }
  });
}

/* --------------------------------------------------------------- history */

function renderHistory() {
  const rows = state.status.history || [];
  $("history-body").innerHTML = rows.length
    ? `<table class="hist"><thead><tr><th>Folder</th><th>When</th><th>Critical</th><th>High</th><th>Total</th><th>Took</th></tr></thead><tbody>` +
      rows
        .map(
          (h) =>
            `<tr><td class="t">${esc(h.targetLabel)}</td>` +
            `<td>${esc(new Date(h.startedAt).toLocaleString())}</td>` +
            `<td>${h.critical}</td><td>${h.high}</td><td>${h.total}</td>` +
            `<td>${(h.durationMs / 1000).toFixed(1)}s</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    : `<p class="hint">No scans yet.</p>`;
}

/* --------------------------------------------------------------- browser */

$("browse").addEventListener("click", () => openBrowser($("path").value.trim() || state.status.home));
$("browser-close").addEventListener("click", () => ($("browser").hidden = true));
$("browser-pick").addEventListener("click", () => {
  $("path").value = state.browsePath;
  $("browser").hidden = true;
});

async function openBrowser(path) {
  $("browser").hidden = false;
  await loadDir(path);
}

async function loadDir(path) {
  let data;
  try {
    data = await api("/api/browse", { method: "POST", body: JSON.stringify({ path }) });
  } catch (err) {
    return showError(err.message);
  }
  state.browsePath = data.path;
  $("browser-path").textContent = data.path;
  const list = $("browser-list");
  list.innerHTML = "";

  if (data.parent) {
    const up = document.createElement("li");
    up.textContent = "↑ ..";
    up.addEventListener("click", () => loadDir(data.parent));
    list.appendChild(up);
  }
  for (const d of data.dirs) {
    const li = document.createElement("li");
    li.textContent = `📁 ${d.name}`;
    li.addEventListener("click", () => loadDir(d.path));
    list.appendChild(li);
  }
}

/* ----------------------------------------------------------------- misc */

$("export-btn").addEventListener("click", () => {
  $("export-menu").hidden = !$("export-menu").hidden;
});
document.addEventListener("click", (e) => {
  if (!e.target.closest(".menu")) $("export-menu").hidden = true;
});

boot();
