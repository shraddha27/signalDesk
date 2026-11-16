const PAGE_SIZE = 50;
let currentOffset = 0;
let currentTotal = 0;
let searchTimer;
let refreshTimer;
let toastTimer;
let selectedAccountId = null;

const elements = {
  total: document.querySelector("#total-accounts"),
  highPriority: document.querySelector("#high-priority"),
  average: document.querySelector("#average-score"),
  active: document.querySelector("#active-ingestions"),
  industries: document.querySelector("#industry-filter"),
  search: document.querySelector("#search-input"),
  tier: document.querySelector("#tier-filter"),
  rows: document.querySelector("#account-rows"),
  empty: document.querySelector("#empty-state"),
  count: document.querySelector("#result-count"),
  pageLabel: document.querySelector("#page-label"),
  previous: document.querySelector("#previous-page"),
  next: document.querySelector("#next-page"),
  detail: document.querySelector("#account-detail"),
  ingestions: document.querySelector("#ingestion-list"),
  toast: document.querySelector("#toast"),
  uploadButton: document.querySelector("#upload-button"),
  demoNotice: document.querySelector("#demo-notice"),
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      // Keep the HTTP status as a useful fallback when the server sends no JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

function showToast(message, isError = false, duration = 3800) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", isError);
  elements.toast.classList.add("visible");
  if (duration > 0) {
    toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), duration);
  }
}

function uploadFile(file, body) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", "/api/ingestions");
    request.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      if (event.loaded >= event.total) {
        showToast(`Upload sent; preparing ${file.name}…`, false, 0);
        return;
      }
      const progress = Math.floor((event.loaded / event.total) * 100);
      showToast(`Uploading ${file.name}… ${progress}%`, false, 0);
    });
    request.addEventListener("load", () => {
      let response = null;
      try {
        response = JSON.parse(request.responseText);
      } catch {
        // The HTTP status remains useful when the server does not return JSON.
      }
      if (request.status < 200 || request.status >= 300) {
        reject(new Error((response && response.detail) || `Upload failed (${request.status})`));
        return;
      }
      resolve(response);
    });
    request.addEventListener("error", () => {
      reject(new Error("Upload failed. Check your connection and try again."));
    });
    request.addEventListener("abort", () => {
      reject(new Error("Upload was cancelled."));
    });
    request.send(body);
  });
}

async function loadOverview() {
  const data = await api("/api/overview");
  elements.total.textContent = data.total_accounts.toLocaleString();
  elements.highPriority.textContent = data.high_priority_accounts.toLocaleString();
  elements.average.textContent = data.average_score;
  elements.active.textContent = data.active_ingestions.toLocaleString();

  const selectedIndustry = elements.industries.value;
  elements.industries.innerHTML = '<option value="">All industries</option>';
  data.industries.forEach((industry) => {
    const option = document.createElement("option");
    option.value = industry;
    option.textContent = industry;
    option.selected = industry === selectedIndustry;
    elements.industries.append(option);
  });
  return data.active_ingestions;
}

async function loadAppConfig() {
  const config = await api("/api/config");
  elements.uploadButton.hidden = !config.uploads_enabled;
  elements.demoNotice.hidden = !config.demo_mode;
}

function renderAccounts(accounts) {
  elements.rows.innerHTML = accounts.map((account) => {
    const signal = account.signals[0];
    const tier = escapeHtml(account.tier);
    const initials = escapeHtml((account.name || "?").trim().slice(0, 2));
    const selected = account.id === selectedAccountId ? " selected" : "";
    return `<tr tabindex="0" data-id="${account.id}" class="${selected}">
      <td><div class="account-name"><span class="company-logo">${initials}</span><span>${escapeHtml(account.name)}<span class="domain-line">${escapeHtml(account.domain || "Domain not provided")}</span></span></div></td>
      <td>${escapeHtml(account.industry || "—")}</td>
      <td>${escapeHtml(account.country || "—")}</td>
      <td>${account.employee_count == null ? "—" : Number(account.employee_count).toLocaleString()}</td>
      <td class="signal-label">${signal ? escapeHtml(signal.title) : "No matched signal"}</td>
      <td class="score-cell"><span class="priority ${tier}">${tier} · ${account.score}</span><div class="score-track"><div class="score-fill" style="width:${Math.min(100, Math.max(0, account.score))}%"></div></div></td>
    </tr>`;
  }).join("");

  const hasResults = accounts.length > 0;
  elements.empty.style.display = hasResults ? "none" : "flex";
  document.querySelector("table").style.display = hasResults ? "table" : "none";
  if (selectedAccountId && !accounts.some((account) => account.id === selectedAccountId)) {
    selectedAccountId = null;
    renderDetail(null);
  }
}

async function loadAccounts() {
  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(currentOffset),
    sort: "score",
  });
  if (elements.search.value.trim()) params.set("q", elements.search.value.trim());
  if (elements.industries.value) params.set("industry", elements.industries.value);
  if (elements.tier.value) params.set("tier", elements.tier.value);

  const data = await api(`/api/accounts?${params}`);
  currentTotal = data.total;
  elements.count.textContent = currentTotal.toLocaleString();
  renderAccounts(data.items);
  const start = currentTotal === 0 ? 0 : currentOffset + 1;
  const end = Math.min(currentOffset + data.items.length, currentTotal);
  elements.pageLabel.textContent = `Showing ${start}–${end} of ${currentTotal.toLocaleString()} accounts`;
  elements.previous.disabled = currentOffset === 0;
  elements.next.disabled = currentOffset + PAGE_SIZE >= currentTotal;
}

function renderDetail(account) {
  if (!account) {
    elements.detail.className = "detail-placeholder";
    elements.detail.innerHTML = '<span class="detail-target">◎</span><p>Select an account to see what drove its score.</p>';
    return;
  }
  const signals = account.signals.length
    ? `<div class="signal-list">${account.signals.map((signal) => `
        <div class="signal-item ${escapeHtml(signal.category)}">
          <div class="signal-title"><span>${escapeHtml(signal.title)}</span><span class="signal-points">+${signal.points}</span></div>
          <div class="signal-evidence">${escapeHtml(signal.evidence)}</div>
        </div>`).join("")}</div>`
    : '<p class="signal-evidence">No matching risk or fit signals were found in the supplied fields.</p>';
  elements.detail.className = "detail-content";
  elements.detail.innerHTML = `
    <div class="detail-account">
      <div><h3>${escapeHtml(account.name)}</h3><p>${escapeHtml(account.domain || "Domain not provided")}</p></div>
      <div class="detail-score">${account.score}<span> / 100</span></div>
    </div>
    ${signals}
    <details class="raw-data"><summary>View source fields</summary><pre>${escapeHtml(JSON.stringify(account.attributes, null, 2))}</pre></details>`;
}

async function selectAccount(id, row) {
  try {
    const account = await api(`/api/accounts/${id}`);
    selectedAccountId = account.id;
    document.querySelectorAll("#account-rows tr").forEach((item) => item.classList.remove("selected"));
    row.classList.add("selected");
    renderDetail(account);
  } catch (error) {
    showToast(error.message, true);
  }
}

async function loadIngestions() {
  const data = await api("/api/ingestions?limit=8");
  if (!data.items.length) {
    elements.ingestions.innerHTML = '<p class="detail-placeholder">No imports yet.</p>';
    return;
  }
  elements.ingestions.innerHTML = data.items.map((job) => {
    const when = job.created_at ? new Date(job.created_at).toLocaleString() : "";
    const issues = job.rows_skipped ? ` · ${job.rows_skipped} skipped` : "";
    const errorMessage = job.error ? job.error.split(/\r?\n/, 1)[0] : "";
    const errorPreview = errorMessage.slice(0, 240);
    const error = errorMessage
      ? `<br>${escapeHtml(errorPreview)}${errorMessage.length > errorPreview.length ? "…" : ""}`
      : "";
    return `<div class="ingestion-item">
      <span class="ingestion-name" title="${escapeHtml(job.filename)}">${escapeHtml(job.filename)}</span>
      <span class="job-status ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span>
      <span class="job-meta">${job.rows_processed.toLocaleString()} rows · ${escapeHtml(when)}${escapeHtml(issues)}${error}</span>
    </div>`;
  }).join("");
}

async function refreshDashboard() {
  try {
    const [, activeIngestions] = await Promise.all([
      loadAppConfig(),
      loadOverview(),
      loadAccounts(),
      loadIngestions(),
    ]);
    window.clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(
      refreshDashboard,
      activeIngestions > 0 ? 15000 : 10000,
    );
  } catch (error) {
    showToast(error.message, true);
    window.clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(refreshDashboard, 10000);
  }
}

document.querySelector("#file-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const body = new FormData();
  body.append("file", file);
  showToast(`Starting upload of ${file.name}…`, false, 0);
  try {
    const job = await uploadFile(file, body);
    showToast(`Import queued: ${job.filename}`);
    await refreshDashboard();
  } catch (error) {
    showToast(error.message, true);
  } finally {
    event.target.value = "";
  }
});

elements.rows.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-id]");
  if (row) selectAccount(Number(row.dataset.id), row);
});
elements.rows.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("tr[data-id]");
  if (row) {
    event.preventDefault();
    selectAccount(Number(row.dataset.id), row);
  }
});
elements.search.addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => {
    currentOffset = 0;
    loadAccounts().catch((error) => showToast(error.message, true));
  }, 250);
});
elements.industries.addEventListener("change", () => {
  currentOffset = 0;
  loadAccounts().catch((error) => showToast(error.message, true));
});
elements.tier.addEventListener("change", () => {
  currentOffset = 0;
  loadAccounts().catch((error) => showToast(error.message, true));
});
elements.previous.addEventListener("click", () => {
  currentOffset = Math.max(0, currentOffset - PAGE_SIZE);
  loadAccounts().catch((error) => showToast(error.message, true));
});
elements.next.addEventListener("click", () => {
  currentOffset += PAGE_SIZE;
  loadAccounts().catch((error) => showToast(error.message, true));
});
document.querySelector("#refresh-button").addEventListener("click", refreshDashboard);

refreshDashboard();
