const apiBaseUrl = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');
const clientIdKey = 'scamshield-client-id';
const sampleMessages = [
  {
    title: 'Prize scam',
    text: 'Congratulations! You have won ₹50,000. Click here immediately and enter your bank details and OTP.'
  },
  {
    title: 'Bank alert',
    text: 'Your bank KYC has expired. Update now to prevent your account from being blocked.'
  },
  {
    title: 'Delivery scam',
    text: 'Your parcel is waiting. Pay ₹25 delivery charges using this link.'
  },
  {
    title: 'Job scam',
    text: 'Congratulations! You have been selected for a work-from-home job. Pay ₹999 registration fee.'
  }
];

const sampleList = document.getElementById('sample-list');
const messageInput = document.getElementById('message-input');
const urlInput = document.getElementById('url-input');
const historyList = document.getElementById('history-list');
const statusPill = document.querySelector('.status-pill');
let dashboardTotals = { total: 0, safe: 0, suspicious: 0, highRisk: 0 };

function getClientId() {
  let clientId = localStorage.getItem(clientIdKey);
  if (!clientId) {
    clientId = crypto.randomUUID();
    localStorage.setItem(clientIdKey, clientId);
  }
  return clientId;
}

const clientId = getClientId();

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function getRiskClass(score) {
  if (score >= 70) return 'danger';
  if (score >= 35) return 'warning';
  return 'safe';
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${apiBaseUrl}/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': clientId,
      ...options.headers
    }
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error || `API request failed (${response.status}).`);
  }

  return response.status === 204 ? null : response.json();
}

function showError(container, error) {
  container.innerHTML = `<p class="error-state">${escapeHtml(error.message)}</p>`;
}

function renderMessageResult(result) {
  const warnings = result.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('');
  document.getElementById('message-result').innerHTML = `
    <div class="result-grid">
      <div class="score-row">
        <h3>Risk Score: ${result.score}/100</h3>
        <span class="score-badge ${getRiskClass(result.score)}">${escapeHtml(result.riskLevel)}</span>
      </div>
      <div><h4>Threat Type:</h4><p>${escapeHtml(result.threatType)}</p></div>
      <div><h4>Detected warning signs:</h4><ul class="indicator-list">${warnings}</ul></div>
      <div><h4>Explanation:</h4><p>${escapeHtml(result.explanation)}</p></div>
      <div><h4>Recommended action:</h4><p>${escapeHtml(result.recommendation)}</p></div>
    </div>
  `;
}

function renderUrlResult(result) {
  const indicators = result.indicators.map((indicator) => `<li>${escapeHtml(indicator)}</li>`).join('');
  document.getElementById('url-result').innerHTML = `
    <div class="result-grid">
      <div class="score-row">
        <h3>URL Risk Score: ${result.score}/100</h3>
        <span class="score-badge ${getRiskClass(result.score)}">${escapeHtml(result.riskLevel)}</span>
      </div>
      <div><h4>Threat Type:</h4><p>${escapeHtml(result.threatType)}</p></div>
      <div><h4>Threat Level:</h4><p>${escapeHtml(result.status)}</p></div>
      <div><h4>Detected indicators:</h4><ul class="indicator-list">${indicators}</ul></div>
      <div><h4>Safety recommendation:</h4><p>${escapeHtml(result.recommendation)}</p></div>
    </div>
  `;
}

function updateDashboard(totals = dashboardTotals) {
  dashboardTotals = totals;
  document.getElementById('total-scans').textContent = totals.total;
  document.getElementById('high-risk-count').textContent = totals.highRisk;
  document.getElementById('suspicious-count').textContent = totals.suspicious;
  document.getElementById('safe-count').textContent = totals.safe;

  const total = totals.total || 0;
  document.getElementById('safe-bar').style.width = `${total ? (totals.safe / total) * 100 : 0}%`;
  document.getElementById('suspicious-bar').style.width = `${total ? (totals.suspicious / total) * 100 : 0}%`;
  document.getElementById('danger-bar').style.width = `${total ? (totals.highRisk / total) * 100 : 0}%`;
}

function renderHistory(items) {
  if (!items.length) {
    historyList.innerHTML = '<p class="empty-history">No scans yet.</p>';
    return;
  }

  historyList.innerHTML = items.map((item) => `
    <div class="history-item">
      <div class="top-line">
        <span>${escapeHtml(item.inputType)}</span>
        <span>${escapeHtml(new Date(item.createdAt).toLocaleString())}</span>
      </div>
      <strong>${item.riskScore}/100</strong>
      <div class="top-line">
        <span>${escapeHtml(item.threatType)}</span>
        <span>${escapeHtml(item.riskLevel)}</span>
      </div>
    </div>
  `).join('');
}

async function refreshHistory() {
  const { scans, totals } = await apiRequest('/history');
  renderHistory(scans);
  updateDashboard(totals);
  statusPill.textContent = 'API Connected';
}

async function runScan(path, payload, render) {
  const resultContainer = document.getElementById(path.endsWith('message') ? 'message-result' : 'url-result');
  try {
    const result = await apiRequest(path, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    render(result);
    try {
      await refreshHistory();
    } catch (error) {
      showError(historyList, error);
      statusPill.textContent = 'History unavailable';
    }
    return result;
  } catch (error) {
    showError(resultContainer, error);
    statusPill.textContent = 'API unavailable';
    return null;
  }
}

async function handleAnalyzeMessage() {
  const text = messageInput.value.trim();
  if (!text) {
    showError(document.getElementById('message-result'), new Error('Enter a message before scanning.'));
    return;
  }
  await runScan('/analyze/message', { message: text }, renderMessageResult);
}

async function handleAnalyzeUrl() {
  const url = urlInput.value.trim();
  if (!url) {
    showError(document.getElementById('url-result'), new Error('Enter a URL before scanning.'));
    return;
  }
  await runScan('/analyze/url', { url }, renderUrlResult);
}

function renderSampleCards() {
  sampleList.innerHTML = sampleMessages.map((sample, index) => `
    <button class="sample-card" data-sample-index="${index}">${escapeHtml(sample.title)}</button>
  `).join('');

  sampleList.querySelectorAll('.sample-card').forEach((button) => {
    button.addEventListener('click', () => {
      messageInput.value = sampleMessages[Number(button.dataset.sampleIndex)].text;
      handleAnalyzeMessage();
    });
  });
}

async function handleExplainSimply() {
  const message = messageInput.value.trim();
  if (!message) {
    showError(document.getElementById('message-result'), new Error('Enter a message before asking for a simple explanation.'));
    return;
  }

  const result = await runScan('/analyze/message', { message }, () => {});
  if (!result) return;
  document.getElementById('message-result').innerHTML = `
    <div class="result-grid">
      <div class="score-row">
        <h3>Simple Explanation</h3>
        <span class="score-badge ${getRiskClass(result.score)}">${escapeHtml(result.riskLevel)}</span>
      </div>
      <p>${escapeHtml(result.simplified)}</p>
      <p><strong>Why:</strong> ${escapeHtml(result.explanation)}</p>
      <p><strong>Recommended action:</strong> ${escapeHtml(result.recommendation)}</p>
    </div>
  `;
}

async function clearHistory() {
  try {
    await apiRequest('/history', { method: 'DELETE' });
    renderHistory([]);
    updateDashboard({ total: 0, safe: 0, suspicious: 0, highRisk: 0 });
    statusPill.textContent = 'API Connected';
  } catch (error) {
    showError(historyList, error);
    statusPill.textContent = 'API unavailable';
  }
}

function setBusy(button, action) {
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    button.disabled = true;
    try {
      await action();
    } finally {
      button.disabled = false;
    }
  });
}

function init() {
  renderSampleCards();
  setBusy(document.getElementById('analyze-message'), handleAnalyzeMessage);
  setBusy(document.getElementById('analyze-url'), handleAnalyzeUrl);
  setBusy(document.getElementById('explain-message'), handleExplainSimply);
  setBusy(document.getElementById('clear-history'), clearHistory);

  refreshHistory().catch((error) => {
    showError(historyList, error);
    statusPill.textContent = 'API unavailable';
  });
}

init();
