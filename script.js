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
const installButton = document.getElementById('install-app');
let dashboardTotals = { total: 0, safe: 0, suspicious: 0, highRisk: 0 };
let installPrompt;

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
  const reputationChecks = result.reputationChecks.map((check) => `
    <li class="reputation-check ${check.status}">
      <strong>${check.status === 'flagged' ? 'Flag' : 'Checked'}: ${escapeHtml(check.label)}</strong>
      <span>${escapeHtml(check.detail)}</span>
    </li>
  `).join('');
  document.getElementById('url-result').innerHTML = `
    <div class="result-grid">
      <div class="score-row">
        <h3>URL Risk Score: ${result.score}/100</h3>
        <span class="score-badge ${getRiskClass(result.score)}">${escapeHtml(result.riskLevel)}</span>
      </div>
      ${result.domain ? `<div><h4>Domain:</h4><p>${escapeHtml(result.domain)}</p></div>` : ''}
      <div><h4>Threat Type:</h4><p>${escapeHtml(result.threatType)}</p></div>
      <div><h4>Threat Level:</h4><p>${escapeHtml(result.status)}</p></div>
      <div>
        <h4>Reputation signals (local checks):</h4>
        <ul class="reputation-list">${reputationChecks || '<li>No additional checks were available for this input.</li>'}</ul>
        <p class="reputation-note">${escapeHtml(result.reputationSource)}</p>
      </div>
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

function setupInstallPrompt() {
  const isAppleMobileDevice = /iPhone|iPad|iPod/.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    installPrompt = event;
    installButton.hidden = false;
  });

  if (isAppleMobileDevice) {
    installButton.textContent = 'Add to Home Screen';
    installButton.hidden = false;
  }

  window.addEventListener('appinstalled', () => {
    installPrompt = null;
    installButton.hidden = true;
    statusPill.textContent = 'App installed';
  });

  installButton.addEventListener('click', async () => {
    if (!installPrompt) {
      if (isAppleMobileDevice) window.alert('In Safari, tap Share, then choose “Add to Home Screen”.');
      return;
    }
    installButton.disabled = true;
    try {
      await installPrompt.prompt();
      const { outcome } = await installPrompt.userChoice;
      if (outcome === 'accepted') installButton.hidden = true;
      installPrompt = null;
    } finally {
      installButton.disabled = false;
    }
  });
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/service-worker.js').catch((error) => {
    console.error('ScamShield offline support could not be enabled:', error);
  });
}

function setupDashboardNavigation() {
  const navigationItems = [...document.querySelectorAll('.nav-item')];
  const sections = navigationItems
    .map((item) => document.getElementById(item.dataset.section))
    .filter(Boolean);

  function setActiveNavigation(item) {
    navigationItems.forEach((navigationItem) => {
      const isActive = navigationItem === item;
      navigationItem.classList.toggle('is-active', isActive);
      if (isActive) navigationItem.setAttribute('aria-current', 'location');
      else navigationItem.removeAttribute('aria-current');
    });
  }

  function updateActiveNavigation() {
    const threshold = window.innerHeight * 0.45;
    const visibleSections = sections
      .map((section) => ({ section, top: section.getBoundingClientRect().top }))
      .filter(({ top }) => top <= threshold);
    if (!visibleSections.length) return;

    const latestTop = Math.max(...visibleSections.map(({ top }) => top));
    const currentItem = navigationItems.find((item) => item.classList.contains('is-active'));
    const latestSections = visibleSections
      .filter(({ top }) => Math.abs(top - latestTop) < 1)
      .map(({ section }) => section);
    const activeSection = latestSections.find((section) => section.id === currentItem?.dataset.section)
      || latestSections[latestSections.length - 1];
    const activeItem = navigationItems.find((item) => item.dataset.section === activeSection.id);
    if (activeItem) setActiveNavigation(activeItem);
  }

  navigationItems.forEach((item) => {
    item.addEventListener('click', () => setActiveNavigation(item));
  });
  window.addEventListener('scroll', updateActiveNavigation, { passive: true });
  window.addEventListener('resize', updateActiveNavigation);
  updateActiveNavigation();
}

function init() {
  setupInstallPrompt();
  registerServiceWorker();
  setupDashboardNavigation();
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
