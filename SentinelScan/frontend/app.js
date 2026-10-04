const TOKEN_KEY = 'sentinel.token';

function getToken() {
  let token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    token = window.prompt('Enter SentinelScan bearer token:');
    if (token) localStorage.setItem(TOKEN_KEY, token.trim());
  }
  return token ? token.trim() : '';
}

async function api(path, opts = {}) {
  const token = getToken();
  const headers = new Headers(opts.headers || {});
  headers.set('Accept', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...opts, headers });
  const type = response.headers.get('content-type') || '';
  if (!response.ok) {
    const message = type.includes('application/json') ? JSON.stringify(await response.json()) : await response.text();
    throw new Error(`${response.status}: ${message}`);
  }
  return type.includes('application/json') ? response.json() : response.text();
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function render(d) {
  const root = document.getElementById('results') || document.getElementById('findings') || document.body;
  root.replaceChildren();
  const results = Array.isArray(d?.findings) ? d.findings : Array.isArray(d?.controls) ? d.controls : [];
  const fragment = document.createDocumentFragment();
  const heading = document.createElement('h2');
  heading.textContent = 'Security Results';
  fragment.appendChild(heading);
  if (!results.length) {
    const empty = document.createElement('p');
    empty.textContent = 'No findings available.';
    fragment.appendChild(empty);
  }
  for (const item of results) {
    const card = document.createElement('article');
    const title = document.createElement('h3');
    title.textContent = item.title || item.name || item.id || 'Security Control';
    const status = document.createElement('p');
    status.textContent = `Status: ${item.status || item.result || 'UNKNOWN'}`;
    const severity = document.createElement('p');
    severity.textContent = `Severity: ${item.severity || 'N/A'}`;
    const description = document.createElement('p');
    description.textContent = item.description || item.message || '';
    card.append(title, status, severity, description);
    if (item.evidence_hash) {
      const evidence = document.createElement('small');
      evidence.textContent = `Evidence SHA-256: ${item.evidence_hash}`;
      card.appendChild(evidence);
    }
    fragment.appendChild(card);
  }
  root.appendChild(fragment);
}

async function scan() {
  try {
    const targetInput = document.getElementById('target');
    const target = targetInput ? targetInput.value.trim() : '';
    const data = await api('/api/check', { method: 'POST', body: JSON.stringify({ target }) });
    render(data);
    await loadAll();
  } catch (error) {
    console.error(error);
    alert(`Scan failed: ${error.message}`);
  }
}

async function loadAll() {
  try {
    const [state, history, anchor] = await Promise.all([
      api('/api/state'), api('/api/history'), api('/api/audit/anchor')
    ]);
    render(state);
    const historyEl = document.getElementById('history');
    if (historyEl) {
      historyEl.replaceChildren();
      const heading = document.createElement('h3');
      heading.textContent = 'Scan History';
      historyEl.appendChild(heading);
      const entries = Array.isArray(history) ? history : Array.isArray(history?.runs) ? history.runs : [];
      for (const entry of entries) {
        const row = document.createElement('div');
        row.textContent = `${entry.timestamp || entry.created_at || ''} — ${entry.status || 'RUN'}`;
        historyEl.appendChild(row);
      }
    }
    const anchorEl = document.getElementById('auditAnchor');
    if (anchorEl) anchorEl.textContent = anchor?.digest || anchor?.sha256 || anchor?.anchor || 'No audit anchor available';
  } catch (error) {
    console.error(error);
  }
}

async function lab(action) {
  try {
    const data = await api(`/api/lab/${action}`, { method: 'POST', body: JSON.stringify({}) });
    render(data);
    await loadAll();
  } catch (error) {
    console.error(error);
    alert(`Lab action failed: ${error.message}`);
  }
}

document.getElementById('scanBtn')?.addEventListener('click', scan);
document.getElementById('refreshBtn')?.addEventListener('click', loadAll);
document.getElementById('reportBtn')?.addEventListener('click', () => window.open('/api/report', '_blank', 'noopener'));
document.getElementById('labRetestBtn')?.addEventListener('click', () => lab('retest'));
document.getElementById('labFixBtn')?.addEventListener('click', () => lab('fix'));
document.getElementById('labRegressionBtn')?.addEventListener('click', () => lab('regression'));

loadAll();
