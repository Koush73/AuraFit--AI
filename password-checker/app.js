/* ═══════════════════════════════════════════
   SecureGuard – Password Strength Analyzer
   app.js – API-driven frontend (Flask + SQLite backend)
   API base: http://localhost:5000/api
═══════════════════════════════════════════ */

'use strict';

/* ── CONFIG ── */
const API_BASE = '/api';

/* ── SCORE GRADES (mirrors server analyzer.py) ── */
const SCORE_GRADES = [
  { min: 9.5, cls: 'vstrong', label: 'Very Strong' },
  { min: 8,   cls: 'strong',  label: 'Strong'      },
  { min: 6,   cls: 'good',    label: 'Good'         },
  { min: 4,   cls: 'fair',    label: 'Fair'         },
  { min: 0,   cls: 'weak',    label: 'Weak'         },
];

const RING_CIRCUMFERENCE = 2 * Math.PI * 80;

/* ── STATE ── */
let currentAccount   = null;   // { id, username, created_at }
let historyData      = [];     // fetched from API
let currentAnalysis  = null;   // last analysis from API (not yet saved)
let isPasswordVisible = false;

/* ── DOM REFS ── */
const $ = id => document.getElementById(id);

const accountModal   = $('account-modal');
const usernameInput  = $('username-input');
const startBtn       = $('start-btn');
const accountAvatar  = $('account-avatar');
const accountDisplay = $('account-display-name');

const passwordInput  = $('password-input');
const toggleVis      = $('toggle-vis');
const checkBtn       = $('check-btn');
const saveBtn        = $('save-btn');
const exportBtn      = $('export-btn');
const exportBtn2     = $('export-btn-2');

const strengthSegs   = document.querySelectorAll('.seg');
const strengthLabel  = $('strength-label');

const scoreNumber    = $('score-number');
const scoreGrade     = $('score-grade');
const ringFill       = $('ring-fill');

const historyTbody      = $('history-tbody');
const fullHistoryTbody  = $('full-history-tbody');
const historyCount      = $('history-count');
const emptyRow          = $('empty-row');
const fullEmptyRow      = $('full-empty-row');
const historyAccName    = $('history-account-name');

const statTotal  = $('stat-total');
const statAvg    = $('stat-avg');
const statBest   = $('stat-best');
const statWeak   = $('stat-weak');

const toast = $('toast');

/* Criteria nodes */
const criteria = {
  length:   $('c-length'),
  upper:    $('c-upper'),
  lower:    $('c-lower'),
  number:   $('c-number'),
  special:  $('c-special'),
  length2:  $('c-length2'),
  norepeat: $('c-norepeat'),
  nocommon: $('c-nocommon'),
};

/* Breakdown bar nodes */
const bdLength  = $('bd-length');
const bdComplex = $('bd-complex');
const bdUnique  = $('bd-unique');
const bdEntropy = $('bd-entropy');
const bdvLength = $('bdv-length');
const bdvComplex= $('bdv-complex');
const bdvUnique = $('bdv-unique');
const bdvEntropy= $('bdv-entropy');

/* ── API HELPERS ── */
async function apiPost(endpoint, body) {
  const res = await fetch(API_BASE + endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  return res.json();
}

async function apiGet(endpoint) {
  const res = await fetch(API_BASE + endpoint);
  return res.json();
}

async function apiDelete(endpoint, body) {
  const res = await fetch(API_BASE + endpoint, {
    method:  'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  return res.json();
}

/* ── LOADING STATE ── */
function setLoading(btn, loading) {
  if (loading) {
    btn.dataset.orig = btn.textContent;
    btn.textContent  = 'Loading…';
    btn.disabled     = true;
  } else {
    btn.textContent = btn.dataset.orig || btn.textContent;
    btn.disabled    = false;
  }
}

/* ── GRADE HELPER ── */
function gradeFromScore(score) {
  for (const g of SCORE_GRADES) if (score >= g.min) return g;
  return SCORE_GRADES[SCORE_GRADES.length - 1];
}

/* ── MASK HELPER ── */
function maskPassword(pwd) {
  if (!pwd || pwd.length === 0) return '';
  if (pwd.length <= 3) return '●'.repeat(pwd.length);
  return pwd[0] + '●'.repeat(pwd.length - 2) + pwd[pwd.length - 1];
}

/* ── UI UPDATERS ── */
function updateStrengthBar(score) {
  const filled = Math.round(score);
  strengthSegs.forEach((seg, i) => {
    seg.className = 'seg';
    if (i < filled) seg.classList.add(`filled-${filled}`);
  });
}

function updateStrengthLabel(grade) {
  strengthLabel.textContent = grade.label;
  const colorMap = {
    weak:'--col-weak', fair:'--col-fair', good:'--col-good',
    strong:'--col-strong', vstrong:'--col-vstrong'
  };
  strengthLabel.style.color = getComputedStyle(document.documentElement)
    .getPropertyValue(colorMap[grade.cls] || '--text-2').trim();
}

function updateRing(score) {
  const pct    = score / 10;
  const offset = RING_CIRCUMFERENCE * (1 - pct);
  ringFill.style.strokeDashoffset = offset;

  // Inject SVG gradient once
  if (!document.getElementById('ringGrad')) {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg   = document.querySelector('.score-ring');
    const defs  = document.createElementNS(svgNS, 'defs');
    const grad  = document.createElementNS(svgNS, 'linearGradient');
    grad.setAttribute('id', 'ringGrad');
    grad.setAttribute('gradientUnits', 'userSpaceOnUse');
    grad.setAttribute('x1','0'); grad.setAttribute('y1','0');
    grad.setAttribute('x2','200'); grad.setAttribute('y2','200');
    const s1 = document.createElementNS(svgNS,'stop'); s1.setAttribute('stop-color','#7c3aed');
    const s2 = document.createElementNS(svgNS,'stop'); s2.setAttribute('offset','1'); s2.setAttribute('stop-color','#06b6d4');
    grad.appendChild(s1); grad.appendChild(s2);
    defs.appendChild(grad); svg.prepend(defs);
  }
}

function updateScoreDisplay(analysis) {
  const { score, score_length, score_complexity, score_uniqueness, score_entropy } = analysis;
  const grade = gradeFromScore(score);

  scoreNumber.textContent = score;
  scoreGrade.textContent  = grade.label;

  const colorMap = { weak:'--col-weak', fair:'--col-fair', good:'--col-good', strong:'--col-strong', vstrong:'--col-vstrong' };
  scoreGrade.style.color = getComputedStyle(document.documentElement)
    .getPropertyValue(colorMap[grade.cls] || '--text-2').trim();

  updateStrengthBar(score);
  updateStrengthLabel(grade);
  updateRing(score);

  [
    [bdLength,  bdvLength,  score_length     ],
    [bdComplex, bdvComplex, score_complexity ],
    [bdUnique,  bdvUnique,  score_uniqueness ],
    [bdEntropy, bdvEntropy, score_entropy    ],
  ].forEach(([bar, val, pct]) => {
    bar.style.width  = pct + '%';
    val.textContent  = pct + '%';
  });
}

function updateCriteria(analysis) {
  const { length, has_upper, has_lower, has_number, has_special, no_repeat, is_common } = analysis;
  setCriterion('length',   length >= 8);
  setCriterion('upper',    has_upper);
  setCriterion('lower',    has_lower);
  setCriterion('number',   has_number);
  setCriterion('special',  has_special);
  setCriterion('length2',  length >= 16);
  setCriterion('norepeat', no_repeat);
  setCriterion('nocommon', !is_common);
}

function setCriterion(key, pass) {
  criteria[key].classList.toggle('pass', pass);
  criteria[key].classList.toggle('fail', !pass);
}

function resetUI() {
  strengthSegs.forEach(s => { s.className = 'seg'; });
  strengthLabel.textContent = '—';
  scoreNumber.textContent   = '—';
  scoreGrade.textContent    = 'No data';
  scoreGrade.style.color    = '';
  ringFill.style.strokeDashoffset = RING_CIRCUMFERENCE;
  Object.values(criteria).forEach(c => { c.classList.remove('pass','fail'); });
  [bdLength, bdComplex, bdUnique, bdEntropy].forEach(b => b.style.width = '0');
  [bdvLength, bdvComplex, bdvUnique, bdvEntropy].forEach(v => v.textContent = '—');
  saveBtn.disabled = true;
  currentAnalysis  = null;
}

/* ── HISTORY RENDERING ── */
function renderHistory() {
  const count = historyData.length;
  historyCount.textContent = `${count} entr${count === 1 ? 'y' : 'ies'}`;

  emptyRow.style.display     = count === 0 ? '' : 'none';
  fullEmptyRow.style.display = count === 0 ? '' : 'none';

  document.querySelectorAll('.hist-row').forEach(r => r.remove());
  document.querySelectorAll('.full-hist-row').forEach(r => r.remove());

  historyData.forEach((entry, idx) => {
    const num    = idx + 1;
    const grade  = gradeFromScore(entry.score);
    const masked = maskPassword(entry.password);
    const ts     = formatTimestamp(entry.created_at);

    // ── MINI TABLE ──
    const tr = document.createElement('tr');
    tr.className   = 'hist-row';
    tr.dataset.entryId = entry.id;
    tr.innerHTML = `
      <td>${num}</td>
      <td style="color:var(--text-2);font-size:.8rem">${ts}</td>
      <td><span class="password-mono" id="mini-pwd-${entry.id}">${masked}</span></td>
      <td><span class="score-badge ${grade.cls}">${entry.score}</span></td>
      <td><span class="grade-pill ${grade.cls}">${grade.label}</span></td>
      <td style="display:flex;gap:6px">
        <button class="btn-icon reveal" aria-label="Reveal password"
          onclick="revealPassword(this,'mini-pwd-${entry.id}','${masked.replace(/'/g,"\\'")}','${entry.password.replace(/'/g,"\\'")}')">👁 Reveal</button>
        <button class="btn-icon" aria-label="Delete entry"
          onclick="deleteEntry(${entry.id})">✕</button>
      </td>`;
    historyTbody.appendChild(tr);

    // ── FULL TABLE ──
    const trF = document.createElement('tr');
    trF.className   = 'full-hist-row';
    trF.dataset.entryId = entry.id;
    trF.innerHTML = `
      <td>${num}</td>
      <td style="color:var(--text-2);font-size:.8rem">${ts}</td>
      <td><span class="password-mono" id="full-pwd-${entry.id}">${masked}</span></td>
      <td><span class="score-badge ${grade.cls}">${entry.score}</span></td>
      <td><span class="grade-pill ${grade.cls}">${grade.label}</span></td>
      <td>${entry.length}</td>
      <td>${boolBadge(entry.has_upper)}</td>
      <td>${boolBadge(entry.has_lower)}</td>
      <td>${boolBadge(entry.has_number)}</td>
      <td>${boolBadge(entry.has_special)}</td>
      <td style="display:flex;gap:6px">
        <button class="btn-icon reveal" aria-label="Reveal password"
          onclick="revealPassword(this,'full-pwd-${entry.id}','${masked.replace(/'/g,"\\'")}','${entry.password.replace(/'/g,"\\'")}')">👁</button>
        <button class="btn-icon" aria-label="Delete entry"
          onclick="deleteEntry(${entry.id})">✕</button>
      </td>`;
    fullHistoryTbody.appendChild(trF);
  });
}

function boolBadge(val) {
  return val
    ? '<span style="color:#22c55e;font-size:1rem">✓</span>'
    : '<span style="color:#ef4444;font-size:1rem">✗</span>';
}

function formatTimestamp(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d)
    ? iso
    : d.toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

/* ── STATS ── */
async function refreshStats() {
  if (!currentAccount) return;
  const data = await apiGet(`/stats/${encodeURIComponent(currentAccount.username)}`);
  const s = data.stats || {};
  statTotal.textContent = s.total  ?? 0;
  statAvg.textContent   = s.avg_score  != null ? s.avg_score  : '—';
  statBest.textContent  = s.best_score != null ? s.best_score : '—';
  statWeak.textContent  = s.weak_count ?? 0;
}

/* ── REVEAL / DELETE (global for inline onclick) ── */
window.revealPassword = function(btn, spanId, masked, plain) {
  const span = $(spanId);
  if (!span) return;
  if (span.textContent === masked || span.textContent.includes('●')) {
    span.textContent = plain;
    btn.textContent  = '🙈 Hide';
  } else {
    span.textContent = masked;
    btn.textContent  = btn.textContent.includes('Hide') ? '👁 Reveal' : '👁';
  }
};

window.deleteEntry = async function(entryId) {
  if (!confirm('Delete this password entry from the database?')) return;
  try {
    const data = await apiDelete(`/history/${entryId}`, { username: currentAccount.username });
    if (data.error) { showToast('Error: ' + data.error, 'warn'); return; }
    historyData = historyData.filter(e => e.id !== entryId);
    renderHistory();
    await refreshStats();
    showToast('Entry deleted from database.');
  } catch {
    showToast('Failed to delete. Is the server running?', 'warn');
  }
};

/* ── CSV EXPORT (via server) ── */
function exportCSV() {
  if (!currentAccount) { showToast('Please log in first.', 'warn'); return; }
  if (historyData.length === 0) { showToast('No history to export!', 'warn'); return; }
  // Trigger file download via server endpoint
  window.location.href = `${API_BASE}/export/${encodeURIComponent(currentAccount.username)}`;
  showToast('✅ CSV download started!');
}

/* ── TOAST ── */
let toastTimer;
function showToast(msg, type = 'ok') {
  toast.textContent = msg;
  toast.style.borderColor = type === 'warn' ? 'rgba(249,115,22,.5)' : 'rgba(6,182,212,.45)';
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3400);
}

/* ── NAVIGATION ── */
function navigate(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.getElementById(pageId)?.classList.add('active');
  document.getElementById(`nav-${pageId}`)?.classList.add('active');
  if (pageId === 'history') refreshStats();
}

/* ── ACCOUNT SETUP ── */
async function initAccount(username) {
  setLoading(startBtn, true);
  try {
    const data = await apiPost('/account', { username });
    if (data.error) { showToast(data.error, 'warn'); return; }
    currentAccount = data.account;
    const initials = username.charAt(0).toUpperCase();
    accountAvatar.textContent  = initials;
    accountDisplay.textContent = username;
    historyAccName.textContent = username;
    accountModal.classList.add('hidden');
    await loadHistory();
  } catch {
    showToast('Cannot connect to server. Is server.py running?', 'warn');
  } finally {
    setLoading(startBtn, false);
  }
}

/* ── LOAD HISTORY FROM API ── */
async function loadHistory() {
  if (!currentAccount) return;
  try {
    const data = await apiGet(`/history/${encodeURIComponent(currentAccount.username)}`);
    historyData = (data.history || []).reverse(); // newest first (server sends DESC)
    renderHistory();
    await refreshStats();
  } catch {
    showToast('Failed to load history.', 'warn');
  }
}

/* ── PASSWORD ANALYSIS (API call) ── */
async function runAnalysis(password) {
  if (!password) { resetUI(); return; }
  try {
    const data = await apiPost('/analyze', { password });
    if (data.error) { showToast(data.error, 'warn'); return; }
    currentAnalysis = { ...data.analysis, password };
    updateScoreDisplay(data.analysis);
    updateCriteria(data.analysis);
    saveBtn.disabled = false;
  } catch {
    showToast('Server not reachable. Is server.py running?', 'warn');
  }
}

/* ── SAVE TO HISTORY ── */
async function saveToHistory() {
  if (!currentAnalysis || !currentAccount) return;
  setLoading(saveBtn, true);
  try {
    const data = await apiPost('/history', {
      username: currentAccount.username,
      password: currentAnalysis.password,
    });
    if (data.error) { showToast(data.error, 'warn'); return; }
    // Prepend to front (newest first)
    historyData.unshift(data.entry);
    renderHistory();
    await refreshStats();
    currentAnalysis  = null;
    saveBtn.disabled = true;
    showToast('✅ Password saved to database!');
  } catch {
    showToast('Failed to save. Is the server running?', 'warn');
  } finally {
    setLoading(saveBtn, false);
  }
}

/* ── EVENT LISTENERS ── */

// Account modal
startBtn.addEventListener('click', () => {
  const name = usernameInput.value.trim();
  if (!name) { usernameInput.focus(); showToast('Please enter a username.', 'warn'); return; }
  initAccount(name);
});
usernameInput.addEventListener('keydown', e => { if (e.key === 'Enter') startBtn.click(); });

// Nav links
document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    navigate(link.getAttribute('href').replace('#', ''));
  });
});

// Password input – live analysis as user types (debounced)
let debounceTimer;
passwordInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  const pwd = passwordInput.value;
  if (!pwd) { resetUI(); return; }
  debounceTimer = setTimeout(() => runAnalysis(pwd), 280);
});

// Check button – immediate analysis
checkBtn.addEventListener('click', () => {
  const pwd = passwordInput.value;
  if (!pwd) { showToast('Please enter a password first!', 'warn'); return; }
  runAnalysis(pwd);
});
passwordInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') checkBtn.click();
});

// Toggle password visibility
toggleVis.addEventListener('click', () => {
  isPasswordVisible = !isPasswordVisible;
  passwordInput.type = isPasswordVisible ? 'text' : 'password';
  $('eye-icon').innerHTML = isPasswordVisible
    ? `<path d="M3 3l14 14M10 4C5.5 4 2 10 2 10s1.5 2.5 4 4M10 16c4.5 0 8-6 8-6s-1.5-2.5-4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>`
    : `<path d="M1 10S4 4 10 4s9 6 9 6-3 6-9 6-9-6-9-6z" stroke="currentColor" stroke-width="1.6"/><circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.6"/>`;
});

// Save to history
saveBtn.addEventListener('click', saveToHistory);

// Export CSV (via server endpoint)
exportBtn.addEventListener('click',  exportCSV);
exportBtn2.addEventListener('click', exportCSV);

/* ── INIT ── */
(function init() {
  accountModal.classList.remove('hidden');
  usernameInput.focus();
  updateRing(0);
})();
