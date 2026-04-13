/**
 * ╔══════════════════════════════════════════╗
 * ║      Dream Store — License System v2.0   ║
 * ╚══════════════════════════════════════════╝
 */

const express   = require('express');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');

/* ================================================================
   CONFIG
================================================================ */
const PORT           = Number(process.env.PORT || 3000);
const ADMIN_KEY      = process.env.ADMIN_KEY      || 'CHANGE_ME_ADMIN_KEY';
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || 'CHANGE_ME_DASH';
const DB_PATH        = process.env.DB_PATH        || './dream_store.db';

// AES-256-GCM key derived from env secret (stored encrypted product code)
const CODE_KEY = crypto.scryptSync(
  process.env.CODE_ENC_SECRET || 'dream_store_default_CHANGE_ME',
  'dream_store_code_salt_v2',
  32
);

/* ================================================================
   APP + DB
================================================================ */
const app = express();
const db  = new DatabaseSync(DB_PATH);

app.disable('x-powered-by');
app.use(express.json({ limit: '8mb' }));

/* ================================================================
   UTILITIES
================================================================ */
const nowIso = () => new Date().toISOString();

function getIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (typeof xf === 'string' && xf.trim()) ? xf.split(',')[0].trim()
       : req.socket?.remoteAddress || 'unknown';
}

function safe(v, fb = '') { return v == null ? fb : String(v); }
function clampPage(v)  { const n = parseInt(v, 10); return (n > 0 && isFinite(n)) ? n : 1; }
function clampLimit(v) { const n = parseInt(v, 10); return isFinite(n) ? Math.min(Math.max(n, 1), 100) : 20; }
function daysFromNow(d) { return new Date(Date.now() + Number(d) * 86400000).toISOString(); }

function genKey(prefix = 'DREAM') {
  return `${prefix}-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}
const genSecret = () => crypto.randomBytes(32).toString('hex');
const genToken  = () => crypto.randomBytes(32).toString('hex');

function hexEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

function hmac(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function verifyHmac(message, secret, sig) {
  if (!message || !secret || !sig) return false;
  return hexEq(hmac(message, secret), sig);
}

function freshTs(ts, windowSec = 60) {
  const n = parseInt(ts, 10);
  return isFinite(n) && Math.abs(Math.floor(Date.now() / 1000) - n) <= windowSec;
}

/* ---------- Code crypto ---------- */
function encryptCode(plaintext) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', CODE_KEY, iv);
  const data   = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: data.toString('hex') };
}

function decryptCode({ iv, tag, data }) {
  const dec = crypto.createDecipheriv('aes-256-gcm', CODE_KEY, Buffer.from(iv, 'hex'));
  dec.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([dec.update(Buffer.from(data, 'hex')), dec.final()]).toString('utf8');
}

/* ---------- Dashboard session tokens ---------- */
function createDashToken() {
  const ts  = Math.floor(Date.now() / 1000);
  const sig = hmac(`dash:${ts}`, ADMIN_KEY);
  return Buffer.from(JSON.stringify({ ts, sig })).toString('base64url');
}

function verifyDashToken(token) {
  try {
    const { ts, sig } = JSON.parse(Buffer.from(token, 'base64url').toString());
    if (Math.floor(Date.now() / 1000) - ts > 86400) return false;
    return hexEq(hmac(`dash:${ts}`, ADMIN_KEY), sig);
  } catch { return false; }
}

/* ---------- Audit ---------- */
function audit(action, licenseKey, ownerId, payload, ip, ok, reason = null) {
  try {
    db.prepare(`INSERT INTO audit_log(action,licenseKey,ownerId,payload,ip,success,reason)
                VALUES(?,?,?,?,?,?,?)`)
      .run(action, licenseKey||null, ownerId||null,
           payload ? JSON.stringify(payload) : null,
           ip||null, ok?1:0, reason);
  } catch (e) { console.error('[AUDIT]', e.message); }
}

/* ---------- License helpers ---------- */
function normLicense(row, reconcile = false) {
  if (!row) return null;
  let status = row.status;
  if (status === 'active' && row.expiresAt && new Date(row.expiresAt).getTime() <= Date.now()) {
    status = 'expired';
    if (reconcile)
      db.prepare(`UPDATE licenses SET status='expired',updatedAt=? WHERE key=? AND status='active'`)
        .run(nowIso(), row.key);
  }
  return {
    key:         row.key,
    secret:      row.secret,
    ownerId:     row.ownerId,
    ownerName:   row.ownerName    || null,
    product:     row.product,
    productType: row.productType  || 'discord',
    tier:        row.tier,
    status,
    price:       Number(row.price || 0),
    currency:    row.currency     || 'USD',
    createdAt:   row.createdAt,
    updatedAt:   row.updatedAt,
    expiresAt:   row.expiresAt    || null,
    trial:       !!row.trial,
    notes:       row.notes        || null,
    boundTo:     row.boundTo      || null,
    lastSeen:    row.lastSeen     || null,
  };
}

function getLic(key, reconcile = false) {
  return normLicense(db.prepare('SELECT * FROM licenses WHERE key=?').get(key), reconcile);
}

function isActive(lic) {
  if (!lic) return false;
  if (lic.status !== 'active' && lic.status !== 'trial') return false;
  if (!lic.expiresAt) return true;
  return new Date(lic.expiresAt).getTime() > Date.now();
}

/* ================================================================
   DATABASE SCHEMA
================================================================ */
db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS licenses (
    key         TEXT PRIMARY KEY,
    secret      TEXT NOT NULL,
    ownerId     TEXT NOT NULL,
    ownerName   TEXT,
    product     TEXT NOT NULL DEFAULT 'unknown',
    productType TEXT NOT NULL DEFAULT 'discord',
    tier        TEXT NOT NULL DEFAULT 'premium',
    status      TEXT NOT NULL DEFAULT 'active',
    price       REAL NOT NULL DEFAULT 0,
    currency    TEXT NOT NULL DEFAULT 'USD',
    createdAt   TEXT NOT NULL DEFAULT (datetime('now')),
    updatedAt   TEXT NOT NULL DEFAULT (datetime('now')),
    expiresAt   TEXT,
    trial       INTEGER NOT NULL DEFAULT 0,
    notes       TEXT,
    boundTo     TEXT,
    lastSeen    TEXT
  );

  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    type        TEXT NOT NULL DEFAULT 'discord',
    price       REAL NOT NULL DEFAULT 0,
    currency    TEXT NOT NULL DEFAULT 'USD',
    codeData    TEXT,
    codeIv      TEXT,
    codeTag     TEXT,
    hasCode     INTEGER NOT NULL DEFAULT 0,
    active      INTEGER NOT NULL DEFAULT 1,
    createdAt   TEXT NOT NULL DEFAULT (datetime('now')),
    updatedAt   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS heartbeat_tokens (
    licenseKey  TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    expiresAt   TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    licenseKey  TEXT,
    ownerId     TEXT,
    payload     TEXT,
    ip          TEXT,
    success     INTEGER NOT NULL DEFAULT 0,
    reason      TEXT,
    ts          TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Seed default products
if (db.prepare('SELECT COUNT(*) AS c FROM products').get().c === 0) {
  const ins = db.prepare(`INSERT OR IGNORE INTO products(id,name,description,type,price,createdAt,updatedAt)
                           VALUES(?,?,?,?,?,?,?)`);
  [
    ['welcome-bot',       'Welcome Bot',           'Auto welcome messages with custom embeds',   'discord', 15],
    ['role-restore-bot',  'Role Restore Bot',      'Restores member roles when they rejoin',     'discord', 20],
    ['server-backup-bot', 'Server Backup Bot',     'Full Discord server backup & restore',       'discord', 35],
    ['vehicle-rental',    'Vehicle Rental Script', 'FiveM QBCore vehicle rental system',         'fivem',   25],
  ].forEach(p => ins.run(...p, nowIso(), nowIso()));
  console.log('[DB] Default products seeded');
}

/* ================================================================
   MIDDLEWARE
================================================================ */
const mk = (max, msg) => rateLimit({ windowMs: 60000, max, standardHeaders: true, legacyHeaders: false, message: msg });
const adminLimiter    = mk(60,  { success: false, error: 'RATE_LIMITED' });
const validateLimiter = mk(30,  { valid:   false, error: 'RATE_LIMITED' });
const loaderLimiter   = mk(30,  { success: false, error: 'RATE_LIMITED' });
const dashLimiter     = mk(120, { success: false, error: 'RATE_LIMITED' });

function adminAuth(req, res, next) {
  if (req.headers['admin-key'] !== ADMIN_KEY)
    return res.status(401).json({ success: false, error: 'UNAUTHORIZED' });
  next();
}

function dashAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (!token || !verifyDashToken(token))
    return res.status(401).json({ success: false, error: 'UNAUTHORIZED' });
  next();
}

/* ================================================================
   HEALTH
================================================================ */
app.get('/', (_, res) => res.json({ status: 'online', service: 'Dream Store', version: '2.0.0' }));

app.get('/health', (_, res) => {
  try {
    res.json({
      status: 'healthy', version: '2.0.0', timestamp: nowIso(),
      uptime: process.uptime(),
      db: {
        licenses: db.prepare('SELECT COUNT(*) AS c FROM licenses').get().c,
        active:   db.prepare("SELECT COUNT(*) AS c FROM licenses WHERE status='active'").get().c,
        products: db.prepare('SELECT COUNT(*) AS c FROM products').get().c,
      }
    });
  } catch (e) { res.status(500).json({ status: 'unhealthy', error: e.message }); }
});

/* ================================================================
   DASHBOARD — HTML
================================================================ */
const DASH_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dream Store — Admin</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
*{box-sizing:border-box}
body{background:#0a0d14;color:#e2e8f0;font-family:system-ui,sans-serif}
.card{background:#111827;border:1px solid #1f2937;border-radius:12px}
.inp{background:#0a0d14;border:1px solid #374151;color:#e2e8f0;padding:8px 12px;border-radius:8px;width:100%;outline:none}
.inp:focus{border-color:#6366f1}
.btn{padding:8px 18px;border-radius:8px;cursor:pointer;border:none;font-weight:600;transition:.15s}
.btn-p{background:#6366f1;color:#fff}.btn-p:hover{background:#4f46e5}
.btn-d{background:#ef4444;color:#fff;font-size:12px;padding:4px 10px;border-radius:6px}
.btn-s{background:#22c55e;color:#fff;font-size:12px;padding:4px 10px;border-radius:6px}
.btn-w{background:#f59e0b;color:#fff;font-size:12px;padding:4px 10px;border-radius:6px}
.btn-g{background:#374151;color:#d1d5db;font-size:12px;padding:4px 10px;border-radius:6px}
.tab{padding:10px 20px;border-radius:8px;cursor:pointer;color:#6b7280;border:none;background:none;font-weight:500}
.tab.on{background:#6366f1;color:#fff}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 14px;border-bottom:1px solid #1f2937;color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
td{padding:10px 14px;border-bottom:1px solid #111827;font-size:13px;vertical-align:middle}
tr:hover td{background:#0f172a}
.badge{padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700}
.ba{background:#064e3b;color:#6ee7b7}.be{background:#450a0a;color:#fca5a5}
.bs{background:#431407;color:#fdba74}.bt{background:#1e3a5f;color:#93c5fd}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:50;align-items:center;justify-content:center}
.modal.open{display:flex}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:#0a0d14}::-webkit-scrollbar-thumb{background:#374151;border-radius:3px}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="loginPage" class="min-h-screen flex items-center justify-center">
  <div class="card p-8 w-full max-w-sm">
    <div class="text-center mb-6">
      <div class="text-5xl mb-3">🏪</div>
      <h1 class="text-2xl font-bold" style="color:#818cf8">Dream Store</h1>
      <p class="text-gray-500 text-sm mt-1">License Management System</p>
    </div>
    <input type="password" id="dashPass" class="inp mb-3" placeholder="Dashboard Password"
      onkeydown="if(event.key==='Enter')login()">
    <button class="btn btn-p w-full" onclick="login()">Sign In</button>
    <p id="loginErr" class="text-red-400 text-sm mt-3 text-center hidden">Invalid password</p>
  </div>
</div>

<!-- DASHBOARD -->
<div id="mainDash" class="hidden min-h-screen">

  <!-- NAV -->
  <nav class="border-b border-gray-800 px-6 py-3 flex items-center justify-between sticky top-0 z-10" style="background:#0a0d14">
    <div class="flex items-center gap-3">
      <span class="text-xl">🏪</span>
      <span class="font-bold" style="color:#818cf8">Dream Store</span>
      <span class="text-gray-700 text-xs">v2.0</span>
    </div>
    <div class="flex items-center gap-4">
      <span id="srvStatus" class="text-xs text-gray-600">●  checking...</span>
      <button onclick="logout()" class="text-gray-500 hover:text-white text-sm">Logout</button>
    </div>
  </nav>

  <!-- TABS -->
  <div class="px-6 pt-3 border-b border-gray-800 flex gap-1">
    <button class="tab on" onclick="showTab('overview')">📊 Overview</button>
    <button class="tab"    onclick="showTab('licenses')">🎫 Licenses</button>
    <button class="tab"    onclick="showTab('products')">📦 Products</button>
    <button class="tab"    onclick="showTab('audit')">📋 Audit Log</button>
  </div>

  <div class="p-6">

    <!-- OVERVIEW -->
    <div id="t-overview">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6" id="statsGrid">
        <div class="card p-5"><p class="text-gray-400 text-xs mb-1">Total Licenses</p><p id="s-total" class="text-3xl font-bold">—</p></div>
        <div class="card p-5"><p class="text-gray-400 text-xs mb-1">Active</p><p id="s-active" class="text-3xl font-bold text-green-400">—</p></div>
        <div class="card p-5"><p class="text-gray-400 text-xs mb-1">Revenue</p><p id="s-revenue" class="text-3xl font-bold" style="color:#818cf8">—</p></div>
        <div class="card p-5"><p class="text-gray-400 text-xs mb-1">Products</p><p id="s-products" class="text-3xl font-bold text-purple-400">—</p></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="card p-4">
          <h3 class="font-semibold mb-3 text-gray-300 text-sm uppercase tracking-wide">License Breakdown</h3>
          <div id="breakdown" class="space-y-2 text-sm text-gray-400">Loading...</div>
        </div>
        <div class="card p-4">
          <h3 class="font-semibold mb-3 text-gray-300 text-sm uppercase tracking-wide">Recent Activity</h3>
          <div id="recentAudit" class="space-y-1 text-sm text-gray-400">Loading...</div>
        </div>
      </div>
    </div>

    <!-- LICENSES -->
    <div id="t-licenses" class="hidden">
      <div class="flex flex-wrap gap-3 mb-4">
        <select id="licFilter" class="inp" style="width:auto" onchange="loadLicenses()">
          <option value="active">Active</option><option value="expired">Expired</option>
          <option value="suspended">Suspended</option><option value="trial">Trial</option>
          <option value="all">All</option>
        </select>
        <input id="licSearch" class="inp" style="width:200px" placeholder="Search key / owner..." oninput="filterLic()">
        <button class="btn btn-p" onclick="openCreateLic()">+ New License</button>
      </div>
      <div class="card overflow-auto">
        <table><thead><tr>
          <th>License Key</th><th>Owner</th><th>Product</th><th>Type</th>
          <th>Status</th><th>Expires</th><th>Bound To</th><th>Actions</th>
        </tr></thead>
        <tbody id="licTable"><tr><td colspan="8" class="text-center text-gray-700 py-10">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- PRODUCTS -->
    <div id="t-products" class="hidden">
      <div class="flex justify-end mb-4">
        <button class="btn btn-p" onclick="openProdModal()">+ Add Product</button>
      </div>
      <div class="card overflow-auto">
        <table><thead><tr>
          <th>ID</th><th>Name</th><th>Type</th><th>Price</th><th>Code</th><th>Status</th><th>Actions</th>
        </tr></thead>
        <tbody id="prodTable"><tr><td colspan="7" class="text-center text-gray-700 py-10">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- AUDIT -->
    <div id="t-audit" class="hidden">
      <div class="card overflow-auto">
        <table><thead><tr>
          <th>Time</th><th>Action</th><th>License</th><th>Owner</th><th>IP</th><th>Ok</th><th>Reason</th>
        </tr></thead>
        <tbody id="auditTable"><tr><td colspan="7" class="text-center text-gray-700 py-10">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<!-- MODAL: Create License -->
<div id="mCreateLic" class="modal">
  <div class="card p-6 w-full max-w-md mx-4" style="max-height:90vh;overflow-y:auto">
    <h2 class="text-lg font-bold mb-4">🎫 Create License</h2>
    <div class="space-y-3">
      <div><label class="text-xs text-gray-400">Discord User ID *</label>
        <input id="cl-owner" class="inp mt-1" placeholder="123456789012345678"></div>
      <div><label class="text-xs text-gray-400">Owner Name</label>
        <input id="cl-name" class="inp mt-1" placeholder="Username"></div>
      <div><label class="text-xs text-gray-400">Product *</label>
        <select id="cl-product" class="inp mt-1" onchange="onProductChange()">
          <option value="">Select product...</option></select></div>
      <div><label class="text-xs text-gray-400" id="cl-bindLabel">Discord Guild ID *</label>
        <input id="cl-bound" class="inp mt-1" placeholder="Server ID or IP:Port"></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="text-xs text-gray-400">Days *</label>
          <input id="cl-days" class="inp mt-1" type="number" value="30" min="1"></div>
        <div><label class="text-xs text-gray-400">Price (USD)</label>
          <input id="cl-price" class="inp mt-1" type="number" value="15" step="0.01" min="0"></div>
      </div>
      <div><label class="text-xs text-gray-400">Notes</label>
        <input id="cl-notes" class="inp mt-1" placeholder="Optional"></div>
    </div>
    <div class="flex gap-2 mt-4">
      <button class="btn btn-p flex-1" onclick="createLicense()">Create</button>
      <button class="btn flex-1" style="background:#1f2937;color:#9ca3af" onclick="closeModal('mCreateLic')">Cancel</button>
    </div>
    <div id="cl-result" class="mt-3 text-sm"></div>
  </div>
</div>

<!-- MODAL: Product -->
<div id="mProduct" class="modal">
  <div class="card p-6 w-full max-w-lg mx-4" style="max-height:90vh;overflow-y:auto">
    <h2 class="text-lg font-bold mb-4" id="pmTitle">📦 Add Product</h2>
    <input type="hidden" id="pm-editId">
    <div class="space-y-3">
      <div><label class="text-xs text-gray-400">Product ID *</label>
        <input id="pm-id" class="inp mt-1" placeholder="e.g. welcome-bot"></div>
      <div><label class="text-xs text-gray-400">Name *</label>
        <input id="pm-name" class="inp mt-1" placeholder="Display Name"></div>
      <div><label class="text-xs text-gray-400">Description</label>
        <input id="pm-desc" class="inp mt-1" placeholder="Short description"></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="text-xs text-gray-400">Type *</label>
          <select id="pm-type" class="inp mt-1">
            <option value="discord">Discord Bot</option>
            <option value="fivem">FiveM Script</option>
          </select></div>
        <div><label class="text-xs text-gray-400">Price (USD)</label>
          <input id="pm-price" class="inp mt-1" type="number" value="0" step="0.01" min="0"></div>
      </div>
      <div>
        <label class="text-xs text-gray-400">Product Code (JS or Lua)</label>
        <p class="text-xs text-gray-600 mt-1 mb-1">🔐 Encrypted with AES-256-GCM at rest. Leave empty to keep existing.</p>
        <textarea id="pm-code" class="inp mt-1" rows="10" placeholder="Paste bot/script code here..."
          style="font-family:monospace;font-size:12px;resize:vertical"></textarea>
      </div>
    </div>
    <div class="flex gap-2 mt-4">
      <button class="btn btn-p flex-1" onclick="saveProduct()">Save</button>
      <button class="btn flex-1" style="background:#1f2937;color:#9ca3af" onclick="closeModal('mProduct')">Cancel</button>
    </div>
    <div id="pm-result" class="mt-3 text-sm"></div>
  </div>
</div>

<script>
let TOK = localStorage.getItem('ds_tok');
let allLic = [], allProd = [];

const $ = id => document.getElementById(id);

async function apix(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOK } };
  if (body) opts.body = JSON.stringify(body);
  try { const r = await fetch('/dash/api' + path, opts); return r.json(); }
  catch (e) { return { success: false, error: e.message }; }
}

async function login() {
  const pass = $('dashPass').value;
  const r = await fetch('/dash/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pass }) });
  const d = await r.json();
  if (d.token) { TOK = d.token; localStorage.setItem('ds_tok', TOK); showDash(); }
  else { $('loginErr').classList.remove('hidden'); }
}

function logout() { localStorage.removeItem('ds_tok'); location.reload(); }

function showDash() {
  $('loginPage').classList.add('hidden');
  $('mainDash').classList.remove('hidden');
  loadOverview();
  checkServer();
}

async function checkServer() {
  try {
    const r = await fetch('/health'); const d = await r.json();
    $('srvStatus').textContent = '● online'; $('srvStatus').style.color = '#4ade80';
  } catch { $('srvStatus').textContent = '● offline'; $('srvStatus').style.color = '#f87171'; }
}

function showTab(t) {
  ['overview','licenses','products','audit'].forEach(x => {
    $('t-'+x).classList.toggle('hidden', x !== t);
  });
  document.querySelectorAll('.tab').forEach((el,i) => {
    el.classList.toggle('on', ['overview','licenses','products','audit'][i] === t);
  });
  if (t === 'overview') loadOverview();
  if (t === 'licenses') loadLicenses();
  if (t === 'products') loadProducts();
  if (t === 'audit')    loadAudit();
}

async function loadOverview() {
  const d = await apix('GET', '/stats');
  if (!d.success) return;
  $('s-total').textContent   = d.total;
  $('s-active').textContent  = d.active;
  $('s-revenue').textContent = '$' + (d.revenue || 0).toFixed(0);
  $('s-products').textContent = d.products;
  $('breakdown').innerHTML = [
    ['Active', d.active, '#4ade80'], ['Expired', d.expired, '#f87171'],
    ['Suspended', d.suspended, '#fb923c'], ['Trial', d.trial, '#60a5fa']
  ].map(([l,v,c]) => \`<div class="flex justify-between border-b border-gray-800 pb-2">
    <span>\${l}</span><span style="color:\${c};font-weight:700">\${v}</span></div>\`).join('');
  const audit = await apix('GET', '/audit?limit=6');
  if (audit.success)
    $('recentAudit').innerHTML = audit.logs.map(l =>
      \`<div class="flex justify-between py-1 border-b border-gray-800 text-xs">
        <span style="color:\${l.success?'#4ade80':'#f87171'}">\${l.action}</span>
        <span class="text-gray-600">\${(l.ts||'').substring(0,16)}</span></div>\`
    ).join('');
}

async function loadLicenses() {
  const f = $('licFilter').value;
  const d = await apix('GET', '/licenses?filter=' + f + '&limit=200');
  if (!d.success) return;
  allLic = d.licenses || [];
  renderLic(allLic);
}

function filterLic() {
  const q = $('licSearch').value.toLowerCase();
  renderLic(q ? allLic.filter(l => l.key.toLowerCase().includes(q) ||
    (l.ownerId||'').includes(q) || (l.ownerName||'').toLowerCase().includes(q)) : allLic);
}

function badge(s) {
  return \`<span class="badge \${{ active:'ba',expired:'be',suspended:'bs',trial:'bt' }[s]||''}">\${s}</span>\`;
}

function renderLic(list) {
  const tb = $('licTable');
  if (!list.length) { tb.innerHTML = '<tr><td colspan="8" class="text-center text-gray-700 py-10">No licenses found</td></tr>'; return; }
  tb.innerHTML = list.map(l => {
    const dl = l.expiresAt ? Math.ceil((new Date(l.expiresAt)-Date.now())/86400000) : null;
    const exp = l.expiresAt ? new Date(l.expiresAt).toLocaleDateString() : '∞';
    const dstr = dl !== null ? (dl > 0 ? dl+'d left' : 'Expired') : '∞';
    return \`<tr>
      <td class="font-mono text-xs">\${l.key}</td>
      <td class="text-xs">\${l.ownerName||l.ownerId}</td>
      <td class="text-xs">\${l.product||'—'}</td>
      <td class="text-xs">\${l.productType||'discord'}</td>
      <td>\${badge(l.status)}</td>
      <td class="text-xs">\${exp}<br><span class="text-gray-600">\${dstr}</span></td>
      <td class="font-mono text-xs text-gray-500">\${l.boundTo||'—'}</td>
      <td class="flex gap-1 flex-wrap">
        \${l.status!=='suspended'?\`<button class="btn-d" onclick="suspLic('\${l.key}')">Suspend</button>\`:''}
        \${l.status==='suspended'?\`<button class="btn-s" onclick="renewLic('\${l.key}',0,true)">Unsuspend</button>\`:''}
        <button class="btn-w" onclick="renewLic('\${l.key}',30)">+30d</button>
        <button class="btn-g" onclick="unbindLic('\${l.key}')">Unbind</button>
      </td>
    </tr>\`;
  }).join('');
}

async function suspLic(key) {
  if (!confirm('Suspend ' + key + '?')) return;
  const d = await apix('POST', '/license/suspend', { licenseKey: key });
  d.success ? loadLicenses() : alert('Error: ' + d.error);
}
async function renewLic(key, days, unsuspend = false) {
  const d = await apix('POST', '/license/renew', { licenseKey: key, days, unsuspend });
  d.success ? loadLicenses() : alert('Error: ' + d.error);
}
async function unbindLic(key) {
  if (!confirm('Unbind ' + key + '? Customer will need to re-activate.')) return;
  const d = await apix('POST', '/license/unbind', { licenseKey: key });
  d.success ? loadLicenses() : alert('Error: ' + d.error);
}

async function loadProducts() {
  const d = await apix('GET', '/products');
  if (!d.success) return;
  allProd = d.products;
  const tb = $('prodTable');
  tb.innerHTML = d.products.map(p => \`<tr>
    <td class="font-mono text-xs">\${p.id}</td>
    <td>\${p.name}</td>
    <td><span class="badge \${p.type==='discord'?'ba':'bt'}">\${p.type}</span></td>
    <td>$\${p.price}</td>
    <td>\${p.hasCode?'<span style="color:#4ade80">✓ Yes</span>':'<span class="text-gray-600">—</span>'}</td>
    <td>\${p.active?'<span style="color:#4ade80">Active</span>':'<span class="text-gray-600">Off</span>'}</td>
    <td><button class="btn-w" onclick="editProd('\${p.id}')">Edit</button></td>
  </tr>\`).join('');
  // Populate create-license product selector
  const sel = $('cl-product');
  sel.innerHTML = '<option value="">Select product...</option>' +
    d.products.filter(p => p.active).map(p =>
      \`<option value="\${p.id}" data-type="\${p.type}" data-price="\${p.price}">\${p.name} (\${p.type})</option>\`
    ).join('');
}

async function loadAudit() {
  const d = await apix('GET', '/audit?limit=80');
  if (!d.success) return;
  const tb = $('auditTable');
  if (!d.logs.length) { tb.innerHTML = '<tr><td colspan="7" class="text-center text-gray-700 py-10">No entries</td></tr>'; return; }
  tb.innerHTML = d.logs.map(l => \`<tr>
    <td class="text-xs text-gray-500">\${(l.ts||'').substring(0,19)}</td>
    <td class="text-xs font-semibold">\${l.action}</td>
    <td class="font-mono text-xs">\${l.licenseKey||'—'}</td>
    <td class="text-xs">\${l.ownerId||'—'}</td>
    <td class="text-xs text-gray-500">\${l.ip||'—'}</td>
    <td>\${l.success?'<span style="color:#4ade80">✓</span>':'<span style="color:#f87171">✗</span>'}</td>
    <td class="text-xs text-gray-600">\${l.reason||''}</td>
  </tr>\`).join('');
}

function openCreateLic() {
  loadProducts();
  $('cl-result').innerHTML = '';
  ['cl-owner','cl-name','cl-bound','cl-notes'].forEach(id => $(id).value = '');
  $('cl-days').value = '30'; $('cl-price').value = '15';
  $('mCreateLic').classList.add('open');
}

function onProductChange() {
  const opt = $('cl-product').options[$('cl-product').selectedIndex];
  const type = opt?.dataset?.type || 'discord';
  $('cl-bindLabel').textContent = type === 'fivem' ? 'Server IP:Port *' : 'Discord Guild ID *';
  $('cl-bound').placeholder = type === 'fivem' ? '51.20.100.50:30120' : '123456789012345678';
  if (opt?.dataset?.price) $('cl-price').value = opt.dataset.price;
}

async function createLicense() {
  const body = {
    ownerId:   $('cl-owner').value.trim(),
    ownerName: $('cl-name').value.trim(),
    product:   $('cl-product').value,
    boundTo:   $('cl-bound').value.trim(),
    days:      parseInt($('cl-days').value),
    price:     parseFloat($('cl-price').value),
    notes:     $('cl-notes').value.trim(),
  };
  if (!body.ownerId || !body.product || !body.days) {
    $('cl-result').innerHTML = '<span style="color:#f87171">Fill required fields</span>'; return;
  }
  const d = await apix('POST', '/admin/create', body);
  if (d.success) {
    $('cl-result').innerHTML = \`<div style="background:#052e16;border:1px solid #166534;border-radius:8px;padding:12px;margin-top:8px">
      <p style="color:#4ade80;font-weight:700">✅ License Created!</p>
      <p class="font-mono text-sm mt-2"><b>Key:</b> \${d.licenseKey}</p>
      <p class="font-mono text-xs mt-1" style="color:#94a3b8"><b>Secret:</b> \${d.licenseSecret}</p>
      <p class="text-xs mt-1" style="color:#6b7280">Expires: \${new Date(d.expiresAt).toLocaleDateString()}</p>
      <p class="text-xs mt-1" style="color:#fb923c">⚠️ Send BOTH Key + Secret to customer via DM</p>
    </div>\`;
  } else {
    $('cl-result').innerHTML = \`<span style="color:#f87171">Error: \${d.error}</span>\`;
  }
}

function openProdModal() {
  ['pm-editId','pm-id','pm-name','pm-desc','pm-code'].forEach(id => $(id).value = '');
  $('pm-type').value = 'discord'; $('pm-price').value = '0';
  $('pm-id').disabled = false;
  $('pmTitle').textContent = '📦 Add Product';
  $('pm-result').innerHTML = '';
  $('mProduct').classList.add('open');
}

function editProd(id) {
  const p = allProd.find(x => x.id === id);
  if (!p) return;
  $('pm-editId').value = id;
  $('pm-id').value = id; $('pm-id').disabled = true;
  $('pm-name').value = p.name;
  $('pm-desc').value = p.description || '';
  $('pm-type').value = p.type;
  $('pm-price').value = p.price;
  $('pm-code').value = '';
  $('pmTitle').textContent = '✏️ Edit: ' + p.name;
  $('pm-result').innerHTML = p.hasCode
    ? '<p class="text-xs" style="color:#6b7280">⚡ Code already uploaded. Leave empty to keep it.</p>'
    : '<p class="text-xs" style="color:#fb923c">⚠️ No code uploaded yet.</p>';
  $('mProduct').classList.add('open');
}

async function saveProduct() {
  const editId = $('pm-editId').value;
  const body = {
    id:          $('pm-id').value.trim(),
    name:        $('pm-name').value.trim(),
    description: $('pm-desc').value.trim(),
    type:        $('pm-type').value,
    price:       parseFloat($('pm-price').value) || 0,
    code:        $('pm-code').value,
  };
  if (!body.id || !body.name) {
    $('pm-result').innerHTML = '<span style="color:#f87171">ID and Name required</span>'; return;
  }
  const d = editId ? await apix('PUT',  '/products/' + editId, body)
                   : await apix('POST', '/products', body);
  if (d.success) {
    $('pm-result').innerHTML = '<span style="color:#4ade80">✅ Saved!</span>';
    setTimeout(() => { closeModal('mProduct'); loadProducts(); }, 800);
  } else {
    $('pm-result').innerHTML = \`<span style="color:#f87171">Error: \${d.error}</span>\`;
  }
}

function closeModal(id) { $(id).classList.remove('open'); }
document.addEventListener('click', e => { if (e.target.classList.contains('modal')) closeModal(e.target.id); });

if (TOK && TOK !== 'null') showDash();
</script>
</body></html>`;

/* ================================================================
   DASHBOARD ROUTES
================================================================ */
app.get('/dash', (_, res) => res.send(DASH_HTML));
app.get('/dash/', (_, res) => res.send(DASH_HTML));

app.post('/dash/login', dashLimiter, (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== DASHBOARD_PASS)
    return res.status(401).json({ success: false, error: 'WRONG_PASSWORD' });
  res.json({ success: true, token: createDashToken() });
});

app.get('/dash/api/stats', dashLimiter, dashAuth, (_, res) => {
  try {
    const all     = db.prepare('SELECT status,trial,price FROM licenses').all();
    const prods   = db.prepare('SELECT COUNT(*) AS c FROM products WHERE active=1').get().c;
    const active  = all.filter(l => l.status === 'active').length;
    const expired = all.filter(l => l.status === 'expired').length;
    const susp    = all.filter(l => l.status === 'suspended').length;
    const trial   = all.filter(l => !!l.trial).length;
    const revenue = all.reduce((s, l) => s + Number(l.price || 0), 0);
    res.json({ success: true, total: all.length, active, expired, suspended: susp, trial, revenue, products: prods });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/dash/api/licenses', dashLimiter, dashAuth, (req, res) => {
  const filter = safe(req.query.filter || 'active').toLowerCase();
  const limit  = clampLimit(req.query.limit || 200);

  let rows = db.prepare('SELECT * FROM licenses ORDER BY createdAt DESC LIMIT ?').all(limit);
  let licenses = rows.map(r => normLicense(r, true)).filter(Boolean);

  if (filter !== 'all') {
    if (filter === 'active')    licenses = licenses.filter(l => l.status === 'active' && isActive(l));
    else if (filter === 'trial') licenses = licenses.filter(l => l.trial);
    else                         licenses = licenses.filter(l => l.status === filter);
  }

  const safe_licenses = licenses.map(({ secret, ...rest }) => rest);
  res.json({ success: true, count: safe_licenses.length, licenses: safe_licenses });
});

app.post('/dash/api/license/suspend', dashLimiter, dashAuth, (req, res) => {
  const { licenseKey } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey, true);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  db.prepare(`UPDATE licenses SET status='suspended',updatedAt=? WHERE key=?`).run(nowIso(), licenseKey);
  audit('dashboard.suspend', licenseKey, lic.ownerId, null, 'dashboard', true);
  res.json({ success: true, license: getLic(licenseKey) });
});

app.post('/dash/api/license/renew', dashLimiter, dashAuth, (req, res) => {
  const { licenseKey, days, unsuspend } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey, true);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });

  if (unsuspend) {
    db.prepare(`UPDATE licenses SET status='active',updatedAt=? WHERE key=?`).run(nowIso(), licenseKey);
    audit('dashboard.unsuspend', licenseKey, lic.ownerId, null, 'dashboard', true);
  } else {
    const base = lic.expiresAt && new Date(lic.expiresAt).getTime() > Date.now()
      ? new Date(lic.expiresAt).getTime() : Date.now();
    const newExp = new Date(base + Number(days || 30) * 86400000).toISOString();
    db.prepare(`UPDATE licenses SET status='active',expiresAt=?,updatedAt=? WHERE key=?`)
      .run(newExp, nowIso(), licenseKey);
    audit('dashboard.renew', licenseKey, lic.ownerId, { days }, 'dashboard', true);
  }
  res.json({ success: true, license: getLic(licenseKey) });
});

app.post('/dash/api/license/unbind', dashLimiter, dashAuth, (req, res) => {
  const { licenseKey } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  db.prepare(`UPDATE licenses SET boundTo=NULL,updatedAt=? WHERE key=?`).run(nowIso(), licenseKey);
  audit('dashboard.unbind', licenseKey, lic.ownerId, null, 'dashboard', true);
  res.json({ success: true });
});

app.get('/dash/api/products', dashLimiter, dashAuth, (_, res) => {
  const rows = db.prepare('SELECT id,name,description,type,price,hasCode,active,createdAt FROM products ORDER BY createdAt DESC').all();
  res.json({ success: true, products: rows });
});

app.post('/dash/api/products', dashLimiter, dashAuth, (req, res) => {
  const { id, name, description, type, price, code } = req.body || {};
  if (!id || !name) return res.status(400).json({ success: false, error: 'MISSING_FIELDS' });

  let codeData = null, codeIv = null, codeTag = null, hasCode = 0;
  if (code && code.trim()) {
    try { const enc = encryptCode(code.trim()); codeData = enc.data; codeIv = enc.iv; codeTag = enc.tag; hasCode = 1; }
    catch (e) { return res.status(500).json({ success: false, error: 'ENCRYPT_FAILED' }); }
  }

  try {
    db.prepare(`INSERT INTO products(id,name,description,type,price,codeData,codeIv,codeTag,hasCode,active,createdAt,updatedAt)
                VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`)
      .run(id, name, description||null, type||'discord', Number(price||0), codeData, codeIv, codeTag, hasCode, nowIso(), nowIso());
    res.json({ success: true });
  } catch (e) {
    const dup = e.message?.includes('UNIQUE') ? 'ID_EXISTS' : e.message;
    res.status(400).json({ success: false, error: dup });
  }
});

app.put('/dash/api/products/:id', dashLimiter, dashAuth, (req, res) => {
  const { id } = req.params;
  const { name, description, type, price, code } = req.body || {};

  let updates = [`name=?`, `description=?`, `type=?`, `price=?`, `updatedAt=?`];
  let vals    = [name, description||null, type||'discord', Number(price||0), nowIso()];

  if (code && code.trim()) {
    try {
      const enc = encryptCode(code.trim());
      updates.push('codeData=?', 'codeIv=?', 'codeTag=?', 'hasCode=1');
      vals.push(enc.data, enc.iv, enc.tag);
    } catch (e) { return res.status(500).json({ success: false, error: 'ENCRYPT_FAILED' }); }
  }

  vals.push(id);
  db.prepare(`UPDATE products SET ${updates.join(',')} WHERE id=?`).run(...vals);
  res.json({ success: true });
});

app.get('/dash/api/audit', dashLimiter, dashAuth, (req, res) => {
  const limit = clampLimit(req.query.limit || 50);
  const logs  = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit);
  res.json({ success: true, logs });
});

/* ================================================================
   ADMIN ROUTES (used by admin-bot.js)
================================================================ */

// Create license
app.post('/admin/create', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { ownerId, ownerName, product, productType, boundTo, days, price, tier, currency, notes } = req.body || {};

  if (!safe(ownerId).trim()) {
    audit('admin.create', null, null, req.body, ip, false, 'MISSING_OWNER');
    return res.status(400).json({ success: false, error: 'MISSING_OWNER_ID' });
  }

  const daysN  = Number(days ?? 30);
  const priceN = Number(price ?? 0);
  if (!isFinite(daysN) || daysN <= 0) return res.status(400).json({ success: false, error: 'INVALID_DAYS' });

  // Resolve product type from DB if not provided
  let pType = safe(productType).trim() || 'discord';
  if (!productType && product) {
    const p = db.prepare('SELECT type FROM products WHERE id=?').get(product);
    if (p) pType = p.type;
  }

  const licenseKey    = genKey('DREAM');
  const licenseSecret = genSecret();
  const expiresAt     = daysFromNow(daysN);

  try {
    db.prepare(`INSERT INTO licenses(key,secret,ownerId,ownerName,product,productType,tier,status,price,currency,createdAt,updatedAt,expiresAt,trial,notes,boundTo)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)`)
      .run(licenseKey, licenseSecret, safe(ownerId).trim(), safe(ownerName).trim()||null,
           safe(product)||'unknown', pType, safe(tier)||'premium', 'active',
           priceN, safe(currency)||'USD', nowIso(), nowIso(), expiresAt,
           notes ? safe(notes) : null, boundTo ? safe(boundTo).trim() : null);

    audit('admin.create', licenseKey, safe(ownerId).trim(), { days: daysN, product, price: priceN }, ip, true);

    return res.json({ success: true, licenseKey, licenseSecret, expiresAt, productType: pType });
  } catch (e) {
    console.error('[CREATE]', e.message);
    audit('admin.create', licenseKey, safe(ownerId).trim(), req.body, ip, false, e.message);
    return res.status(500).json({ success: false, error: 'CREATE_FAILED' });
  }
});

// Trial license
app.post('/trial/create', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { discordId, name, product } = req.body || {};
  if (!safe(discordId).trim()) return res.status(400).json({ success: false, error: 'MISSING_DISCORD_ID' });

  const existing = db.prepare(`SELECT * FROM licenses WHERE ownerId=? AND trial=1 ORDER BY createdAt DESC LIMIT 1`).get(discordId);
  const exLic    = normLicense(existing, true);
  if (exLic && isActive(exLic)) return res.status(409).json({ success: false, error: 'TRIAL_ALREADY_ACTIVE' });

  const licenseKey    = genKey('TRIAL');
  const licenseSecret = genSecret();
  const expiresAt     = daysFromNow(7);

  try {
    db.prepare(`INSERT INTO licenses(key,secret,ownerId,ownerName,product,productType,tier,status,price,currency,createdAt,updatedAt,expiresAt,trial)
                VALUES(?,?,?,?,?,?,?,?,0,'USD',?,?,?,1)`)
      .run(licenseKey, licenseSecret, discordId, safe(name)||null, safe(product)||'unknown',
           'discord', 'trial', 'active', nowIso(), nowIso(), expiresAt);
    audit('trial.create', licenseKey, discordId, { product }, ip, true);
    return res.json({ success: true, licenseKey, licenseSecret, expiresAt, expiresIn: '7 days' });
  } catch (e) {
    audit('trial.create', null, discordId, req.body, ip, false, e.message);
    return res.status(500).json({ success: false, error: 'TRIAL_FAILED' });
  }
});

// List licenses
app.get('/licenses', adminLimiter, adminAuth, (req, res) => {
  const filter = safe(req.query.filter || 'active').toLowerCase();
  const page   = clampPage(req.query.page);
  const limit  = clampLimit(req.query.limit || 20);

  let all = db.prepare('SELECT * FROM licenses ORDER BY createdAt DESC').all()
              .map(r => normLicense(r, true)).filter(Boolean);

  if (filter === 'active')   all = all.filter(l => l.status === 'active' && isActive(l));
  else if (filter === 'trial')  all = all.filter(l => l.trial);
  else if (filter !== 'all')    all = all.filter(l => l.status === filter);

  const total = all.length;
  const start = (page - 1) * limit;
  const list  = all.slice(start, start + limit).map(({ secret, ...rest }) => rest);
  res.json({ success: true, count: total, page, totalPages: Math.max(1, Math.ceil(total/limit)), licenses: list });
});

// Suspend
app.post('/license/suspend', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { licenseKey } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey, true);
  if (!lic) { audit('admin.suspend', licenseKey, null, null, ip, false, 'NOT_FOUND'); return res.status(404).json({ success: false, error: 'NOT_FOUND' }); }
  db.prepare(`UPDATE licenses SET status='suspended',updatedAt=? WHERE key=?`).run(nowIso(), licenseKey);
  audit('admin.suspend', licenseKey, lic.ownerId, null, ip, true);
  res.json({ success: true, license: getLic(licenseKey) });
});

// Renew
app.post('/license/renew', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { licenseKey, days } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const daysN = Number(days ?? 30);
  if (!isFinite(daysN) || daysN < 0) return res.status(400).json({ success: false, error: 'INVALID_DAYS' });
  const lic = getLic(licenseKey, true);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  const base   = lic.expiresAt && new Date(lic.expiresAt).getTime() > Date.now() ? new Date(lic.expiresAt).getTime() : Date.now();
  const newExp = new Date(base + daysN * 86400000).toISOString();
  db.prepare(`UPDATE licenses SET status='active',expiresAt=?,updatedAt=? WHERE key=?`).run(newExp, nowIso(), licenseKey);
  audit('admin.renew', licenseKey, lic.ownerId, { days: daysN }, ip, true);
  res.json({ success: true, license: getLic(licenseKey) });
});

// Revoke (permanent delete)
app.post('/license/revoke', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { licenseKey } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  db.prepare('DELETE FROM licenses WHERE key=?').run(licenseKey);
  db.prepare('DELETE FROM heartbeat_tokens WHERE licenseKey=?').run(licenseKey);
  audit('admin.revoke', licenseKey, lic.ownerId, null, ip, true);
  res.json({ success: true, message: 'License permanently deleted' });
});

// Unbind
app.post('/license/unbind', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const { licenseKey } = req.body || {};
  if (!licenseKey) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(licenseKey);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  db.prepare('UPDATE licenses SET boundTo=NULL,updatedAt=? WHERE key=?').run(nowIso(), licenseKey);
  audit('admin.unbind', licenseKey, lic.ownerId, null, ip, true);
  res.json({ success: true });
});

// License info
app.get('/license/info', adminLimiter, adminAuth, (req, res) => {
  const key = safe(req.query.key || req.query.licenseKey);
  if (!key) return res.status(400).json({ success: false, error: 'MISSING_KEY' });
  const lic = getLic(key, true);
  if (!lic) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
  const { secret, ...safe_lic } = lic;
  res.json({ success: true, license: safe_lic });
});

// Active trials
app.get('/trials/active', adminLimiter, adminAuth, (_, res) => {
  const rows = db.prepare("SELECT * FROM licenses WHERE trial=1 ORDER BY createdAt DESC").all();
  const trials = rows.map(r => normLicense(r, true)).filter(l => l && isActive(l))
    .map(l => {
      const dl = l.expiresAt ? Math.max(0, Math.ceil((new Date(l.expiresAt)-Date.now())/86400000)) : null;
      const { secret, ...safe_l } = l;
      return { ...safe_l, daysLeft: dl };
    });
  res.json({ success: true, count: trials.length, trials });
});

// Products list (admin)
app.get('/admin/products', adminLimiter, adminAuth, (_, res) => {
  const rows = db.prepare('SELECT id,name,description,type,price,hasCode,active,createdAt FROM products').all();
  res.json({ success: true, products: rows });
});

/* ================================================================
   CLIENT ROUTES — called by loader / bot
================================================================ */

// Validate license
app.post('/api/validate', validateLimiter, (req, res) => {
  const ip        = getIp(req);
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { licenseKey, identifier } = req.body || {};

  if (!licenseKey || !identifier || !timestamp || !signature)
    return res.status(400).json({ valid: false, error: 'missing_fields' });

  if (!freshTs(timestamp))
    return res.status(400).json({ valid: false, error: 'timestamp_expired' });

  const row = db.prepare('SELECT * FROM licenses WHERE key=?').get(licenseKey);
  if (!row) { audit('validate', licenseKey, null, { identifier }, ip, false, 'not_found'); return res.status(403).json({ valid: false, error: 'invalid_license' }); }

  const message = `${timestamp}:${licenseKey}:${identifier}`;
  if (!verifyHmac(message, row.secret, signature)) {
    audit('validate', licenseKey, row.ownerId, { identifier }, ip, false, 'bad_signature');
    return res.status(403).json({ valid: false, error: 'invalid_signature' });
  }

  const lic = normLicense(row, true);
  if (!isActive(lic)) {
    audit('validate', licenseKey, lic.ownerId, { identifier }, ip, false, lic.status);
    return res.status(403).json({ valid: false, error: 'license_' + lic.status });
  }

  // Bind on first use
  if (!lic.boundTo) {
    db.prepare('UPDATE licenses SET boundTo=?,lastSeen=?,updatedAt=? WHERE key=?').run(identifier, nowIso(), nowIso(), licenseKey);
  } else if (lic.boundTo !== identifier) {
    audit('validate', licenseKey, lic.ownerId, { identifier, expected: lic.boundTo }, ip, false, 'wrong_identifier');
    return res.status(403).json({ valid: false, error: 'license_bound_elsewhere' });
  } else {
    db.prepare('UPDATE licenses SET lastSeen=?,updatedAt=? WHERE key=?').run(nowIso(), nowIso(), licenseKey);
  }

  audit('validate', licenseKey, lic.ownerId, { identifier }, ip, true);
  res.json({ valid: true, plan: lic.tier, product: lic.product, productType: lic.productType, expires_at: lic.expiresAt });
});

// Fetch product code (loader endpoint)
app.post('/loader/fetch', loaderLimiter, (req, res) => {
  const ip        = getIp(req);
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { licenseKey, productId, identifier } = req.body || {};

  if (!licenseKey || !productId || !identifier || !timestamp || !signature)
    return res.status(400).json({ success: false, error: 'missing_fields' });

  if (!freshTs(timestamp, 90))
    return res.status(400).json({ success: false, error: 'timestamp_expired' });

  const row = db.prepare('SELECT * FROM licenses WHERE key=?').get(licenseKey);
  if (!row) { audit('loader.fetch', licenseKey, null, { productId, identifier }, ip, false, 'not_found'); return res.status(403).json({ success: false, error: 'invalid_license' }); }

  // Verify HMAC
  const message = `${timestamp}:${licenseKey}:${productId}:${identifier}`;
  if (!verifyHmac(message, row.secret, signature)) {
    audit('loader.fetch', licenseKey, row.ownerId, { productId, identifier }, ip, false, 'bad_signature');
    return res.status(403).json({ success: false, error: 'invalid_signature' });
  }

  const lic = normLicense(row, true);
  if (!isActive(lic)) {
    audit('loader.fetch', licenseKey, lic.ownerId, { productId }, ip, false, lic.status);
    return res.status(403).json({ success: false, error: 'license_' + lic.status });
  }

  // Verify correct product
  if (lic.product !== productId)
    return res.status(403).json({ success: false, error: 'product_mismatch' });

  // Check binding
  if (!lic.boundTo) {
    db.prepare('UPDATE licenses SET boundTo=?,lastSeen=?,updatedAt=? WHERE key=?').run(identifier, nowIso(), nowIso(), licenseKey);
  } else if (lic.boundTo !== identifier) {
    audit('loader.fetch', licenseKey, lic.ownerId, { identifier, expected: lic.boundTo }, ip, false, 'wrong_identifier');
    return res.status(403).json({ success: false, error: 'license_bound_elsewhere' });
  }

  // Get product code
  const product = db.prepare('SELECT * FROM products WHERE id=?').get(productId);
  if (!product) return res.status(404).json({ success: false, error: 'product_not_found' });
  if (!product.hasCode || !product.codeData)
    return res.status(503).json({ success: false, error: 'code_not_available' });

  let code;
  try {
    code = decryptCode({ iv: product.codeIv, tag: product.codeTag, data: product.codeData });
  } catch (e) {
    console.error('[LOADER] decrypt failed:', e.message);
    return res.status(500).json({ success: false, error: 'decrypt_failed' });
  }

  db.prepare('UPDATE licenses SET lastSeen=?,updatedAt=? WHERE key=?').run(nowIso(), nowIso(), licenseKey);
  audit('loader.fetch', licenseKey, lic.ownerId, { productId, identifier }, ip, true);

  res.json({ success: true, code, product: product.name, type: product.type, expires_at: lic.expiresAt });
});

// Heartbeat
app.post('/api/heartbeat', validateLimiter, (req, res) => {
  const ip        = getIp(req);
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { license_id, heartbeat_token } = req.body || {};

  if (!license_id || !heartbeat_token || !timestamp || !signature)
    return res.status(400).json({ alive: false, error: 'missing_fields' });

  if (!freshTs(timestamp))
    return res.status(400).json({ alive: false, error: 'timestamp_expired' });

  const record = db.prepare(`
    SELECT ht.token,ht.nonce,ht.expiresAt, l.status,l.secret
    FROM heartbeat_tokens ht JOIN licenses l ON l.key=ht.licenseKey
    WHERE ht.licenseKey=?
  `).get(license_id);

  if (!record) return res.status(403).json({ alive: false, error: 'not_registered' });

  const message = `${timestamp}:${license_id}:${heartbeat_token}:${record.nonce}`;
  if (!verifyHmac(message, record.secret, signature))
    return res.status(403).json({ alive: false, error: 'bad_signature' });

  if (!hexEq(record.token, heartbeat_token))
    return res.status(403).json({ alive: false, error: 'token_invalid' });

  if (new Date(record.expiresAt) < new Date())
    return res.status(403).json({ alive: false, error: 'token_expired' });

  if (record.status !== 'active' && record.status !== 'trial')
    return res.status(403).json({ alive: false, error: 'license_' + record.status });

  const nextToken  = genToken();
  const nextNonce  = genToken();
  const nextExpiry = new Date(Date.now() + 6 * 60000).toISOString();

  db.prepare('UPDATE heartbeat_tokens SET token=?,nonce=?,expiresAt=? WHERE licenseKey=?')
    .run(nextToken, nextNonce, nextExpiry, license_id);
  db.prepare('UPDATE licenses SET lastSeen=?,updatedAt=? WHERE key=?').run(nowIso(), nowIso(), license_id);

  res.json({ alive: true, next_token: nextToken, next_nonce: nextNonce, next_interval: 300 });
});

// Register heartbeat (first call after validate)
app.post('/api/heartbeat/register', validateLimiter, (req, res) => {
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { licenseKey, identifier } = req.body || {};

  if (!licenseKey || !identifier || !timestamp || !signature)
    return res.status(400).json({ success: false, error: 'missing_fields' });

  if (!freshTs(timestamp)) return res.status(400).json({ success: false, error: 'timestamp_expired' });

  const row = db.prepare('SELECT * FROM licenses WHERE key=?').get(licenseKey);
  if (!row) return res.status(403).json({ success: false, error: 'not_found' });

  const message = `${timestamp}:${licenseKey}:${identifier}`;
  if (!verifyHmac(message, row.secret, signature))
    return res.status(403).json({ success: false, error: 'bad_signature' });

  const lic = normLicense(row, true);
  if (!isActive(lic)) return res.status(403).json({ success: false, error: 'license_' + lic.status });

  const token  = genToken();
  const nonce  = genToken();
  const expiry = new Date(Date.now() + 6 * 60000).toISOString();

  db.prepare(`INSERT OR REPLACE INTO heartbeat_tokens(licenseKey,token,nonce,expiresAt) VALUES(?,?,?,?)`)
    .run(licenseKey, token, nonce, expiry);

  res.json({ success: true, token, nonce, interval: 300 });
});

/* ================================================================
   404 + ERROR
================================================================ */
app.use((req, res) => res.status(404).json({ success: false, error: 'NOT_FOUND', path: req.path }));
app.use((err, req, res, next) => {
  console.error('[ERR]', err);
  res.status(500).json({ success: false, error: 'INTERNAL_ERROR' });
});

/* ================================================================
   START
================================================================ */
app.listen(PORT, () => console.log(`[Dream Store] API + Dashboard running on :${PORT}`));
