const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-kjl-secret-911456';
const DB_PATH = process.env.DB_PATH || './licenses.db';

const app = express();
const db = new DatabaseSync(DB_PATH);

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

/* ============================================================
   Utilities
============================================================ */

function nowIso() {
  return new Date().toISOString();
}

function getIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.trim()) {
    return xf.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

function safeString(v, fallback = '') {
  if (v === null || v === undefined) return fallback;
  return String(v);
}

function generateLicenseKey() {
  const a = crypto.randomBytes(4).toString('hex').toUpperCase();
  const b = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `KJL-${a}-${b}`;
}

function generateSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function canonicalize(params) {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join('&');
}

function timingSafeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b)) return false;
  if (a.length !== b.length) return false;

  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;

  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyHMAC(message, secret, signature) {
  if (
    typeof message !== 'string' ||
    typeof secret !== 'string' ||
    typeof signature !== 'string'
  ) {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  return timingSafeHexEqual(expected, signature);
}

function isTimestampFresh(ts) {
  const parsed = Number.parseInt(String(ts), 10);
  if (!Number.isFinite(parsed)) return false;

  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - parsed) <= 45;
}

function daysFromNow(days) {
  return new Date(Date.now() + Number(days) * 24 * 60 * 60 * 1000).toISOString();
}

function clampPage(v) {
  const n = Number.parseInt(String(v || '1'), 10);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

function clampLimit(v) {
  const n = Number.parseInt(String(v || '20'), 10);
  if (!Number.isFinite(n)) return 20;
  return Math.min(Math.max(n, 1), 100);
}

function adminAuth(req, res, next) {
  const key = req.headers['admin-key'];
  if (key !== ADMIN_KEY) {
    return res.status(401).json({ success: false, error: 'UNAUTHORIZED' });
  }
  return next();
}

function audit(action, licenseKey, ownerId, payload, ip, success, reason = null) {
  try {
    db.prepare(`
      INSERT INTO audit_log(action, licenseKey, ownerId, payload, ip, success, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      action,
      licenseKey || null,
      ownerId || null,
      payload ? JSON.stringify(payload) : null,
      ip || null,
      success ? 1 : 0,
      reason
    );
  } catch (err) {
    console.error('[AUDIT] failed:', err.message);
  }
}

function parseExpiry(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

function normalizeLicense(row, { reconcile = false } = {}) {
  if (!row) return null;

  const expiresDate = parseExpiry(row.expiresAt);
  const isExpired = expiresDate ? expiresDate.getTime() <= Date.now() : false;

  let status = row.status;
  if (status === 'active' && isExpired) {
    status = 'expired';
    if (reconcile) {
      db.prepare(`
        UPDATE licenses
        SET status = 'expired', updatedAt = ?
        WHERE key = ? AND status = 'active'
      `).run(nowIso(), row.key);
    }
  }

  return {
    key: row.key,
    ownerId: row.ownerId,
    ownerName: row.ownerName,
    product: row.product,
    tier: row.tier,
    status,
    price: Number(row.price || 0),
    currency: row.currency || 'USD',
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    expiresAt: row.expiresAt || null,
    trial: !!row.trial,
    notes: row.notes || null,
    boundTo: row.boundTo || null,
    lastSeen: row.lastSeen || null,
    secret: row.secret,
  };
}

function rowToLicense(row, opts) {
  return normalizeLicense(row, opts);
}

function getAllLicenses({ reconcile = false } = {}) {
  const rows = db.prepare(`SELECT * FROM licenses ORDER BY createdAt DESC`).all();
  return rows.map(r => rowToLicense(r, { reconcile })).filter(Boolean);
}

function getLicenseByKey(key, { reconcile = false } = {}) {
  const row = db.prepare(`SELECT * FROM licenses WHERE key = ?`).get(key);
  return rowToLicense(row, { reconcile });
}

function isActiveLicense(license) {
  if (!license) return false;
  if (license.status !== 'active' && license.status !== 'trial') return false;
  if (!license.expiresAt) return true;
  return new Date(license.expiresAt).getTime() > Date.now();
}

/* ============================================================
   Database init + migration
============================================================ */

try {
  db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS licenses (
      key         TEXT PRIMARY KEY,
      secret      TEXT NOT NULL,
      ownerId     TEXT NOT NULL,
      ownerName   TEXT DEFAULT NULL,
      product     TEXT NOT NULL DEFAULT 'discordbot',
      tier        TEXT NOT NULL DEFAULT 'premium',
      status      TEXT NOT NULL DEFAULT 'active', -- active | expired | suspended | pending | trial
      price       REAL NOT NULL DEFAULT 0,
      currency    TEXT NOT NULL DEFAULT 'USD',
      createdAt   TEXT NOT NULL DEFAULT (datetime('now')),
      updatedAt   TEXT NOT NULL DEFAULT (datetime('now')),
      expiresAt   TEXT DEFAULT NULL,
      trial       INTEGER NOT NULL DEFAULT 0,
      notes       TEXT DEFAULT NULL,
      boundTo     TEXT DEFAULT NULL,
      lastSeen    TEXT DEFAULT NULL
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
      licenseKey  TEXT DEFAULT NULL,
      ownerId     TEXT DEFAULT NULL,
      payload     TEXT DEFAULT NULL,
      ip          TEXT DEFAULT NULL,
      success     INTEGER NOT NULL DEFAULT 0,
      reason      TEXT DEFAULT NULL,
      ts          TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
} catch (err) {
  console.error('[DB] schema init failed:', err.message);
  process.exit(1);
}

/* ============================================================
   Middleware
============================================================ */

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'RATE_LIMITED' },
});

const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, error: 'RATE_LIMITED' },
});

/* ============================================================
   Health / root
============================================================ */

app.get('/', (_, res) => {
  res.json({ status: 'online', service: 'license-api', sqlite: 'node:sqlite' });
});

app.get('/health', (_, res) => {
  try {
    const licenseCount = db.prepare(`SELECT COUNT(*) AS c FROM licenses`).get().c || 0;
    const activeCount = db.prepare(`SELECT COUNT(*) AS c FROM licenses WHERE status = 'active'`).get().c || 0;
    const trialCount = db.prepare(`SELECT COUNT(*) AS c FROM licenses WHERE trial = 1`).get().c || 0;

    res.json({
      status: 'healthy',
      version: '1.0.0',
      timestamp: nowIso(),
      server: {
        uptime: process.uptime(),
      },
      database: {
        status: 'connected',
        licenseCount,
        activeCount,
        trialCount,
      },
    });
  } catch (err) {
    res.status(500).json({
      status: 'unhealthy',
      timestamp: nowIso(),
      error: err.message,
      database: {
        status: 'error',
      },
    });
  }
});

/* ============================================================
   Admin routes used by the bot
============================================================ */

app.post('/admin/create', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);

  const ownerId = safeString(req.body?.ownerId).trim();
  const ownerName = safeString(req.body?.ownerName).trim() || null;
  const days = Number(req.body?.days ?? 30);
  const price = Number(req.body?.price ?? 10);
  const tier = safeString(req.body?.tier).trim() || 'premium';
  const product = safeString(req.body?.product).trim() || 'discordbot';
  const currency = safeString(req.body?.currency).trim() || 'USD';
  const notes = req.body?.notes ? safeString(req.body.notes).trim() : null;

  if (!ownerId) {
    audit('admin.create', null, ownerId, req.body, ip, false, 'MISSING_OWNER');
    return res.status(400).json({ success: false, error: 'MISSING_OWNER_ID' });
  }

  if (!Number.isFinite(days) || days <= 0) {
    return res.status(400).json({ success: false, error: 'INVALID_DAYS' });
  }

  if (!Number.isFinite(price) || price < 0) {
    return res.status(400).json({ success: false, error: 'INVALID_PRICE' });
  }

  const licenseKey = generateLicenseKey();
  const secret = generateSecret();
  const expiresAt = days ? daysFromNow(days) : null;

  try {
    db.prepare(`
      INSERT INTO licenses (
        key, secret, ownerId, ownerName, product, tier, status,
        price, currency, createdAt, updatedAt, expiresAt, trial, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      licenseKey,
      secret,
      ownerId,
      ownerName,
      product,
      tier,
      'active',
      price,
      currency,
      nowIso(),
      nowIso(),
      expiresAt,
      0,
      notes
    );

    audit('admin.create', licenseKey, ownerId, { days, price, tier, product }, ip, true);

    return res.json({
      success: true,
      licenseKey,
      expiresAt,
      license: getLicenseByKey(licenseKey),
    });
  } catch (err) {
    console.error('[ADMIN CREATE] failed:', err.message);
    audit('admin.create', licenseKey, ownerId, req.body, ip, false, err.message);
    return res.status(500).json({ success: false, error: 'CREATE_FAILED' });
  }
});

app.post('/trial/create', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);

  const discordId = safeString(req.body?.discordId).trim();
  const name = safeString(req.body?.name).trim() || null;

  if (!discordId) {
    return res.status(400).json({ success: false, error: 'MISSING_DISCORD_ID' });
  }

  const existing = db.prepare(`
    SELECT *
    FROM licenses
    WHERE ownerId = ? AND trial = 1
    ORDER BY createdAt DESC
    LIMIT 1
  `).get(discordId);

  const existingLicense = rowToLicense(existing, { reconcile: true });
  if (existingLicense && isActiveLicense(existingLicense)) {
    return res.status(409).json({ success: false, error: 'TRIAL_ALREADY_ACTIVE' });
  }

  const licenseKey = generateLicenseKey();
  const secret = generateSecret();
  const expiresAt = daysFromNow(7);

  try {
    db.prepare(`
      INSERT INTO licenses (
        key, secret, ownerId, ownerName, product, tier, status,
        price, currency, createdAt, updatedAt, expiresAt, trial, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      licenseKey,
      secret,
      discordId,
      name,
      'discordbot',
      'trial',
      'active',
      0,
      'USD',
      nowIso(),
      nowIso(),
      expiresAt,
      1,
      'Trial license'
    );

    audit('trial.create', licenseKey, discordId, { name }, ip, true);

    return res.json({
      success: true,
      licenseKey,
      expiresAt,
      expiresIn: '7 days',
      license: getLicenseByKey(licenseKey),
    });
  } catch (err) {
    console.error('[TRIAL CREATE] failed:', err.message);
    audit('trial.create', licenseKey, discordId, req.body, ip, false, err.message);
    return res.status(500).json({ success: false, error: 'TRIAL_CREATE_FAILED' });
  }
});

app.get('/licenses', adminLimiter, adminAuth, (req, res) => {
  const page = clampPage(req.query.page);
  const limit = clampLimit(req.query.limit || 20);
  const filter = safeString(req.query.filter).toLowerCase() || 'active';

  const all = getAllLicenses({ reconcile: true });

  const filtered = all.filter((lic) => {
    if (filter === 'all') return true;
    if (filter === 'suspended') return lic.status === 'suspended';
    if (filter === 'expired') return lic.status === 'expired';
    if (filter === 'active') return lic.status === 'active' && isActiveLicense(lic);
    if (filter === 'trial') return lic.trial === true;
    return lic.status === filter;
  });

  const count = filtered.length;
  const totalPages = Math.max(1, Math.ceil(count / limit));
  const start = (page - 1) * limit;
  const licenses = filtered.slice(start, start + limit).map(({ secret, ...safe }) => safe);

  return res.json({
    success: true,
    count,
    page,
    totalPages,
    licenses,
  });
});

app.post('/license/suspend', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const licenseKey = safeString(req.body?.licenseKey).trim();

  if (!licenseKey) {
    return res.status(400).json({ success: false, error: 'MISSING_LICENSE_KEY' });
  }

  const lic = getLicenseByKey(licenseKey, { reconcile: true });
  if (!lic) {
    audit('license.suspend', licenseKey, null, req.body, ip, false, 'NOT_FOUND');
    return res.status(404).json({ success: false, error: 'LICENSE_NOT_FOUND' });
  }

  db.prepare(`
    UPDATE licenses
    SET status = 'suspended', updatedAt = ?
    WHERE key = ?
  `).run(nowIso(), licenseKey);

  audit('license.suspend', licenseKey, lic.ownerId, req.body, ip, true);

  return res.json({
    success: true,
    license: getLicenseByKey(licenseKey),
  });
});

app.post('/license/renew', adminLimiter, adminAuth, (req, res) => {
  const ip = getIp(req);
  const licenseKey = safeString(req.body?.licenseKey).trim();
  const days = Number(req.body?.days ?? 30);

  if (!licenseKey) {
    return res.status(400).json({ success: false, error: 'MISSING_LICENSE_KEY' });
  }

  if (!Number.isFinite(days) || days <= 0) {
    return res.status(400).json({ success: false, error: 'INVALID_DAYS' });
  }

  const lic = getLicenseByKey(licenseKey, { reconcile: true });
  if (!lic) {
    audit('license.renew', licenseKey, null, req.body, ip, false, 'NOT_FOUND');
    return res.status(404).json({ success: false, error: 'LICENSE_NOT_FOUND' });
  }

  const base = lic.expiresAt && new Date(lic.expiresAt).getTime() > Date.now()
    ? new Date(lic.expiresAt).getTime()
    : Date.now();

  const newExpiresAt = new Date(base + days * 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    UPDATE licenses
    SET status = 'active',
        expiresAt = ?,
        updatedAt = ?
    WHERE key = ?
  `).run(newExpiresAt, nowIso(), licenseKey);

  audit('license.renew', licenseKey, lic.ownerId, { days }, ip, true);

  return res.json({
    success: true,
    license: getLicenseByKey(licenseKey),
  });
});

app.get('/trials/active', adminLimiter, adminAuth, (req, res) => {
  const all = getAllLicenses({ reconcile: true });

  const trials = all
    .filter((lic) => lic.trial)
    .filter((lic) => lic.status === 'active' && isActiveLicense(lic))
    .map((lic) => {
      const expiresAt = new Date(lic.expiresAt);
      const daysLeft = Math.max(
        0,
        Math.ceil((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      );

      const { secret, ...safe } = lic;
      return {
        ...safe,
        daysLeft,
      };
    });

  return res.json({
    success: true,
    count: trials.length,
    trials,
  });
});

/* ============================================================
   Client validation API (original functionality kept)
============================================================ */

function buildValidatePayload(license_id, identifier) {
  return canonicalize({ license_id, identifier });
}

function buildHeartbeatPayload(license_id, heartbeat_token, nonce) {
  return canonicalize({ license_id, heartbeat_token, nonce });
}

app.post('/api/validate', validateLimiter, (req, res) => {
  const ip = getIp(req);
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { license_id, identifier } = req.body || {};

  if (!license_id || !identifier || !timestamp || !signature) {
    return res.status(400).json({ valid: false, error: 'missing_fields' });
  }

  if (!isTimestampFresh(timestamp)) {
    audit(license_id, 'validate', identifier, ip, false, 'stale_timestamp');
    return res.status(400).json({ valid: false, error: 'timestamp_expired' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(license_id);

  if (!license) {
    audit(license_id, 'validate', identifier, ip, false, 'not_found');
    return res.status(403).json({ valid: false, error: 'invalid_license' });
  }

  const message = `${timestamp}:${buildValidatePayload(license_id, identifier)}`;
  if (!verifyHMAC(message, license.secret, signature)) {
    audit(license_id, 'validate', identifier, ip, false, 'bad_signature');
    return res.status(403).json({ valid: false, error: 'invalid_signature' });
  }

  const normalized = rowToLicense(license, { reconcile: true });

  if (!normalized.status || normalized.status === 'suspended') {
    audit(license_id, 'validate', identifier, ip, false, 'revoked');
    return res.status(403).json({ valid: false, error: 'license_revoked' });
  }

  if (normalized.expiresAt && new Date(normalized.expiresAt) < new Date()) {
    audit(license_id, 'validate', identifier, ip, false, 'expired');
    return res.status(403).json({ valid: false, error: 'license_expired' });
  }

  if (!normalized.boundTo) {
    db.prepare(`
      UPDATE licenses
      SET boundTo = ?, lastSeen = ?, updatedAt = ?
      WHERE key = ?
    `).run(identifier, nowIso(), nowIso(), license_id);
  } else if (normalized.boundTo !== identifier) {
    audit(license_id, 'validate', identifier, ip, false, 'wrong_identifier');
    return res.status(403).json({ valid: false, error: 'license_bound_to_another' });
  }

  const hbToken = generateToken();
  const hbNonce = generateToken();
  const hbExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO heartbeat_tokens(licenseKey, token, nonce, expiresAt)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(licenseKey) DO UPDATE SET
      token = excluded.token,
      nonce = excluded.nonce,
      expiresAt = excluded.expiresAt
  `).run(license_id, hbToken, hbNonce, hbExpiry);

  db.prepare(`
    UPDATE licenses
    SET lastSeen = ?, updatedAt = ?
    WHERE key = ?
  `).run(nowIso(), nowIso(), license_id);

  audit(license_id, 'validate', identifier, ip, true);

  return res.json({
    valid: true,
    plan: normalized.tier,
    product: normalized.product,
    heartbeat_token: hbToken,
    heartbeat_nonce: hbNonce,
    heartbeat_interval: 240,
    expires_at: normalized.expiresAt || null,
  });
});

app.post('/api/heartbeat', (req, res) => {
  const ip = getIp(req);
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { license_id, heartbeat_token } = req.body || {};

  if (!license_id || !heartbeat_token || !timestamp || !signature) {
    return res.status(400).json({ alive: false, error: 'missing_fields' });
  }

  if (!isTimestampFresh(timestamp)) {
    return res.status(400).json({ alive: false, error: 'timestamp_expired' });
  }

  const record = db.prepare(`
    SELECT ht.token, ht.nonce, ht.expiresAt, l.status, l.secret
    FROM heartbeat_tokens ht
    JOIN licenses l ON l.key = ht.licenseKey
    WHERE ht.licenseKey = ?
  `).get(license_id);

  if (!record) {
    return res.status(403).json({ alive: false, error: 'not_found' });
  }

  const message = `${timestamp}:${buildHeartbeatPayload(
    license_id,
    heartbeat_token,
    record.nonce
  )}`;

  if (!verifyHMAC(message, record.secret, signature)) {
    return res.status(403).json({ alive: false, error: 'bad_signature' });
  }

  if (!timingSafeHexEqual(record.token, heartbeat_token)) {
    return res.status(403).json({ alive: false, error: 'token_invalid' });
  }

  if (new Date(record.expiresAt) < new Date()) {
    return res.status(403).json({ alive: false, error: 'token_expired' });
  }

  if (record.status !== 'active') {
    return res.status(403).json({ alive: false, error: 'revoked' });
  }

  const nextToken = generateToken();
  const nextNonce = generateToken();
  const nextExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`
    UPDATE heartbeat_tokens
    SET token = ?, nonce = ?, expiresAt = ?
    WHERE licenseKey = ?
  `).run(nextToken, nextNonce, nextExpiry, license_id);

  db.prepare(`
    UPDATE licenses
    SET lastSeen = ?, updatedAt = ?
    WHERE key = ?
  `).run(nowIso(), nowIso(), license_id);

  return res.json({
    alive: true,
    next_token: nextToken,
    next_nonce: nextNonce,
    next_interval: 240,
  });
});

/* ============================================================
   404 / error handlers
============================================================ */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'NOT_FOUND',
    path: req.path,
  });
});

app.use((err, req, res, next) => {
  console.error('[ERR]', err);
  res.status(500).json({
    success: false,
    error: 'INTERNAL_ERROR',
  });
});

/* ============================================================
   Start
============================================================ */

app.listen(PORT, () => {
  console.log(`[HTTP] License API running on port ${PORT}`);
});
