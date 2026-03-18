/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║ server.js                  ║
 * ╚══════════════════════════════════════════════════════════════╝
 ***/

// ─── المكتبات ─────────────────────────────────────────────────
const express    = require('express');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const Database   = require('better-sqlite3');
const {
  Client,
  GatewayIntentBits,
  SlashCommandBuilder,
  REST,
  Routes,
  EmbedBuilder,
  PermissionFlagsBits,
} = require('discord.js');

// ══════════════════════════════════════════════════════════════
//  [A] إعداد قاعدة البيانات
//  SQLite ملف واحد بسيط، Render يحفظه في /data إذا عرّفت Disk
// ══════════════════════════════════════════════════════════════
const db = new Database(process.env.DB_PATH || './licenses.db');

// إنشاء الجداول إذا لم تكن موجودة
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id          TEXT PRIMARY KEY,
    secret      TEXT NOT NULL,
    product     TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'basic',
    bound_to    TEXT DEFAULT NULL,
    expires_at  TEXT DEFAULT NULL,
    active      INTEGER DEFAULT 1,
    note        TEXT DEFAULT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    last_seen   TEXT DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS heartbeat_tokens (
    license_id  TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    expires_at  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id  TEXT,
    action      TEXT,
    identifier  TEXT,
    ip          TEXT,
    success     INTEGER,
    reason      TEXT,
    ts          TEXT DEFAULT (datetime('now'))
  );
`);

// ══════════════════════════════════════════════════════════════
//  [B] الإعدادات والمتغيرات العامة
// ══════════════════════════════════════════════════════════════
const PORT        = process.env.PORT || 3000;
const SALT        = process.env.SECRET_SALT || 'dev-salt-change-this';
const BOT_TOKEN   = process.env.BOT_TOKEN;
const ADMIN_GUILD = process.env.ADMIN_GUILD_ID;
const ADMIN_ROLE  = process.env.ADMIN_ROLE_ID;

// ══════════════════════════════════════════════════════════════
//  [C] دوال التشفير والتحقق
// ══════════════════════════════════════════════════════════════

/**
 * التحقق من التوقيع HMAC-SHA256
 *
 * المنطق: الكلاينت عنده SECRET الخاص بترخيصه.
 * يحسب: HMAC(timestamp + ":" + payload, secret)
 * ويرسل الناتج كـ signature في الـ headers.
 * الخادم يعيد نفس الحساب ويقارن بشكل آمن.
 * أي فرق ولو بحرف واحد = رفض فوري.
 */
function verifyHMAC(payload, timestamp, clientSecret, receivedSig) {
  const message  = `${timestamp}:${payload}`;
  const expected = crypto
    .createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');

  // timingSafeEqual يمنع Timing Attacks
  // (المهاجم لا يستطيع قياس وقت المقارنة لاكتشاف الفرق)
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected.padEnd(64)),
      Buffer.from(receivedSig.padEnd(64))
    );
  } catch {
    return false;
  }
}

/**
 * رفض أي طلب عمره أكثر من 45 ثانية
 * هذا يمنع Replay Attack: حتى لو اعترض أحد طلبك وحفظه،
 * لا يمكنه استخدامه بعد 45 ثانية من إرساله.
 */
function isTimestampFresh(ts) {
  const now  = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - parseInt(ts, 10));
  return diff <= 45;
}

/** توليد ID ترخيص بصيغة LIC-XXXX-XXXX */
function generateLicenseId() {
  const a = crypto.randomBytes(4).toString('hex').toUpperCase();
  const b = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `LIC-${a}-${b}`;
}

/** توليد Secret طويل للترخيص */
function generateSecret() {
  return crypto.randomBytes(32).toString('hex');
}

/** توليد توكن Heartbeat */
function generateHBToken() {
  return crypto.randomBytes(32).toString('hex');
}

/** تسجيل العملية في الـ Audit Log */
function audit(licenseId, action, identifier, ip, success, reason = null) {
  db.prepare(`
    INSERT INTO audit_log(license_id, action, identifier, ip, success, reason)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(licenseId, action, identifier, ip, success ? 1 : 0, reason);
}

// ══════════════════════════════════════════════════════════════
//  [D] إعداد خادم Express (HTTP API للعملاء)
// ══════════════════════════════════════════════════════════════
const app = express();
app.use(express.json());

// Rate Limiter: أقصى 10 محاولات تحقق في الدقيقة من نفس IP
const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { valid: false, error: 'rate_limit_exceeded' },
});

// ─────────────────────────────────────────────────────────────
//  نقطة [1]: POST /api/validate
//  يُستدعى من الكلاينت مرة واحدة عند الإقلاع
//
//  Headers المطلوبة:
//    X-Timestamp : الوقت الحالي بالثواني (Unix)
//    X-Signature : HMAC(timestamp + ":" + body, license_secret)
//    X-License-Id: معرّف الترخيص
//
//  Body:
//    { license_id, identifier }
//    identifier = معرّف فريد للجهاز (sv_licenseKey في FiveM أو guild_id في Discord)
// ─────────────────────────────────────────────────────────────
app.post('/api/validate', validateLimiter, (req, res) => {
  const ip        = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const { license_id, identifier } = req.body || {};

  // التحقق من وجود الحقول الأساسية
  if (!license_id || !identifier || !timestamp || !signature) {
    return res.status(400).json({ valid: false, error: 'missing_fields' });
  }

  // رفض الطلبات القديمة (منع Replay)
  if (!isTimestampFresh(timestamp)) {
    audit(license_id, 'validate', identifier, ip, false, 'stale_timestamp');
    return res.status(400).json({ valid: false, error: 'timestamp_expired' });
  }

  // جلب الترخيص من قاعدة البيانات
  const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(license_id);

  // لا نقول "not found" - نقول فقط "invalid" لمنع Enumeration
  if (!license) {
    audit(license_id, 'validate', identifier, ip, false, 'not_found');
    return res.status(403).json({ valid: false, error: 'invalid_license' });
  }

  // التحقق من التوقيع
  const payload = JSON.stringify({ license_id, identifier });
  if (!verifyHMAC(payload, timestamp, license.secret, signature)) {
    audit(license_id, 'validate', identifier, ip, false, 'bad_signature');
    return res.status(403).json({ valid: false, error: 'invalid_signature' });
  }

  // هل الترخيص ملغى؟
  if (!license.active) {
    audit(license_id, 'validate', identifier, ip, false, 'revoked');
    return res.status(403).json({ valid: false, error: 'license_revoked' });
  }

  // هل انتهت صلاحيته؟
  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    audit(license_id, 'validate', identifier, ip, false, 'expired');
    return res.status(403).json({ valid: false, error: 'license_expired' });
  }

  // التحقق من الربط (Binding)
  // أول استخدام → يُربط تلقائياً
  if (!license.bound_to) {
    db.prepare('UPDATE licenses SET bound_to = ?, last_seen = datetime("now") WHERE id = ?')
      .run(identifier, license_id);
  } else if (license.bound_to !== identifier) {
    // مرتبط بجهاز/سيرفر/جيلد آخر
    audit(license_id, 'validate', identifier, ip, false, 'wrong_identifier');
    return res.status(403).json({ valid: false, error: 'license_bound_to_another' });
  }

  // توليد Heartbeat Token (صالح 5 دقائق)
  const hbToken  = generateHBToken();
  const hbExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO heartbeat_tokens(license_id, token, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(license_id) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at
  `).run(license_id, hbToken, hbExpiry);

  db.prepare('UPDATE licenses SET last_seen = datetime("now") WHERE id = ?').run(license_id);
  audit(license_id, 'validate', identifier, ip, true);

  return res.json({
    valid:              true,
    plan:               license.plan,
    product:            license.product,
    heartbeat_token:    hbToken,
    heartbeat_interval: 240,        // أرسل نبضة كل 4 دقائق
    expires_at:         license.expires_at || null,
  });
});

// ─────────────────────────────────────────────────────────────
//  نقطة [2]: POST /api/heartbeat
//  الكلاينت يرسل هذا كل 4 دقائق لإثبات أنه لا يزال شرعياً
//  إذا انتهى التوكن أو تم إلغاء الرخصة → رفض → الكلاينت يتوقف
// ─────────────────────────────────────────────────────────────
app.post('/api/heartbeat', (req, res) => {
  const { license_id, heartbeat_token } = req.body || {};

  if (!license_id || !heartbeat_token) {
    return res.status(400).json({ alive: false, error: 'missing_fields' });
  }

  const record = db.prepare(`
    SELECT ht.token, ht.expires_at, l.active
    FROM heartbeat_tokens ht
    JOIN licenses l ON l.id = ht.license_id
    WHERE ht.license_id = ?
  `).get(license_id);

  if (!record) {
    return res.status(403).json({ alive: false, error: 'not_found' });
  }

  // مقارنة آمنة للتوكن
  let tokenMatch = false;
  try {
    tokenMatch = crypto.timingSafeEqual(
      Buffer.from(record.token.padEnd(64)),
      Buffer.from(heartbeat_token.padEnd(64))
    );
  } catch { tokenMatch = false; }

  // التوكن منتهي أو خاطئ
  if (!tokenMatch || new Date(record.expires_at) < new Date()) {
    return res.status(403).json({ alive: false, error: 'token_invalid' });
  }

  // الرخصة ملغاة (يمكنك إلغاؤها وتتوقف في أقصى 4 دقائق)
  if (!record.active) {
    return res.status(403).json({ alive: false, error: 'revoked' });
  }

  // ✓ كل شيء صحيح → جدّد التوكن (Token Rotation)
  const newToken  = generateHBToken();
  const newExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`
    UPDATE heartbeat_tokens SET token = ?, expires_at = ? WHERE license_id = ?
  `).run(newToken, newExpiry, license_id);

  db.prepare('UPDATE licenses SET last_seen = datetime("now") WHERE id = ?').run(license_id);

  return res.json({
    alive:         true,
    next_token:    newToken,
    next_interval: 240,
  });
});

// ─── صفحة بسيطة للتحقق أن الخادم شغّال ──────────────────────
app.get('/', (_, res) => res.json({ status: 'online', service: 'license-server' }));

// تشغيل الخادم
app.listen(PORT, () => console.log(`[HTTP] خادم الترخيص يعمل على منفذ ${PORT}`));

// ══════════════════════════════════════════════════════════════
//  [E] بوت Discord - واجهة الإدارة
//  هذا هو "الوسيط" الذي تستخدمه أنت لإنشاء وإدارة الرخص
//  يعمل في نفس العملية مع HTTP Server بدون أي مشكلة
// ══════════════════════════════════════════════════════════════

if (!BOT_TOKEN) {
  console.warn('[BOT] لم يتم تعريف BOT_TOKEN - بوت الإدارة لن يعمل');
} else {

  const discordClient = new Client({
    intents: [GatewayIntentBits.Guilds],
  });

  // ─── تعريف أوامر Slash ──────────────────────────────────────
  const commands = [
    new SlashCommandBuilder()
      .setName('license-create')
      .setDescription('إنشاء ترخيص جديد')
      .addStringOption(o => o
        .setName('product')
        .setDescription('نوع المنتج')
        .setRequired(true)
        .addChoices(
          { name: 'FiveM Script', value: 'fivem' },
          { name: 'Discord Bot',  value: 'discordbot' },
        ))
      .addStringOption(o => o
        .setName('plan')
        .setDescription('خطة الاشتراك')
        .setRequired(true)
        .addChoices(
          { name: 'Basic',      value: 'basic' },
          { name: 'Premium',    value: 'premium' },
          { name: 'Enterprise', value: 'enterprise' },
        ))
      .addIntegerOption(o => o
        .setName('days')
        .setDescription('مدة الصلاحية بالأيام (اتركه فارغاً للترخيص الدائم)'))
      .addStringOption(o => o
        .setName('note')
        .setDescription('ملاحظة (اسم العميل مثلاً)')),

    new SlashCommandBuilder()
      .setName('license-revoke')
      .setDescription('إلغاء ترخيص')
      .addStringOption(o => o
        .setName('id')
        .setDescription('معرّف الترخيص')
        .setRequired(true)),

    new SlashCommandBuilder()
      .setName('license-unbind')
      .setDescription('فك ربط الترخيص من الجهاز الحالي (لإعادة الاستخدام في جهاز آخر)')
      .addStringOption(o => o
        .setName('id')
        .setDescription('معرّف الترخيص')
        .setRequired(true)),

    new SlashCommandBuilder()
      .setName('license-info')
      .setDescription('عرض معلومات ترخيص')
      .addStringOption(o => o
        .setName('id')
        .setDescription('معرّف الترخيص')
        .setRequired(true)),

    new SlashCommandBuilder()
      .setName('license-list')
      .setDescription('عرض آخر 20 ترخيص'),
  ].map(c => c.toJSON());

  // ─── تسجيل الأوامر عند الاتصال ─────────────────────────────
  discordClient.once('ready', async () => {
    console.log(`[BOT] مسجّل كـ ${discordClient.user.tag}`);

    // تسجيل الـ Slash Commands في السيرفر المحدد فقط (فوري)
    try {
      const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
      await rest.put(
        Routes.applicationGuildCommands(discordClient.user.id, ADMIN_GUILD),
        { body: commands }
      );
      console.log('[BOT] تم تسجيل الأوامر بنجاح');
    } catch (err) {
      console.error('[BOT] فشل تسجيل الأوامر:', err.message);
    }
  });

  // ─── معالجة الأوامر ─────────────────────────────────────────
  discordClient.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    // التحقق من أن الأمر من السيرفر الصحيح
    if (interaction.guildId !== ADMIN_GUILD) return;

    // التحقق من الصلاحية عبر الرول
    const member = interaction.member;
    const hasRole = member?.roles?.cache?.has(ADMIN_ROLE);
    if (!hasRole) {
      return interaction.reply({
        content: '⛔ ليس لديك صلاحية استخدام هذا الأمر.',
        ephemeral: true,
      });
    }

    // ══════════════════════════════════════════════════
    //  أمر: إنشاء ترخيص جديد /license-create
    // ══════════════════════════════════════════════════
    if (interaction.commandName === 'license-create') {
      const product = interaction.options.getString('product');
      const plan    = interaction.options.getString('plan');
      const days    = interaction.options.getInteger('days');
      const note    = interaction.options.getString('note') || null;

      const id      = generateLicenseId();
      const secret  = generateSecret();
      const expires = days
        ? new Date(Date.now() + days * 86_400_000).toISOString()
        : null;

      db.prepare(`
        INSERT INTO licenses(id, secret, product, plan, expires_at, note)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, secret, product, plan, expires, note);

      const embed = new EmbedBuilder()
        .setTitle('✅ تم إنشاء الترخيص')
        .setColor(0x2ecc71)
        .addFields(
          { name: 'المعرّف (ID)',  value: `\`${id}\``,     inline: false },
          { name: 'المفتاح السري', value: `\`${secret}\``, inline: false },
          { name: 'المنتج',        value: product,          inline: true },
          { name: 'الخطة',         value: plan,             inline: true },
          { name: 'الصلاحية',      value: expires ? `${days} يوم` : 'دائم', inline: true },
          { name: 'ملاحظة',        value: note || '—',      inline: false },
        )
        .setFooter({ text: 'أرسل المعرّف والمفتاح للعميل — المفتاح لا يظهر مرة ثانية' })
        .setTimestamp();

      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ══════════════════════════════════════════════════
    //  أمر: إلغاء ترخيص /license-revoke
    // ══════════════════════════════════════════════════
    if (interaction.commandName === 'license-revoke') {
      const id = interaction.options.getString('id');
      const result = db.prepare('UPDATE licenses SET active = 0 WHERE id = ?').run(id);

      if (result.changes === 0) {
        return interaction.reply({ content: '❌ لم يتم العثور على الترخيص.', ephemeral: true });
      }

      return interaction.reply({
        content: `🚫 تم إلغاء الترخيص \`${id}\` — سيتوقف الكلاينت خلال أقصى 4 دقائق.`,
        ephemeral: true,
      });
    }

    // ══════════════════════════════════════════════════
    //  أمر: فك الربط /license-unbind
    // ══════════════════════════════════════════════════
    if (interaction.commandName === 'license-unbind') {
      const id = interaction.options.getString('id');
      const result = db.prepare('UPDATE licenses SET bound_to = NULL WHERE id = ?').run(id);

      if (result.changes === 0) {
        return interaction.reply({ content: '❌ لم يتم العثور على الترخيص.', ephemeral: true });
      }

      return interaction.reply({
        content: `🔓 تم فك ربط \`${id}\` — سيُربط بالجهاز الجديد في أول استخدام.`,
        ephemeral: true,
      });
    }

    // ══════════════════════════════════════════════════
    //  أمر: معلومات ترخيص /license-info
    // ══════════════════════════════════════════════════
    if (interaction.commandName === 'license-info') {
      const id = interaction.options.getString('id');
      const lic = db.prepare('SELECT * FROM licenses WHERE id = ?').get(id);

      if (!lic) {
        return interaction.reply({ content: '❌ الترخيص غير موجود.', ephemeral: true });
      }

      const statusEmoji = lic.active ? '🟢 فعّال' : '🔴 ملغى';
      const embed = new EmbedBuilder()
        .setTitle(`معلومات الترخيص`)
        .setColor(lic.active ? 0x2ecc71 : 0xe74c3c)
        .addFields(
          { name: 'المعرّف',     value: `\`${lic.id}\``,          inline: false },
          { name: 'المنتج',      value: lic.product,               inline: true },
          { name: 'الخطة',       value: lic.plan,                  inline: true },
          { name: 'الحالة',      value: statusEmoji,               inline: true },
          { name: 'مرتبط بـ',    value: lic.bound_to || '—',       inline: false },
          { name: 'تنتهي في',    value: lic.expires_at || 'دائم',  inline: true },
          { name: 'آخر ظهور',    value: lic.last_seen || '—',      inline: true },
          { name: 'ملاحظة',      value: lic.note || '—',           inline: false },
        )
        .setTimestamp();

      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ══════════════════════════════════════════════════
    //  أمر: قائمة الرخص /license-list
    // ══════════════════════════════════════════════════
    if (interaction.commandName === 'license-list') {
      const list = db.prepare(`
        SELECT id, product, plan, active, expires_at, last_seen, note
        FROM licenses ORDER BY created_at DESC LIMIT 20
      `).all();

      if (!list.length) {
        return interaction.reply({ content: 'لا توجد رخص بعد.', ephemeral: true });
      }

      // بناء جدول نصي مضغوط
      const rows = list.map(l => {
        const status = l.active ? '🟢' : '🔴';
        const plan   = l.plan.padEnd(10);
        const prod   = l.product.padEnd(10);
        const seen   = l.last_seen ? l.last_seen.substring(0, 10) : 'لم يُستخدم';
        return `${status} \`${l.id}\` | ${prod} | ${plan} | ${seen}`;
      }).join('\n');

      const embed = new EmbedBuilder()
        .setTitle(`آخر ${list.length} رخصة`)
        .setColor(0x3498db)
        .setDescription(rows)
        .setTimestamp();

      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
  });

  // تسجيل الدخول
  discordClient.login(BOT_TOKEN)
    .then(() => console.log('[BOT] تم تسجيل الدخول'))
    .catch(err => console.error('[BOT] فشل تسجيل الدخول:', err.message));
}
