// ====================================================
// server.js - 
// ====================================================
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// ==================== إعدادات البيئة ====================
const {
    MONGODB_URI,
    ADMIN_KEY,
    ENCRYPTION_KEY, // 32 حرفاً سداسي عشري
    PORT = 3000
} = process.env;

if (!MONGODB_URI || !ADMIN_KEY || !ENCRYPTION_KEY) {
    console.error('❌ متغيرات البيئة مفقودة!');
    process.exit(1);
}

// ==================== اتصال MongoDB ====================
mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB متصل'))
    .catch(err => console.error('❌ MongoDB خطأ:', err));

// ==================== نموذج الرخصة ====================
const licenseSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    ownerId: String,
    hwid: String,           // معرف الجهاز
    status: { type: String, default: 'active' },
    expiresAt: Date,
    lastSeen: Date,
    version: { type: String, default: '1.0.0' } // إصدار الكود المسلَّم
});

const License = mongoose.model('License', licenseSchema);

// ==================== دوال التشفير ====================
const algorithm = 'aes-256-gcm';
const ivLength = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(ivLength);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(encryptedText) {
    const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==================== تحميل كود البوت الأصلي ====================
let BOT_CODE = '';
try {
    // الكود الفعلي للبوت (مثلاً bot_source.js)
    BOT_CODE = fs.readFileSync(path.join(__dirname, 'bot_source.js'), 'utf8');
    console.log(`✅ تم تحميل كود البوت (${BOT_CODE.length} حرف)`);
} catch (err) {
    console.error('❌ فشل تحميل كود البوت:', err.message);
    process.exit(1);
}

// ==================== نقطة طلب الكود ====================
app.post('/request_code', async (req, res) => {
    const { licenseKey, hwid } = req.body;

    if (!licenseKey || !hwid) {
        return res.status(400).json({ error: 'بيانات ناقصة' });
    }

    const license = await License.findOne({ key: licenseKey });

    // 1. هل الرخصة موجودة؟
    if (!license) {
        return res.json({ success: false, reason: 'LICENSE_NOT_FOUND' });
    }

    // 2. هل الرخصة نشطة؟
    if (license.status !== 'active') {
        return res.json({ success: false, reason: `LICENSE_${license.status}` });
    }

    // 3. هل انتهت؟
    if (license.expiresAt && new Date() > license.expiresAt) {
        license.status = 'expired';
        await license.save();
        return res.json({ success: false, reason: 'LICENSE_EXPIRED' });
    }

    // 4. التحقق من HWID
    if (license.hwid && license.hwid !== hwid) {
        return res.json({ success: false, reason: 'HWID_MISMATCH' });
    }

    // 5. أول مرة: تسجيل HWID
    if (!license.hwid) {
        license.hwid = hwid;
    }

    license.lastSeen = new Date();
    await license.save();

    // 6. تشفير كود البوت
    const encryptedCode = encrypt(BOT_CODE);

    // 7. إرسال الكود المشفر
    res.json({
        success: true,
        encryptedCode,
        version: license.version || '1.0.0',
        expiresAt: license.expiresAt
    });
});

// ==================== نقطة إنشاء رخصة (للبوت الإداري) ====================
app.post('/admin/create', async (req, res) => {
    const { adminKey, ownerId, days = 30 } = req.body;

    if (adminKey !== ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const key = 'DREAM-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);

    const license = new License({
        key,
        ownerId,
        expiresAt,
        status: 'active'
    });

    await license.save();

    res.json({ success: true, licenseKey: key, expiresAt });
});

// ==================== نقطة الصحة ====================
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', version: '3.0.0-remote' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Remote Control Server يعمل على المنفذ ${PORT}`);
});
