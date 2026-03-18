// ====================================================
// server.js - نظام ترخيص محصن بأمان متعدد الطبقات
// ====================================================
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// ==================== 1. إعدادات الأمان الأساسية ====================
app.use(helmet()); // تأمين الرؤوس
app.use(express.json({ limit: '5kb' })); // تحديد حجم الطلبات

// تمكين CORS بشكل آمن
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGINS || '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, admin-key');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    next();
});

// ==================== 2. Rate Limiting متعدد المستويات ====================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 200, // حد عام
    message: { error: 'TOO_MANY_REQUESTS', message: 'طلبات كثيرة جداً، حاول لاحقاً' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', globalLimiter);

// حدود أشد للتحقق من الرخصة
const verifyLimiter = rateLimit({
    windowMs: 60 * 1000, // دقيقة واحدة
    max: 20, // 20 طلب في الدقيقة كحد أقصى
    message: { error: 'RATE_LIMIT', message: 'طلبات تحقق كثيرة جداً' },
});

// حدود أشد لنقاط الإدارة
const adminLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'ADMIN_RATE_LIMIT', message: 'طلبات إدارة كثيرة جداً' },
});

// ==================== 3. متغيرات البيئة ====================
const {
    MONGODB_URI,
    ADMIN_KEY,
    ENCRYPTION_KEY, // مفتاح لتشفير البيانات الحساسة (يجب أن يكون 32 حرفًا)
    NODE_ENV = 'development',
    PORT = 3000
} = process.env;

if (!MONGODB_URI || !ADMIN_KEY || !ENCRYPTION_KEY) {
    console.error('❌ متغيرات البيئة مفقودة!');
    process.exit(1);
}

// التحقق من قوة ADMIN_KEY
if (ADMIN_KEY.length < 16) {
    console.error('❌ ADMIN_KEY ضعيف جداً - يجب أن يكون 16 حرفًا على الأقل');
    process.exit(1);
}

// ==================== 4. دالة تشفير البيانات الحساسة ====================
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

// ==================== 5. الاتصال بقاعدة البيانات مع TLS ====================
const connectDB = async () => {
    try {
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            ssl: true, // إجباري لـ TLS
            retryWrites: true,
            retryReads: true,
            maxPoolSize: 10,
            minPoolSize: 2,
        });
        console.log('✅ MongoDB متصل بشكل آمن');
    } catch (error) {
        console.error('❌ فشل الاتصال بقاعدة البيانات:', error.message);
        process.exit(1);
    }
};
connectDB();

// ==================== 6. نموذج الرخصة مع تشفير HWID ====================
const licenseSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true, index: true },
    ownerId: { type: String, required: true, index: true },
    ownerName: String,
    encryptedHwid: String, // HWID مشفر
    status: {
        type: String,
        enum: ['active', 'suspended', 'expired', 'pending'],
        default: 'active',
        index: true
    },
    tier: { type: String, enum: ['basic', 'premium', 'enterprise', 'trial'], default: 'premium' },
    price: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' },
    createdAt: { type: Date, default: Date.now, index: true },
    expiresAt: { type: Date, required: true, index: true },
    lastVerified: Date,
    ipHistory: [String], // تسجيل عناوين IP للكشف عن النشاط المشبوه
    notes: String
}, { timestamps: true });

// دالة افتراضية للوصول إلى HWID بعد فك التشفير
licenseSchema.virtual('hwid').get(function() {
    if (!this.encryptedHwid) return null;
    return decrypt(this.encryptedHwid);
});

licenseSchema.virtual('hwid').set(function(value) {
    if (value) this.encryptedHwid = encrypt(value);
});

const License = mongoose.model('License', licenseSchema);

// ==================== 7. دوال مساعدة ====================
const generateLicenseKey = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let key = 'DREAM-';
    for (let i = 0; i < 12; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
        if ((i + 1) % 4 === 0 && i < 11) key += '-';
    }
    return key;
};

const verifyAdminKey = (req) => {
    const adminKey = req.headers['admin-key'] || req.body.adminKey;
    return bcrypt.compareSync(adminKey, ADMIN_KEY); // مقارنة آمنة
};

// تسجيل جميع الطلبات الإدارية
const logAdminAction = async (action, adminId, details) => {
    console.log(`[ADMIN] ${new Date().toISOString()} - ${action} by ${adminId}: ${details}`);
    // يمكن حفظ السجلات في قاعدة بيانات منفصلة
};

// ==================== 8. نقاط API مع التحقق من المدخلات ====================

// ----- نقطة الصحة -----
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '3.0.0-secure'
    });
});

// ----- التحقق من الرخصة -----
app.post('/verify',
    verifyLimiter,
    [
        body('licenseKey').isString().trim().isLength({ min: 10, max: 50 }),
        body('hwid').isString().trim().isLength({ min: 8, max: 64 }),
        body('timestamp').isInt({ min: Date.now() - 300000, max: Date.now() + 300000 }) // في حدود 5 دقائق
    ],
    async (req, res) => {
        // التحقق من صحة المدخلات
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ valid: false, reason: 'INVALID_INPUT', errors: errors.array() });
        }

        const { licenseKey, hwid, timestamp } = req.body;

        try {
            const license = await License.findOne({ key: licenseKey });

            if (!license) {
                return res.json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
            }

            // التحقق من الحالة
            if (license.status !== 'active') {
                return res.json({ valid: false, reason: `LICENSE_${license.status.toUpperCase()}` });
            }

            // التحقق من تاريخ الانتهاء
            if (license.expiresAt && new Date() > license.expiresAt) {
                license.status = 'expired';
                await license.save();
                return res.json({ valid: false, reason: 'LICENSE_EXPIRED' });
            }

            // التحقق من HWID
            if (license.encryptedHwid) {
                const storedHwid = license.hwid;
                if (storedHwid !== hwid) {
                    // تسجيل محاولة دخول من جهاز مختلف
                    console.warn(`⚠️ محاولة استخدام الرخصة ${licenseKey} من جهاز مختلف HWID: ${hwid}`);
                    return res.json({ valid: false, reason: 'HWID_MISMATCH' });
                }
            } else {
                // أول مرة: ربط HWID بالرخصة
                license.hwid = hwid;
            }

            // تسجيل IP الحالي
            const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            license.ipHistory = license.ipHistory || [];
            if (!license.ipHistory.includes(clientIp)) {
                license.ipHistory.push(clientIp);
                // إذا تغير IP كثيراً، قد يكون مشبوهاً
                if (license.ipHistory.length > 5) {
                    console.warn(`⚠️ تغير IP متكرر للرخصة ${licenseKey}`);
                }
            }

            license.lastVerified = new Date();
            await license.save();

            res.json({
                valid: true,
                expiresAt: license.expiresAt,
                tier: license.tier
            });

        } catch (error) {
            console.error('❌ خطأ في /verify:', error);
            res.status(500).json({ valid: false, reason: 'SERVER_ERROR' });
        }
    }
);

// ----- إنشاء رخصة جديدة (مع تحسينات أمان) -----
app.post('/admin/create',
    adminLimiter,
    [
        body('adminKey').isString().isLength({ min: 8 }),
        body('ownerId').isString().trim().isLength({ min: 5 }),
        body('days').optional().isInt({ min: 1, max: 365 }),
        body('tier').optional().isIn(['basic', 'premium', 'enterprise', 'trial'])
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'INVALID_INPUT', details: errors.array() });
        }

        const { adminKey, ownerId, days = 30, tier = 'premium' } = req.body;

        // التحقق من المفتاح الإداري بشكل آمن
        if (!verifyAdminKey({ headers: { 'admin-key': adminKey } })) {
            await logAdminAction('UNAUTHORIZED_CREATE', 'unknown', `محاولة إنشاء رخصة بمفتاح غير صالح`);
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }

        try {
            const licenseKey = generateLicenseKey();
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + days);

            const license = new License({
                key: licenseKey,
                ownerId,
                tier,
                expiresAt,
                status: 'active'
            });

            await license.save();

            await logAdminAction('CREATE', ownerId, `رخصة ${licenseKey} لمدة ${days} يوم`);

            res.json({
                success: true,
                licenseKey,
                expiresAt,
                tier
            });

        } catch (error) {
            console.error('❌ خطأ في /admin/create:', error);
            res.status(500).json({ error: 'SERVER_ERROR' });
        }
    }
);

// ----- تعليق الرخصة -----
app.post('/admin/suspend',
    adminLimiter,
    [
        body('adminKey').isString().isLength({ min: 8 }),
        body('licenseKey').isString().trim().isLength({ min: 10 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'INVALID_INPUT' });
        }

        const { adminKey, licenseKey } = req.body;

        if (!verifyAdminKey({ headers: { 'admin-key': adminKey } })) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }

        try {
            const license = await License.findOneAndUpdate(
                { key: licenseKey },
                { status: 'suspended' },
                { new: true }
            );

            if (!license) {
                return res.status(404).json({ error: 'LICENSE_NOT_FOUND' });
            }

            await logAdminAction('SUSPEND', license.ownerId, `تعليق الرخصة ${licenseKey}`);

            res.json({ success: true, message: 'تم تعليق الرخصة' });

        } catch (error) {
            res.status(500).json({ error: 'SERVER_ERROR' });
        }
    }
);

// ----- عرض الرخص مع فلترة -----
app.get('/admin/licenses',
    adminLimiter,
    async (req, res) => {
        const adminKey = req.headers['admin-key'] || req.query.adminKey;
        if (!verifyAdminKey({ headers: { 'admin-key': adminKey } })) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }

        try {
            const { filter = 'all', page = 1, limit = 20 } = req.query;
            const query = filter !== 'all' ? { status: filter } : {};

            const licenses = await License.find(query)
                .select('-encryptedHwid') // لا نرسل HWID المشفر أبداً
                .sort({ createdAt: -1 })
                .limit(Math.min(parseInt(limit), 100))
                .skip((parseInt(page) - 1) * parseInt(limit))
                .lean();

            const total = await License.countDocuments(query);

            res.json({
                success: true,
                licenses,
                total,
                page: parseInt(page),
                totalPages: Math.ceil(total / limit)
            });

        } catch (error) {
            res.status(500).json({ error: 'SERVER_ERROR' });
        }
    }
);

// ==================== 9. معالجة الأخطاء بشكل آمن ====================
app.use((err, req, res, next) => {
    console.error('🚨 خطأ غير معالج:', err.stack);
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'حدث خطأ غير متوقع' });
});

// 404 للمسارات غير الموجودة
app.use('*', (req, res) => {
    res.status(404).json({ error: 'NOT_FOUND', message: 'المسار غير موجود' });
});

// ==================== 10. بدء الخادم ====================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('=========================================');
    console.log(`🚀 خادم آمن يعمل على المنفذ ${PORT}`);
    console.log(`🔒 وضع الأمان: ${NODE_ENV === 'production' ? 'إنتاج' : 'تطوير'}`);
    console.log('=========================================');
});

// إغلاق آمن
process.on('SIGTERM', () => {
    console.log('🛑 استقبال SIGTERM، جاري الإغلاق...');
    server.close(() => {
        mongoose.connection.close(false, () => {
            console.log('✅ تم إغلاق الاتصالات');
            process.exit(0);
        });
    });
});

process.on('uncaughtException', (err) => {
    console.error('🚨 استثناء غير معالج:', err.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason) => {
    console.error('🚨 رفض غير معالج:', reason);
    process.exit(1);
});
