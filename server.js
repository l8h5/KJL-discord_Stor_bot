// ====================================================
// server.js - نظام ترخيص بوتات Discord - نسخة محسنة
// ====================================================

const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); // للحماية من الهجمات

const app = express();

// ==================== الإعدادات الأساسية ====================
app.use(express.json({ limit: '10kb' })); // تحديد حجم الطلبات للحماية

// تمكين الـ CORS للسماح بالاتصال من البوتات
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, admin-key');
    next();
});

// ==================== متغيرات البيئة ====================
const {
    MONGODB_URI,
    ADMIN_KEY,
    NODE_ENV = 'development',
    PORT = 3000
} = process.env;

if (!MONGODB_URI) {
    console.error('❌ متغير MONGODB_URI غير موجود!');
    process.exit(1);
}

if (!ADMIN_KEY) {
    console.error('❌ متغير ADMIN_KEY غير موجود!');
    process.exit(1);
}

// ==================== حماية من الهجمات (Rate Limiting) ====================
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // حد أقصى 100 طلب لكل IP
    message: { error: 'TOO_MANY_REQUESTS', message: 'طلبات كثيرة جداً، حاول لاحقاً' }
});
app.use('/api/', limiter); // تطبيق على جميع مسارات API

// ==================== الاتصال بقاعدة بيانات MongoDB ====================
let isConnected = false;

const connectDB = async () => {
    try {
        console.log('🔄 محاولة الاتصال بـ MongoDB...');
        
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            minPoolSize: 2,
            // إعدادات إضافية للاستقرار
            retryWrites: true,
            retryReads: true
        });
        
        isConnected = true;
        console.log('✅ اتصال MongoDB ناجح!');
        console.log(`📊 قاعدة البيانات: ${mongoose.connection.name}`);
        console.log(`📡 حالة الاتصال: متصل`);
        
        // الاستماع لأحداث الاتصال
        mongoose.connection.on('disconnected', () => {
            console.log('⚠️ انقطع اتصال MongoDB، محاولة إعادة الاتصال...');
            isConnected = false;
        });
        
        mongoose.connection.on('reconnected', () => {
            console.log('✅ تم إعادة الاتصال بـ MongoDB');
            isConnected = true;
        });
        
    } catch (error) {
        console.error('❌ فشل الاتصال بـ MongoDB:', error.message);
        console.log('⚠️ النظام سيعمل في وضع التخزين المؤقت');
        isConnected = false;
    }
};

// بدء الاتصال (لا ننتظر حتى يكتمل لنبدأ الخادم)
connectDB();

// ==================== نماذج البيانات ====================
const LicenseSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true, index: true },
    ownerId: { type: String, required: true, index: true },
    ownerName: String,
    email: String,
    status: { 
        type: String, 
        enum: ['active', 'suspended', 'expired', 'pending'],
        default: 'active',
        index: true
    },
    tier: { 
        type: String, 
        enum: ['basic', 'premium', 'enterprise', 'trial'],
        default: 'premium' 
    },
    price: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' },
    createdAt: { type: Date, default: Date.now, index: true },
    expiresAt: { type: Date, required: true, index: true },
    features: { type: [String], default: ['basic_access'] },
    lastVerified: Date,
    notes: String
});

// تجنب إعادة تعريف النموذج
const License = mongoose.models.License || mongoose.model('License', LicenseSchema);

// ==================== وظائف مساعدة ====================
const generateLicenseKey = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let key = 'Dream-';
    for (let i = 0; i < 12; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
        if ((i + 1) % 4 === 0 && i < 11) key += '-';
    }
    return key;
};

const verifyAdminKey = (req) => {
    const adminKey = req.headers['admin-key'] || req.body.adminKey;
    return adminKey === ADMIN_KEY;
};

// ==================== نقطة الصحة (Health Check) ====================
app.get('/health', async (req, res) => {
    const dbStatus = isConnected ? 'connected' : 'disconnected';
    const connectionState = mongoose.connection.readyState;
    
    const healthData = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '2.1.0',
        database: {
            status: dbStatus,
            connectionState,
            cached: !isConnected
        },
        server: {
            uptime: process.uptime(),
            memory: process.memoryUsage()
        },
        env: NODE_ENV
    };
    
    if (isConnected) {
        try {
            healthData.database.licenseCount = await License.countDocuments();
        } catch (err) {
            healthData.database.error = err.message;
        }
    }
    
    res.json(healthData);
});

// ==================== التحقق من الرخصة ====================
app.post('/verify', async (req, res) => {
    try {
        const { licenseKey, botId } = req.body;
        
        if (!licenseKey || !botId) {
            return res.status(400).json({ 
                valid: false, 
                reason: 'MISSING_DATA',
                message: 'مفتاح الرخصة ومعرف البوت مطلوبان' 
            });
        }
        
        // إذا كانت قاعدة البيانات غير متصلة، نستخدم التخزين المؤقت
        if (!isConnected) {
            return res.json({ 
                valid: true, 
                cached: true,
                expiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                message: 'تحقق مؤقت - قاعدة البيانات غير متصلة'
            });
        }
        
        const license = await License.findOne({ key: licenseKey }).lean();
        
        if (!license) {
            return res.json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
        }
        
        if (license.status !== 'active') {
            return res.json({ valid: false, reason: `LICENSE_${license.status.toUpperCase()}` });
        }
        
        if (new Date() > license.expiresAt) {
            // تحديث الحالة في الخلفية (لا ننتظر)
            License.updateOne({ key: licenseKey }, { status: 'expired' }).exec();
            return res.json({ valid: false, reason: 'LICENSE_EXPIRED' });
        }
        
        // تحديث وقت التحقق الأخير (لا ننتظر)
        License.updateOne({ key: licenseKey }, { lastVerified: new Date() }).exec();
        
        res.json({
            valid: true,
            expiry: license.expiresAt,
            tier: license.tier,
            features: license.features
        });
        
    } catch (error) {
        console.error('❌ خطأ في /verify:', error.message);
        res.status(500).json({ valid: false, reason: 'SERVER_ERROR' });
    }
});

// ==================== إنشاء رخصة جديدة (للإدارة) ====================
app.post('/admin/create', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ 
                error: 'DATABASE_NOT_CONNECTED',
                message: 'قاعدة البيانات غير متصلة حالياً، حاول لاحقاً' 
            });
        }
        
        const { ownerId, days = 30, price = 0, tier = 'premium', email, ownerName } = req.body;
        
        if (!ownerId) {
            return res.status(400).json({ error: 'MISSING_OWNER_ID' });
        }
        
        // توليد مفتاح فريد
        let licenseKey;
        let attempts = 0;
        const maxAttempts = 5;
        
        do {
            licenseKey = generateLicenseKey();
            attempts++;
            const existing = await License.findOne({ key: licenseKey });
            if (!existing) break;
        } while (attempts < maxAttempts);
        
        if (attempts === maxAttempts) {
            return res.status(500).json({ error: 'KEY_GENERATION_FAILED' });
        }
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);
        
        const features = {
            basic: ['basic_access'],
            premium: ['basic_access', 'premium_features', 'priority_support'],
            enterprise: ['basic_access', 'premium_features', 'priority_support', 'custom_integration']
        }[tier] || ['basic_access'];
        
        const license = new License({
            key: licenseKey,
            ownerId,
            ownerName: ownerName || `User-${ownerId.substring(0, 6)}`,
            email,
            tier,
            price,
            expiresAt,
            features,
            status: 'active'
        });
        
        await license.save();
        
        res.json({
            success: true,
            licenseKey,
            expiresAt: expiresAt.toISOString(),
            days,
            price,
            tier
        });
        
    } catch (error) {
        console.error('❌ خطأ في /admin/create:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR', message: error.message });
    }
});

// ==================== إنشاء رخصة تجريبية ====================
app.post('/trial/create', async (req, res) => {
    try {
        const { discordId, name } = req.body;
        
        if (!discordId) {
            return res.status(400).json({ error: 'MISSING_DISCORD_ID' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ error: 'DATABASE_NOT_CONNECTED' });
        }
        
        // التحقق من عدم وجود رخصة تجريبية نشطة
        const existing = await License.findOne({
            ownerId: discordId,
            tier: 'trial',
            status: 'active',
            expiresAt: { $gt: new Date() }
        });
        
        if (existing) {
            return res.status(400).json({ 
                error: 'TRIAL_ALREADY_ACTIVE',
                expiresAt: existing.expiresAt
            });
        }
        
        const trialKey = 'TRIAL-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);
        
        const trial = new License({
            key: trialKey,
            ownerId: discordId,
            ownerName: name || `Trial-${discordId.substring(0, 6)}`,
            tier: 'trial',
            status: 'active',
            price: 0,
            expiresAt,
            features: ['basic_access'],
            notes: 'رخصة تجريبية - 7 أيام'
        });
        
        await trial.save();
        
        res.json({
            success: true,
            licenseKey: trialKey,
            expiresAt: expiresAt.toISOString(),
            expiresIn: '7 أيام',
            downloadLink: 'https://your-site.com/trial-bot.zip'
        });
        
    } catch (error) {
        console.error('❌ خطأ في /trial/create:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR' });
    }
});

// ==================== عرض الرخص ====================
app.get('/licenses', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ error: 'DATABASE_NOT_CONNECTED' });
        }
        
        const filter = req.query.filter || 'all';
        const limit = Math.min(parseInt(req.query.limit) || 50, 100); // حد أقصى 100
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;
        
        const query = filter !== 'all' ? { status: filter } : {};
        
        const [licenses, total] = await Promise.all([
            License.find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            License.countDocuments(query)
        ]);
        
        res.json({
            success: true,
            count: licenses.length,
            total,
            page,
            totalPages: Math.ceil(total / limit),
            licenses
        });
        
    } catch (error) {
        console.error('❌ خطأ في /licenses:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR' });
    }
});

// ==================== تعليق الرخصة ====================
app.post('/license/suspend', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ error: 'DATABASE_NOT_CONNECTED' });
        }
        
        const { licenseKey } = req.body;
        
        const result = await License.findOneAndUpdate(
            { key: licenseKey },
            { 
                status: 'suspended',
                notes: `تم التعليق في: ${new Date().toISOString()}`
            },
            { new: true }
        );
        
        if (!result) {
            return res.status(404).json({ error: 'LICENSE_NOT_FOUND' });
        }
        
        res.json({
            success: true,
            license: {
                key: result.key,
                status: result.status,
                ownerId: result.ownerId
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في /license/suspend:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR' });
    }
});

// ==================== تجديد الرخصة ====================
app.post('/license/renew', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ error: 'DATABASE_NOT_CONNECTED' });
        }
        
        const { licenseKey, days = 30 } = req.body;
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);
        
        const result = await License.findOneAndUpdate(
            { key: licenseKey },
            { 
                expiresAt,
                status: 'active',
                notes: `تم التجديد في: ${new Date().toISOString()} لـ ${days} يوم`
            },
            { new: true }
        );
        
        if (!result) {
            return res.status(404).json({ error: 'LICENSE_NOT_FOUND' });
        }
        
        res.json({
            success: true,
            license: {
                key: result.key,
                expiresAt: result.expiresAt,
                status: result.status
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في /license/renew:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR' });
    }
});

// ==================== عرض الرخص التجريبية النشطة ====================
app.get('/trials/active', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        if (!isConnected) {
            return res.status(503).json({ error: 'DATABASE_NOT_CONNECTED' });
        }
        
        const trials = await License.find({
            tier: 'trial',
            status: 'active',
            expiresAt: { $gt: new Date() }
        }).sort({ expiresAt: 1 }).lean();
        
        const result = trials.map(trial => ({
            key: trial.key,
            ownerId: trial.ownerId,
            ownerName: trial.ownerName,
            expiresAt: trial.expiresAt,
            daysLeft: Math.ceil((trial.expiresAt - new Date()) / (1000 * 60 * 60 * 24))
        }));
        
        res.json({ success: true, count: result.length, trials: result });
        
    } catch (error) {
        console.error('❌ خطأ في /trials/active:', error.message);
        res.status(500).json({ error: 'SERVER_ERROR' });
    }
});

// ==================== معالجة الأخطاء ====================
app.use((req, res) => {
    res.status(404).json({ error: 'NOT_FOUND', message: 'المسار غير موجود' });
});

app.use((err, req, res, next) => {
    console.error('🚨 خطأ غير معالج:', err.stack);
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: 'حدث خطأ غير متوقع' });
});

// ==================== بدء الخادم ====================
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('=========================================');
    console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`);
    console.log(`🌍 البيئة: ${NODE_ENV}`);
    console.log(`🔗 رابط الصحة: /health`);
    console.log('=========================================');
});

// إغلاق الاتصال بقاعدة البيانات عند إيقاف الخادم
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
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 رفض غير معالج:', reason);
});
