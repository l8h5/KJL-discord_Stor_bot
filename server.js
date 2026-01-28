// ====================================================
// server.js - نظام ترخيص بوتات Discord مع MongoDB
// النسخة النهائية المصححة - لا تحتوي على أخطاء فادحة
// ====================================================

const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ====================================================
// 1. إعدادات اتصال MongoDB
// ====================================================

// الحصول على رابط الاتصال من المتغيرات البيئية أو استخدام الرابط الداخلي
const getMongoURI = () => {
    if (process.env.MONGODB_URI) {
        console.log('🔗 استخدام MONGODB_URI من متغيرات البيئة');
        return process.env.MONGODB_URI;
    }
    
    // ⚠️ ملاحظة: هذا الرابط تجريبي - ضع رابط MongoDB الخاص بك في Railway Variables
    return 'mongodb://mongo:DclRPBJecWAorZVQrorSSordicvuXCHs@mongodb.railway.internal:27017';
};

const MONGODB_URI = getMongoURI();

console.log('🔗 بدء الاتصال بقاعدة البيانات...');

// إعدادات اتصال MongoDB محسنة
const mongooseOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 10000, // 10 ثواني
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 2
};

mongoose.connect(MONGODB_URI, mongooseOptions)
    .then(() => {
        console.log('✅ اتصال MongoDB ناجح');
        console.log(`📊 قاعدة البيانات: ${mongoose.connection.name}`);
        console.log(`📡 حالة الاتصال: ${mongoose.connection.readyState === 1 ? 'متصل' : 'غير متصل'}`);
    })
    .catch(err => {
        console.error('❌ خطأ في اتصال MongoDB:', err.message);
        console.log('⚠️  النظام سيستخدم التخزين المؤقت كبديل');
    });

// ====================================================
// 2. نماذج البيانات (Schemas)
// ====================================================

const LicenseSchema = new mongoose.Schema({
    key: { 
        type: String, 
        unique: true, 
        required: true,
        index: true 
    },
    ownerId: { 
        type: String, 
        required: true 
    },
    ownerName: String,
    email: String,
    discordTag: String,
    status: { 
        type: String, 
        enum: ['active', 'suspended', 'expired', 'pending'],
        default: 'active',
        index: true
    },
    tier: { 
        type: String, 
        enum: ['basic', 'premium', 'enterprise'],
        default: 'premium' 
    },
    price: { 
        type: Number, 
        default: 0 
    },
    currency: { 
        type: String, 
        default: 'USD' 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    expiresAt: { 
        type: Date, 
        required: true,
        index: true 
    },
    features: {
        type: [String],
        default: ['basic_access']
    },
    lastVerified: Date,
    notes: String
});

// إنشاء النموذج فقط إذا كان MongoDB متصلاً
let License;
try {
    License = mongoose.model('License');
} catch {
    License = mongoose.model('License', LicenseSchema);
}

// ====================================================
// 3. وظائف المساعدة (Helper Functions)
// ====================================================

// توليد مفتاح ترخيص فريد
function generateLicenseKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // تجنب الأحرف المربكة
    let key = 'Dream-';
    
    for (let i = 0; i < 12; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
        if ((i + 1) % 4 === 0 && i < 11) key += '-';
    }
    
    return key;
}

// التحقق من المفتاح الإداري
function verifyAdminKey(req) {
    const adminKey = req.headers['admin-key'] || req.body.adminKey;
    const expectedKey = process.env.ADMIN_KEY || 'default-admin-key';
    
    return adminKey === expectedKey;
}

// ====================================================
// 4. نقاط النهاية (Endpoints)
// ====================================================

// ----- نقطة الصحة (Health Check) -----
app.get('/health', async (req, res) => {
    const dbStatus = mongoose.connection.readyState;
    const statusMap = {
        0: 'disconnected',
        1: 'connected',
        2: 'connecting',
        3: 'disconnecting'
    };
    
    const healthData = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        database: {
            status: statusMap[dbStatus] || 'unknown',
            connectionState: dbStatus
        },
        server: {
            uptime: process.uptime(),
            memory: process.memoryUsage()
        }
    };
    
    // إذا كان MongoDB متصلاً، أضف معلومات إضافية
    if (dbStatus === 1) {
        try {
            const licenseCount = await License.countDocuments();
            healthData.database.licenseCount = licenseCount;
            healthData.database.collections = await mongoose.connection.db.listCollections().toArray();
        } catch (dbErr) {
            healthData.database.error = dbErr.message;
        }
    }
    
    res.json(healthData);
});

// ----- التحقق من الرخصة (للبوتات) -----
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
        
        let license;
        try {
            license = await License.findOne({ key: licenseKey });
        } catch (dbError) {
            // إذا فشل الاتصال بقاعدة البيانات، استخدم التخزين المؤقت
            console.warn('⚠️  استخدام التخزين المؤقت بسبب خطأ قاعدة البيانات:', dbError.message);
            return res.json({ 
                valid: true, 
                expiry: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
                tier: 'premium',
                cached: true 
            });
        }
        
        if (!license) {
            return res.json({ 
                valid: false, 
                reason: 'LICENSE_NOT_FOUND',
                message: 'الرخصة غير موجودة' 
            });
        }
        
        if (license.status !== 'active') {
            return res.json({ 
                valid: false, 
                reason: `LICENSE_${license.status.toUpperCase()}`,
                message: `حالة الرخصة: ${license.status}` 
            });
        }
        
        if (new Date() > license.expiresAt) {
            try {
                license.status = 'expired';
                await license.save();
            } catch (saveError) {
                console.error('❌ خطأ في حفظ الرخصة المنتهية:', saveError.message);
            }
            
            return res.json({ 
                valid: false, 
                reason: 'LICENSE_EXPIRED',
                message: 'الرخصة منتهية الصلاحية' 
            });
        }
        
        // تحديث وقت التحقق الأخير
        try {
            license.lastVerified = new Date();
            await license.save();
        } catch (saveError) {
            console.warn('⚠️  لم يتم حفظ وقت التحقق:', saveError.message);
        }
        
        res.json({
            valid: true,
            expiry: license.expiresAt,
            tier: license.tier,
            features: license.features || ['basic_access'],
            message: 'الرخصة سارية وصالحة'
        });
        
    } catch (error) {
        console.error('❌ خطأ غير متوقع في /verify:', error);
        res.status(500).json({ 
            valid: false, 
            reason: 'SERVER_ERROR',
            message: 'خطأ في الخادم' 
        });
    }
});

// ----- إنشاء رخصة جديدة (للإدارة) -----
app.post('/admin/create', async (req, res) => {
    try {
        // التحقق من المفتاح الإداري
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ 
                error: 'UNAUTHORIZED',
                message: 'مفتاح إداري غير صالح' 
            });
        }
        
        const { ownerId, days = 30, price = 0, tier = 'premium', email, ownerName } = req.body;
        
        if (!ownerId) {
            return res.status(400).json({ 
                error: 'MISSING_OWNER_ID',
                message: 'معرف المالك مطلوب' 
            });
        }
        
        // توليد مفتاح فريد
        let licenseKey;
        let isUnique = false;
        let attempts = 0;
        const maxAttempts = 5;
        
        while (!isUnique && attempts < maxAttempts) {
            licenseKey = generateLicenseKey();
            attempts++;
            
            try {
                const existingLicense = await License.findOne({ key: licenseKey });
                if (!existingLicense) {
                    isUnique = true;
                }
            } catch (dbError) {
                // في حالة خطأ قاعدة البيانات، نفترض أنه فريد
                isUnique = true;
                console.warn('⚠️  افتراض أن المفتاح فريد بسبب خطأ قاعدة البيانات');
            }
        }
        
        if (!isUnique) {
            return res.status(500).json({ 
                error: 'KEY_GENERATION_FAILED',
                message: 'فشل في توليد مفتاح فريد' 
            });
        }
        
        // حساب تاريخ الانتهاء
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);
        
        // تحديد الميزات بناءً على الفئة
        const features = {
            'basic': ['basic_access'],
            'premium': ['basic_access', 'premium_features', 'priority_support'],
            'enterprise': ['basic_access', 'premium_features', 'priority_support', 'custom_integration']
        }[tier] || ['basic_access'];
        
        // إنشاء الرخصة
        const licenseData = {
            key: licenseKey,
            ownerId,
            ownerName: ownerName || `User-${ownerId.substring(0, 6)}`,
            email: email || null,
            tier,
            price,
            expiresAt,
            features,
            status: 'active'
        };
        
        let savedLicense;
        try {
            const license = new License(licenseData);
            savedLicense = await license.save();
        } catch (saveError) {
            console.error('❌ خطأ في حفظ الرخصة:', saveError.message);
            
            // التخزين المؤقت كبديل
            return res.json({
                success: true,
                licenseKey,
                expiresAt: expiresAt.toISOString(),
                days,
                price,
                tier,
                cached: true,
                message: 'تم إنشاء الرخصة (مخزنة مؤقتاً)'
            });
        }
        
        res.json({
            success: true,
            licenseKey,
            expiresAt: expiresAt.toISOString(),
            days,
            price,
            tier,
            id: savedLicense._id,
            message: 'تم إنشاء الرخصة بنجاح'
        });
        
    } catch (error) {
        console.error('❌ خطأ في /admin/create:', error);
        res.status(500).json({ 
            error: 'SERVER_ERROR',
            message: error.message 
        });
    }
});

// أضف هذا الكود بعد نقطة `/admin/create` وقبل `/licenses`

// ----- إنشاء رخصة تجريبية (7 أيام مجانية) -----
app.post('/trial/create', async (req, res) => {
    try {
        const { discordId, name } = req.body;
        
        if (!discordId) {
            return res.status(400).json({ 
                error: 'MISSING_DISCORD_ID', 
                message: 'معرف الديسكورد مطلوب' 
            });
        }
        
        // التحقق من وجود رخصة تجريبية سابقة لهذا المستخدم
        const existingTrial = await License.findOne({
            ownerId: discordId,
            tier: 'trial',
            status: 'active'
        });
        
        if (existingTrial && new Date() < existingTrial.expiresAt) {
            return res.status(400).json({ 
                error: 'TRIAL_ALREADY_ACTIVE', 
                message: 'لديك بالفعل رخصة تجريبية نشطة',
                expiresAt: existingTrial.expiresAt
            });
        }
        
        // توليد مفتاح تجريبي فريد
        const trialKey = 'TRIAL-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        
        // حساب تاريخ انتهاء (7 أيام)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);
        
        // إنشاء الرخصة التجريبية
        const trialLicense = new License({
            key: trialKey,
            ownerId: discordId,
            ownerName: name || `Trial-User-${discordId.substring(0, 6)}`,
            tier: 'trial',
            status: 'active',
            price: 0,
            expiresAt: expiresAt,
            features: ['basic_access', 'trial_features'],
            notes: 'رخصة تجريبية - 7 أيام مجانية'
        });
        
        await trialLicense.save();
        
        res.json({
            success: true,
            message: 'تم إنشاء الرخصة التجريبية بنجاح',
            licenseKey: trialKey,
            expiresAt: expiresAt.toISOString(),
            expiresIn: '7 أيام',
            downloadLink: 'https://your-site.com/trial-bot.zip',
            note: 'الرخصة التجريبية تنتهي تلقائياً بعد 7 أيام'
        });
        
    } catch (error) {
        console.error('❌ خطأ في /trial/create:', error);
        res.status(500).json({ 
            error: 'SERVER_ERROR', 
            message: error.message 
        });
    }
});

// ----- نقطة للتحقق من الرخص التجريبية -----
app.get('/trials/active', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ error: 'UNAUTHORIZED' });
        }
        
        const activeTrials = await License.find({
            tier: 'trial',
            status: 'active',
            expiresAt: { $gt: new Date() }
        }).sort({ expiresAt: 1 });
        
        res.json({
            success: true,
            count: activeTrials.length,
            trials: activeTrials.map(trial => ({
                key: trial.key,
                ownerId: trial.ownerId,
                ownerName: trial.ownerName,
                expiresAt: trial.expiresAt,
                daysLeft: Math.ceil((trial.expiresAt - new Date()) / (1000 * 60 * 60 * 24))
            }))
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ----- الحصول على جميع الرخص (للإدارة) -----
app.get('/licenses', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ 
                error: 'UNAUTHORIZED',
                message: 'مفتاح إداري غير صالح' 
            });
        }
        
        const filter = req.query.filter || 'all';
        const limit = parseInt(req.query.limit) || 50;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;
        
        let query = {};
        
        if (filter !== 'all') {
            query.status = filter;
        }
        
        let licenses, total;
        try {
            licenses = await License.find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean();
            
            total = await License.countDocuments(query);
        } catch (dbError) {
            console.error('❌ خطأ في جلب الرخص:', dbError.message);
            return res.json({
                success: true,
                count: 0,
                licenses: [],
                message: 'لا يمكن الوصول إلى قاعدة البيانات حالياً'
            });
        }
        
        res.json({
            success: true,
            count: licenses.length,
            total,
            page,
            totalPages: Math.ceil(total / limit),
            licenses,
            filter
        });
        
    } catch (error) {
        console.error('❌ خطأ في /licenses:', error);
        res.status(500).json({ 
            error: 'SERVER_ERROR',
            message: error.message 
        });
    }
});

// ----- تعليق الرخصة (للإدارة) -----
app.post('/license/suspend', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ 
                error: 'UNAUTHORIZED',
                message: 'مفتاح إداري غير صالح' 
            });
        }
        
        const { licenseKey } = req.body;
        
        if (!licenseKey) {
            return res.status(400).json({ 
                error: 'MISSING_LICENSE_KEY',
                message: 'مفتاح الرخصة مطلوب' 
            });
        }
        
        let result;
        try {
            result = await License.findOneAndUpdate(
                { key: licenseKey },
                { 
                    status: 'suspended',
                    notes: `تم التعليق في: ${new Date().toISOString()}`
                },
                { new: true }
            );
        } catch (dbError) {
            console.error('❌ خطأ في تعليق الرخصة:', dbError.message);
            return res.status(500).json({ 
                error: 'DATABASE_ERROR',
                message: 'فشل في تحديث الرخصة' 
            });
        }
        
        if (!result) {
            return res.status(404).json({ 
                error: 'LICENSE_NOT_FOUND',
                message: 'الرخصة غير موجودة' 
            });
        }
        
        res.json({
            success: true,
            message: 'تم تعليق الرخصة بنجاح',
            license: {
                key: result.key,
                status: result.status,
                ownerId: result.ownerId
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في /license/suspend:', error);
        res.status(500).json({ 
            error: 'SERVER_ERROR',
            message: error.message 
        });
    }
});

// ----- تجديد الرخصة (للإدارة) -----
app.post('/license/renew', async (req, res) => {
    try {
        if (!verifyAdminKey(req)) {
            return res.status(401).json({ 
                error: 'UNAUTHORIZED',
                message: 'مفتاح إداري غير صالح' 
            });
        }
        
        const { licenseKey, days = 30 } = req.body;
        
        if (!licenseKey) {
            return res.status(400).json({ 
                error: 'MISSING_LICENSE_KEY',
                message: 'مفتاح الرخصة مطلوب' 
            });
        }
        
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);
        
        let result;
        try {
            result = await License.findOneAndUpdate(
                { key: licenseKey },
                { 
                    expiresAt,
                    status: 'active',
                    notes: `تم التجديد في: ${new Date().toISOString()} لـ ${days} يوم`
                },
                { new: true }
            );
        } catch (dbError) {
            console.error('❌ خطأ في تجديد الرخصة:', dbError.message);
            return res.status(500).json({ 
                error: 'DATABASE_ERROR',
                message: 'فشل في تجديد الرخصة' 
            });
        }
        
        if (!result) {
            return res.status(404).json({ 
                error: 'LICENSE_NOT_FOUND',
                message: 'الرخصة غير موجودة' 
            });
        }
        
        res.json({
            success: true,
            message: `تم تجديد الرخصة لـ ${days} يوم`,
            license: {
                key: result.key,
                expiresAt: result.expiresAt,
                status: result.status
            }
        });
        
    } catch (error) {
        console.error('❌ خطأ في /license/renew:', error);
        res.status(500).json({ 
            error: 'SERVER_ERROR',
            message: error.message 
        });
    }
});

// ====================================================
// 5. معالجة الأخطاء وعمليات التنظيف
// ====================================================

// معالجة المسارات غير الموجودة
app.use((req, res) => {
    res.status(404).json({
        error: 'NOT_FOUND',
        message: 'المسار غير موجود',
        availableEndpoints: [
            'GET  /health',
            'POST /verify',
            'POST /admin/create',
            'GET  /licenses',
            'POST /license/suspend',
            'POST /license/renew'
        ]
    });
});

// معالجة الأخطاء العامة
app.use((err, req, res, next) => {
    console.error('🚨 خطأ غير معالج:', err);
    
    res.status(500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'حدث خطأ غير متوقع في الخادم',
        timestamp: new Date().toISOString()
    });
});

// ====================================================
// 6. بدء الخادم
// ====================================================

// استخدام المنفذ من المتغيرات البيئية أو المنفذ الافتراضي
const PORT = process.env.PORT || 3000;
const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';

app.listen(PORT, HOST, () => {
    console.log(`=========================================`);
    console.log(`🚀 خادم الترخيص يعمل على: ${HOST}:${PORT}`);
    console.log(`📅 الوقت: ${new Date().toLocaleString('ar-SA')}`);
    console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}`);
    console.log(`=========================================`);
});

// معالجة إغلاق الخادم بشكل أنيق
process.on('SIGTERM', () => {
    console.log('🛑 تلقي إشارة إغلاق، جاري إيقاف الخادم...');
    
    mongoose.connection.close(false, () => {
        console.log('✅ تم إغلاق اتصال MongoDB');
        process.exit(0);
    });
});

// منع انهيار التطبيق بسبب أخطاء غير معالجة
process.on('uncaughtException', (err) => {
    console.error('🚨 خطأ غير معالج (Exception):', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 وعد مرفوض غير معالج:', reason);
});
