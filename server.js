// server.js - النسخة الكاملة
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// 1. الاتصال بقاعدة البيانات
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ MongoDB Connected');
}).catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
});

// 2. نماذج البيانات
const LicenseSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    ownerId: String,
    ownerName: String,
    email: String,
    discordTag: String,
    status: { type: String, default: 'active' },
    tier: { type: String, default: 'premium' },
    price: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' },
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    features: [String],
    notes: String
});

const License = mongoose.model('License', LicenseSchema);

// 3. التحقق من المفتاح الإداري
const authMiddleware = (req, res, next) => {
    const adminKey = req.headers['admin-key'] || req.body.adminKey;
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// 4. نقاط API الأساسية
app.post('/verify', async (req, res) => {
    try {
        const { licenseKey, botId } = req.body;
        
        const license = await License.findOne({ key: licenseKey });
        if (!license) {
            return res.json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
        }
        
        if (license.status !== 'active') {
            return res.json({ valid: false, reason: `LICENSE_${license.status.toUpperCase()}` });
        }
        
        if (new Date() > license.expiresAt) {
            license.status = 'expired';
            await license.save();
            return res.json({ valid: false, reason: 'LICENSE_EXPIRED' });
        }
        
        res.json({
            valid: true,
            expiry: license.expiresAt,
            tier: license.tier,
            features: license.features || []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/admin/create', authMiddleware, async (req, res) => {
    try {
        const { ownerId, days = 30, price = 0, tier = 'premium', email } = req.body;
        
        const licenseKey = 'LIC-' + crypto.randomBytes(6).toString('hex').toUpperCase();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + days);
        
        const license = new License({
            key: licenseKey,
            ownerId,
            email,
            tier,
            price,
            expiresAt,
            features: tier === 'premium' ? ['all'] : ['basic']
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
        res.status(500).json({ error: error.message });
    }
});

// 5. نقاط API إضافية
app.get('/licenses', authMiddleware, async (req, res) => {
    try {
        const licenses = await License.find().sort({ createdAt: -1 });
        res.json({ success: true, count: licenses.length, licenses });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/license/suspend', authMiddleware, async (req, res) => {
    try {
        const { licenseKey } = req.body;
        await License.findOneAndUpdate(
            { key: licenseKey },
            { status: 'suspended' }
        );
        res.json({ success: true, message: 'License suspended' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ License Server running on port ${PORT}`);
    console.log(`🔗 Health Check: http://localhost:${PORT}/health`);
});
