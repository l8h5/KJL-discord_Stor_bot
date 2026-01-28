// ملف واحد فقط! يستضيف على railway.app مجانًا
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// قاعدة بيانات بسيطة في الذاكرة
const licenses = {};

// مفتاح سري لتوقيع الطلبات
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key';

// 🔐 إنشاء توقيع للتحقق من الطلبات
function createSignature(data) {
    return crypto.createHmac('sha256', SECRET_KEY)
        .update(JSON.stringify(data))
        .digest('hex');
}

// 📝 نقطة نهاية التحقق
app.post('/verify', (req, res) => {
    const { licenseKey, botId, signature } = req.body;
    
    // التحقق من التوقيع
    const expectedSig = createSignature({ licenseKey, botId });
    if (signature !== expectedSig) {
        return res.json({ valid: false, reason: 'INVALID_SIGNATURE' });
    }
    
    // البحث عن الرخصة
    if (!licenses[licenseKey]) {
        return res.json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
    }
    
    const license = licenses[licenseKey];
    
    // التحقق من الصلاحية
    if (!license.active) {
        return res.json({ valid: false, reason: 'LICENSE_SUSPENDED' });
    }
    
    if (Date.now() > license.expiry) {
        return res.json({ valid: false, reason: 'LICENSE_EXPIRED' });
    }
    
    // الرخصة صالحة
    res.json({
        valid: true,
        expiry: license.expiry,
        tier: license.tier,
        features: license.features
    });
});

// 📋 نقطة نهاية إدارة الرخص (للبوت الأساسي)
app.post('/admin/create', (req, res) => {
    const { adminKey, days = 30, owner } = req.body;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const licenseKey = 'LIC-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const expiry = Date.now() + (days * 24 * 60 * 60 * 1000);
    
    licenses[licenseKey] = {
        key: licenseKey,
        owner,
        created: Date.now(),
        expiry,
        active: true,
        tier: 'premium',
        features: ['all']
    };
    
    res.json({
        licenseKey,
        expiry: new Date(expiry).toISOString(),
        days
    });
});

// تشغيل السيرفر
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ License server running on port ${PORT}`);
});