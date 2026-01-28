// ملف واحد فقط! يستضيف على railway.app مجانًا
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose'); // ⬅️ أضف هذا

const app = express();
app.use(express.json());

// 🔗 الاتصال بقاعدة البيانات MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/license_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ متصل بقاعدة البيانات MongoDB');
}).catch(err => {
    console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err);
});

// 📋 نموذج الرخصة في MongoDB
const licenseSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    ownerId: { type: String, required: true },
    ownerName: { type: String },
    email: { type: String },
    status: { 
        type: String, 
        enum: ['active', 'suspended', 'expired', 'pending_payment'],
        default: 'active'
    },
    tier: { 
        type: String, 
        enum: ['basic', 'premium', 'enterprise'],
        default: 'premium'
    },
    price: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' },
    paymentStatus: { type: String, default: 'paid' },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    lastPaymentDate: { type: Date },
    nextPaymentDate: { type: Date },
    autoRenew: { type: Boolean, default: true },
    invoiceCount: { type: Number, default: 0 }
});

const License = mongoose.model('License', licenseSchema);

// 📋 نموذج الفواتير
const invoiceSchema = new mongoose.Schema({
    invoiceId: { type: String, unique: true, required: true },
    licenseKey: { type: String, required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'USD' },
    status: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'refunded'],
        default: 'pending'
    },
    paymentMethod: { type: String },
    transactionId: { type: String },
    dueDate: { type: Date },
    paidAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const Invoice = mongoose.model('Invoice', invoiceSchema);

// 📋 إنشاء فاتورة جديدة
app.post('/invoice/create', async (req, res) => {
    const { adminKey, licenseKey, amount, dueDays = 7 } = req.body;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    try {
        // توليد رقم فاتورة فريد
        const invoiceId = 'INV-' + Date.now().toString().slice(-8) + 
                         '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + dueDays);
        
        const invoice = new Invoice({
            invoiceId,
            licenseKey,
            amount,
            currency: 'USD',
            status: 'pending',
            dueDate
        });
        
        await invoice.save();
        
        // تحديث الرخصة برقم الفاتورة
        await License.findOneAndUpdate(
            { key: licenseKey },
            { 
                status: 'pending_payment',
                nextPaymentDate: dueDate
            }
        );
        
        res.json({
            success: true,
            invoiceId,
            amount,
            dueDate: dueDate.toISOString(),
            licenseKey
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 📋 دفع فاتورة
app.post('/invoice/pay', async (req, res) => {
    const { invoiceId, paymentMethod = 'manual', transactionId } = req.body;
    
    try {
        const invoice = await Invoice.findOne({ invoiceId });
        if (!invoice) {
            return res.status(404).json({ error: 'Invoice not found' });
        }
        
        // تحديث حالة الفاتورة
        invoice.status = 'paid';
        invoice.paymentMethod = paymentMethod;
        invoice.transactionId = transactionId;
        invoice.paidAt = new Date();
        await invoice.save();
        
        // تجديد الرخصة
        const license = await License.findOne({ key: invoice.licenseKey });
        if (license) {
            // حساب تاريخ التجديد (30 يوم من الآن)
            const newExpiry = new Date();
            newExpiry.setDate(newExpiry.getDate() + 30);
            
            license.status = 'active';
            license.expiresAt = newExpiry;
            license.lastPaymentDate = new Date();
            license.nextPaymentDate = new Date(newExpiry);
            license.invoiceCount += 1;
            await license.save();
        }
        
        res.json({
            success: true,
            message: 'Payment processed successfully',
            invoiceId,
            newExpiry: license.expiresAt
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 📋 التحقق من الفواتير المستحقة
app.get('/invoice/check-due', async (req, res) => {
    try {
        const today = new Date();
        const threeDaysLater = new Date();
        threeDaysLater.setDate(today.getDate() + 3);
        
        // البحث عن الفواتير المستحقة خلال 3 أيام
        const dueInvoices = await Invoice.find({
            status: 'pending',
            dueDate: { $lte: threeDaysLater, $gte: today }
        }).populate('licenseKey');
        
        // البحث عن الرخص المتأخرة
        const overdueLicenses = await License.find({
            status: 'active',
            nextPaymentDate: { $lt: today }
        });
        
        res.json({
            dueInvoices: dueInvoices.length,
            overdueLicenses: overdueLicenses.length,
            details: {
                dueInvoices,
                overdueLicenses: overdueLicenses.map(l => ({
                    key: l.key,
                    ownerId: l.ownerId,
                    nextPaymentDate: l.nextPaymentDate
                }))
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
    const { licenseKey, botId, timestamp, signature } = req.body;
    
    const expectedSig = createSignature({ licenseKey, botId, timestamp }); 
    
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
