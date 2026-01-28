const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const app = express();

app.use(express.json());

// اتصال MongoDB
mongoose.connect(process.env.MONGODB_URI);

// النماذج
const License = mongoose.model('License', new mongoose.Schema({
    key: String, ownerId: String, ownerName: String, email: String,
    status: String, tier: String, price: Number, currency: String,
    createdAt: Date, expiresAt: Date, lastPaymentDate: Date,
    nextPaymentDate: Date, autoRenew: Boolean, invoiceCount: Number
}));

const Invoice = mongoose.model('Invoice', new mongoose.Schema({
    invoiceId: String, licenseKey: String, amount: Number, currency: String,
    status: String, paymentMethod: String, transactionId: String,
    dueDate: Date, paidAt: Date, createdAt: Date
}));

// نقاط API الرئيسية
app.post('/verify', async (req, res) => {
    const { licenseKey, botId, signature } = req.body;
    
    const license = await License.findOne({ key: licenseKey });
    if (!license) return res.json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
    if (license.status !== 'active') return res.json({ valid: false, reason: `LICENSE_${license.status.toUpperCase()}` });
    if (new Date() > license.expiresAt) {
        license.status = 'expired';
        await license.save();
        return res.json({ valid: false, reason: 'LICENSE_EXPIRED' });
    }
    
    res.json({ valid: true, expiry: license.expiresAt, tier: license.tier });
});

app.post('/admin/create', async (req, res) => {
    if (req.body.adminKey !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const licenseKey = 'KJL-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + (req.body.days || 30));
    
    const license = new License({
        key: licenseKey,
        ownerId: req.body.owner,
        status: 'active',
        tier: 'premium',
        price: req.body.price || 0,
        expiresAt: expiry,
        autoRenew: true,
        invoiceCount: 0
    });
    
    await license.save();
    res.json({ licenseKey, expiry: expiry.toISOString() });
});

// نقاط API جديدة
app.get('/licenses', async (req, res) => {
    if (req.headers['admin-key'] !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const filter = req.query.filter || 'all';
    let query = {};
    
    if (filter === 'active') query.status = 'active';
    if (filter === 'expired') query.status = 'expired';
    if (filter === 'suspended') query.status = 'suspended';
    
    const licenses = await License.find(query).sort({ createdAt: -1 });
    res.json({ licenses });
});

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

app.get('/stats', async (req, res) => {
    if (req.headers['admin-key'] !== process.env.ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const activeLicenses = await License.countDocuments({ status: 'active' });
    const expiredLicenses = await License.countDocuments({ status: 'expired' });
    const totalRevenue = await License.aggregate([
        { $group: { _id: null, total: { $sum: '$price' } } }
    ]);
    
    res.json({
        activeLicenses,
        expiredLicenses,
        totalRevenue: totalRevenue[0]?.total || 0,
        pendingPayments: await Invoice.countDocuments({ status: 'pending' })
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
