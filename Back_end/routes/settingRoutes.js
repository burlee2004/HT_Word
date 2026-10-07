const express = require('express');
const router = express.Router();
const settingsStore = require('../services/settingsStore');

// CÀI ĐẶT HỆ THỐNG
router.get('/api/admin/settings', (req, res) => {
    res.json({ autoApprovePayOS: settingsStore.getAutoApprovePayOS(), autoApproveWithdraw: settingsStore.getAutoApproveWithdraw() });
});

router.post('/api/admin/settings', (req, res) => {
    const { autoApprovePayOS, autoApproveWithdraw } = req.body;
    if (typeof autoApprovePayOS === 'boolean') {
        settingsStore.setAutoApprovePayOS(autoApprovePayOS);
    }
    if (typeof autoApproveWithdraw === 'boolean') {
        settingsStore.setAutoApproveWithdraw(autoApproveWithdraw);
    }
    res.json({ success: true, autoApprovePayOS: settingsStore.getAutoApprovePayOS(), autoApproveWithdraw: settingsStore.getAutoApproveWithdraw() });
});

module.exports = router;
