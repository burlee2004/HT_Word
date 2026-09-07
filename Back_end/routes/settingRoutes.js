const express = require('express');
const router = express.Router();
const settingsStore = require('../services/settingsStore');

// CÀI ĐẶT HỆ THỐNG
router.get('/api/admin/settings', (req, res) => {
    res.json({ autoApprovePayOS: settingsStore.getAutoApprovePayOS() });
});

router.post('/api/admin/settings', (req, res) => {
    const { autoApprovePayOS } = req.body;
    if (typeof autoApprovePayOS === 'boolean') {
        settingsStore.setAutoApprovePayOS(autoApprovePayOS);
    }
    res.json({ success: true, autoApprovePayOS: settingsStore.getAutoApprovePayOS() });
});

module.exports = router;
