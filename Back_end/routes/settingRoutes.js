const express = require('express');
const router = express.Router();
const settingsStore = require('../services/settingsStore');

// CÀI ĐẶT HỆ THỐNG
router.get('/api/admin/settings', (req, res) => {
    res.json({
        autoApprovePayOS: settingsStore.getAutoApprovePayOS(),
        autoApproveWithdraw: settingsStore.getAutoApproveWithdraw(),
        platformFeePercent: settingsStore.getPlatformFeePercent(),
        urgentJobFee: settingsStore.getUrgentJobFee()
    });
});

router.post('/api/admin/settings', (req, res) => {
    const { autoApprovePayOS, autoApproveWithdraw, platformFeePercent, urgentJobFee } = req.body;
    if (typeof autoApprovePayOS === 'boolean') {
        settingsStore.setAutoApprovePayOS(autoApprovePayOS);
    }
    if (typeof autoApproveWithdraw === 'boolean') {
        settingsStore.setAutoApproveWithdraw(autoApproveWithdraw);
    }
    if (platformFeePercent !== undefined && !isNaN(Number(platformFeePercent))) {
        settingsStore.setPlatformFeePercent(platformFeePercent);
    }
    if (urgentJobFee !== undefined && !isNaN(Number(urgentJobFee))) {
        settingsStore.setUrgentJobFee(urgentJobFee);
    }
    res.json({
        success: true,
        autoApprovePayOS: settingsStore.getAutoApprovePayOS(),
        autoApproveWithdraw: settingsStore.getAutoApproveWithdraw(),
        platformFeePercent: settingsStore.getPlatformFeePercent(),
        urgentJobFee: settingsStore.getUrgentJobFee()
    });
});

module.exports = router;
