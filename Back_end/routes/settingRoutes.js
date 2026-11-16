const express = require('express');
const router = express.Router();
const settingsStore = require('../services/settingsStore');

// CÀI ĐẶT HỆ THỐNG
router.get('/api/admin/settings', (req, res) => {
    res.json({
        autoApprovePayOS: settingsStore.getAutoApprovePayOS(),
        autoApproveWithdraw: settingsStore.getAutoApproveWithdraw(),
        aiModerationEnabled: settingsStore.getAiModerationEnabled(),
        googleSheetWebhook: settingsStore.getGoogleSheetWebhook(),
        firebaseDbUrl: settingsStore.getFirebaseDbUrl()
    });
});

router.post('/api/admin/settings', (req, res) => {
    const { autoApprovePayOS, autoApproveWithdraw, aiModerationEnabled, googleSheetWebhook, firebaseDbUrl } = req.body || {};
    if (typeof autoApprovePayOS === 'boolean') {
        settingsStore.setAutoApprovePayOS(autoApprovePayOS);
    }
    if (typeof autoApproveWithdraw === 'boolean') {
        settingsStore.setAutoApproveWithdraw(autoApproveWithdraw);
    }
    if (typeof aiModerationEnabled === 'boolean') {
        settingsStore.setAiModerationEnabled(aiModerationEnabled);
    }
    if (typeof googleSheetWebhook === 'string') {
        settingsStore.setGoogleSheetWebhook(googleSheetWebhook);
    }
    if (typeof firebaseDbUrl === 'string') {
        settingsStore.setFirebaseDbUrl(firebaseDbUrl);
    }
    res.json({
        success: true,
        autoApprovePayOS: settingsStore.getAutoApprovePayOS(),
        autoApproveWithdraw: settingsStore.getAutoApproveWithdraw(),
        aiModerationEnabled: settingsStore.getAiModerationEnabled(),
        googleSheetWebhook: settingsStore.getGoogleSheetWebhook(),
        firebaseDbUrl: settingsStore.getFirebaseDbUrl()
    });
});

module.exports = router;
