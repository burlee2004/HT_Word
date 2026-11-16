const fs = require('fs');
const path = require('path');

const primarySettingsPath = path.join(__dirname, '..', 'data', 'system_settings.json');
const secondarySettingsPath = path.join(__dirname, '..', 'node_modules', '.cache', 'kgs work_data', 'system_settings.json');

function ensureDir(filePath) {
    try {
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch (e) {}
}

function loadSettings() {
    let settings = {
        autoApprovePayOS: true,
        autoApproveWithdraw: false,
        aiModerationEnabled: true,
        googleSheetWebhook: process.env.GOOGLE_SHEET_LOG_WEBHOOK || '',
        firebaseDbUrl: process.env.FIREBASE_DATABASE_URL || ''
    };

    for (const p of [primarySettingsPath, secondarySettingsPath]) {
        try {
            if (fs.existsSync(p)) {
                const raw = fs.readFileSync(p, 'utf-8');
                const parsed = JSON.parse(raw);
                settings = { ...settings, ...parsed };
                break;
            }
        } catch (e) {}
    }

    return settings;
}

let currentSettings = loadSettings();

function saveSettings() {
    for (const p of [primarySettingsPath, secondarySettingsPath]) {
        try {
            ensureDir(p);
            fs.writeFileSync(p, JSON.stringify(currentSettings, null, 2), 'utf-8');
        } catch (e) {}
    }
}

const settingsStore = {
    getAutoApprovePayOS: () => currentSettings.autoApprovePayOS,
    setAutoApprovePayOS: (val) => {
        currentSettings.autoApprovePayOS = Boolean(val);
        saveSettings();
        return currentSettings.autoApprovePayOS;
    },
    getAutoApproveWithdraw: () => currentSettings.autoApproveWithdraw,
    setAutoApproveWithdraw: (val) => {
        currentSettings.autoApproveWithdraw = Boolean(val);
        saveSettings();
        return currentSettings.autoApproveWithdraw;
    },
    getAiModerationEnabled: () => currentSettings.aiModerationEnabled !== false,
    setAiModerationEnabled: (val) => {
        currentSettings.aiModerationEnabled = Boolean(val);
        saveSettings();
        return currentSettings.aiModerationEnabled;
    },
    getGoogleSheetWebhook: () => currentSettings.googleSheetWebhook || process.env.GOOGLE_SHEET_LOG_WEBHOOK || '',
    setGoogleSheetWebhook: (url) => {
        currentSettings.googleSheetWebhook = (url || '').trim();
        saveSettings();
        return currentSettings.googleSheetWebhook;
    },
    getFirebaseDbUrl: () => currentSettings.firebaseDbUrl || process.env.FIREBASE_DATABASE_URL || '',
    setFirebaseDbUrl: (url) => {
        currentSettings.firebaseDbUrl = (url || '').trim().replace(/\/+$/, ''); // bỏ dấu / ở cuối nếu có
        saveSettings();
        return currentSettings.firebaseDbUrl;
    },
    getAllSettings: () => ({ ...currentSettings })
};

module.exports = settingsStore;
