// Global admin settings store
global.autoApprovePayOS = true;

const settingsStore = {
    getAutoApprovePayOS: () => global.autoApprovePayOS,
    setAutoApprovePayOS: (val) => {
        global.autoApprovePayOS = Boolean(val);
        return global.autoApprovePayOS;
    }
};

module.exports = settingsStore;
