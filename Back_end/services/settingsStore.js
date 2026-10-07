// Global admin settings store
global.autoApprovePayOS = true;
global.autoApproveWithdraw = false;

const settingsStore = {
    getAutoApprovePayOS: () => global.autoApprovePayOS,
    setAutoApprovePayOS: (val) => {
        global.autoApprovePayOS = Boolean(val);
        return global.autoApprovePayOS;
    },
    getAutoApproveWithdraw: () => global.autoApproveWithdraw,
    setAutoApproveWithdraw: (val) => {
        global.autoApproveWithdraw = Boolean(val);
        return global.autoApproveWithdraw;
    }
};

module.exports = settingsStore;
