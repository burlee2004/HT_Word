// Global admin settings store
global.autoApprovePayOS = true;
global.autoApproveWithdraw = false;
global.platformFeePercent = Number(process.env.PLATFORM_FEE_PERCENT || 10); // Mặc định 10% hoa hồng Escrow
global.urgentJobFee = Number(process.env.URGENT_JOB_FEE || 50000); // 50,000 Token phí Đẩy tin Tuyển gấp

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
    },
    getPlatformFeePercent: () => global.platformFeePercent,
    setPlatformFeePercent: (val) => {
        const num = Number(val);
        if (!isNaN(num) && num >= 0 && num <= 100) {
            global.platformFeePercent = num;
        }
        return global.platformFeePercent;
    },
    getUrgentJobFee: () => global.urgentJobFee,
    setUrgentJobFee: (val) => {
        const num = Number(val);
        if (!isNaN(num) && num >= 0) {
            global.urgentJobFee = num;
        }
        return global.urgentJobFee;
    }
};

module.exports = settingsStore;
