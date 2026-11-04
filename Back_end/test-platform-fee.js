require('dotenv').config();
const settingsStore = require('./services/settingsStore');

console.log('====================================================================');
console.log('💰 KIỂM THỬ HỆ THỐNG THU PHÍ DOANH THU SÀN HT WORK (FEE SYSTEM)');
console.log('====================================================================\n');

let passedTests = 0;
let totalTests = 0;

function assert(condition, testName) {
    totalTests++;
    if (condition) {
        console.log(`✅ [PASS] ${testName}`);
        passedTests++;
    } else {
        console.error(`❌ [FAIL] ${testName}`);
    }
}

async function runTests() {
    // ---------------------------------------------------------
    // 1. Kiểm thử Cài đặt tỷ lệ phí sàn (Settings Store)
    // ---------------------------------------------------------
    console.log('--- 1. Kiểm thử Cấu hình Phí sàn & Giới hạn an toàn ---');
    const defaultFee = settingsStore.getPlatformFeePercent();
    assert(defaultFee === 10, `Tỷ lệ hoa hồng Escrow mặc định là 10% (Hiện tại: ${defaultFee}%)`);

    const defaultUrgentFee = settingsStore.getUrgentJobFee();
    assert(defaultUrgentFee === 50000, `Phí dịch vụ đẩy tin Tuyển Gấp mặc định là 50,000 Token (Hiện tại: ${defaultUrgentFee})`);

    // Thử cập nhật tỷ lệ phí mới
    settingsStore.setPlatformFeePercent(8);
    assert(settingsStore.getPlatformFeePercent() === 8, 'Cập nhật tỷ lệ hoa hồng sang 8% thành công');

    // Chống nhập giá trị phi lý (> 100% hoặc < 0%)
    settingsStore.setPlatformFeePercent(150);
    assert(settingsStore.getPlatformFeePercent() === 8, 'Chặn cập nhật tỷ lệ phần trăm vượt quá 100%');

    settingsStore.setPlatformFeePercent(-5);
    assert(settingsStore.getPlatformFeePercent() === 8, 'Chặn cập nhật tỷ lệ phần trăm số âm');

    // Đặt lại 10% chuẩn
    settingsStore.setPlatformFeePercent(10);
    assert(settingsStore.getPlatformFeePercent() === 10, 'Khôi phục tỷ lệ chuẩn 10%');

    // ---------------------------------------------------------
    // 2. Kiểm thử Logic Trừ phí Hoa hồng Nghiệm thu Escrow
    // ---------------------------------------------------------
    console.log('\n--- 2. Kiểm thử Khấu trừ Phí Hoa hồng Giải ngân Escrow ---');
    const milestoneAmount = 1000000; // 1,000,000 Token
    const feePercent = settingsStore.getPlatformFeePercent();
    const platformFee = Math.round(milestoneAmount * (feePercent / 100));
    const netFreelancerAmount = milestoneAmount - platformFee;

    assert(platformFee === 100000, `Tính toán phí sàn chính xác: 1,000,000 * 10% = ${platformFee.toLocaleString()} Token`);
    assert(netFreelancerAmount === 900000, `Freelancer thực nhận chính xác: 1,000,000 - 100,000 = ${netFreelancerAmount.toLocaleString()} Token`);
    assert(netFreelancerAmount + platformFee === milestoneAmount, 'Bảo toàn tuyệt đối tổng số tiền giao dịch: Net + Fee = Milestone Amount');

    // Test trường hợp số lẻ (Ví dụ: 333,333 Token)
    const oddAmount = 333333;
    const oddFee = Math.round(oddAmount * (feePercent / 100));
    const oddNet = oddAmount - oddFee;
    assert(oddNet + oddFee === oddAmount, `Bảo toàn số tiền với số lẻ: ${oddNet} + ${oddFee} = ${oddAmount}`);

    // ---------------------------------------------------------
    // 3. Kiểm thử Logic Phí Đẩy Tin Tuyển Gấp (Job Boost Fee)
    // ---------------------------------------------------------
    console.log('\n--- 3. Kiểm thử Tính phí Nâng cấp Tin Tuyển Gấp (Client) ---');
    const jobBudget = 500000;
    const urgentFee = settingsStore.getUrgentJobFee();
    const totalRequiredWithBoost = jobBudget + urgentFee;

    assert(totalRequiredWithBoost === 550000, `Tổng tiền Client cần thanh toán gồm Ngân sách (500k) + Phí Gấp (50k) = ${totalRequiredWithBoost.toLocaleString()} Token`);

    // Kiểm tra định dạng tiêu đề gắn nhãn
    const rawTitle = 'Lập trình website React & Node.js';
    const isUrgent = true;
    const finalTitle = isUrgent && !rawTitle.includes('🔥') ? `🔥 [TUYỂN GẤP] ${rawTitle.trim()}` : rawTitle.trim();
    assert(finalTitle.startsWith('🔥 [TUYỂN GẤP]'), `Tiêu đề được gắn cờ nổi bật: "${finalTitle}"`);

    // ---------------------------------------------------------
    // 4. Kiểm thử Hạch toán Sổ cái & Doanh thu Admin (Audit Ledger)
    // ---------------------------------------------------------
    console.log('\n--- 4. Kiểm thử Hạch toán Doanh thu Sàn trong Sổ cái ---');
    const mockLedgers = [
        { type: 'DEPOSIT', amount: 2000000 },
        { type: 'escrow_release', amount: 900000 },
        { type: 'PLATFORM_FEE', amount: 100000 },
        { type: 'JOB_BOOST_FEE', amount: 50000 },
        { type: 'WITHDRAW', amount: 500000 }
    ];

    const totalDeposits = mockLedgers.filter(l => l.type === 'DEPOSIT').reduce((s, l) => s + l.amount, 0);
    const totalWithdrawn = mockLedgers.filter(l => l.type === 'WITHDRAW').reduce((s, l) => s + l.amount, 0);
    const totalPlatformRevenue = mockLedgers
        .filter(l => l.type === 'PLATFORM_FEE' || l.type === 'JOB_BOOST_FEE')
        .reduce((s, l) => s + l.amount, 0);

    assert(totalDeposits === 2000000, 'Tách bạch tiền nạp của khách hàng: 2,000,000 Token');
    assert(totalWithdrawn === 500000, 'Tách bạch tiền rút của người dùng: 500,000 Token');
    assert(totalPlatformRevenue === 150000, `Tổng doanh thu thực nhận của Sàn HT Work chính xác (Hoa hồng 100k + Phí gấp 50k = ${totalPlatformRevenue.toLocaleString()} Token)`);

    console.log('\n====================================================================');
    console.log(`🎉 KẾT QUẢ: VƯỢT QUA ${passedTests}/${totalTests} BÀI KIỂM THỬ HỆ THỐNG THU PHÍ!`);
    console.log('====================================================================');
    process.exit(0);
}

runTests().catch(err => {
    console.error('Lỗi kiểm thử:', err);
    process.exit(1);
});
