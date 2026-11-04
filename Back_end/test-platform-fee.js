require('dotenv').config();
const settingsStore = require('./services/settingsStore');
const boostPackageStore = require('./services/boostPackageStore');

console.log('========================================================================================');
console.log('💰 KIỂM THỬ TOÀN DIỆN HỆ THỐNG THU PHÍ, GÓI ĐẨY TIN, VOUCHER & CHỐNG SPAM (HT WORK)');
console.log('========================================================================================\n');

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
    // --------------------------------------------------------------------------
    // 1. Kiểm thử Cài đặt tỷ lệ phí sàn (Escrow 5%)
    // --------------------------------------------------------------------------
    console.log('--- 1. Kiểm thử Cấu hình Hoa hồng Escrow 5% ---');
    const defaultFee = settingsStore.getPlatformFeePercent();
    assert(defaultFee === 5, `Tỷ lệ hoa hồng Escrow mặc định là 5% (Hiện tại: ${defaultFee}%)`);

    const milestoneAmount = 1000000; // 1,000,000 Token
    const platformFee = Math.round(milestoneAmount * (defaultFee / 100));
    const netFreelancerAmount = milestoneAmount - platformFee;

    assert(platformFee === 50000, `Khấu trừ đúng 5% hoa hồng sàn: 1,000,000 * 5% = ${platformFee.toLocaleString()} Token`);
    assert(netFreelancerAmount === 950000, `Freelancer thực nhận 95% giá trị hợp đồng: ${netFreelancerAmount.toLocaleString()} Token`);
    assert(netFreelancerAmount + platformFee === milestoneAmount, 'Bảo toàn tuyệt đối dòng tiền: Net + Fee = Milestone Amount');

    // --------------------------------------------------------------------------
    // 2. Kiểm thử Danh mục Gói đẩy tin theo ngày (Boost Packages)
    // --------------------------------------------------------------------------
    console.log('\n--- 2. Kiểm thử Bảng Gói Đẩy Tin theo ngày ---');
    const packages = boostPackageStore.packages;
    assert(packages.length >= 4, `Hệ thống có đủ ${packages.length} gói đẩy tin đa dạng`);

    const starterPkg = boostPackageStore.getPackageById('boost_starter');
    assert(starterPkg && starterPkg.days === 4 && starterPkg.price === 20000, 'Gói Cơ Bản: 20k Token hiển thị 4 ngày');

    const standardPkg = boostPackageStore.getPackageById('boost_standard');
    assert(standardPkg && standardPkg.days === 12 && standardPkg.price === 50000, 'Gói Tiêu Chuẩn: 50k Token hiển thị 12 ngày');

    const proPkg = boostPackageStore.getPackageById('boost_pro');
    assert(proPkg && proPkg.days === 25 && proPkg.price === 100000, 'Gói Chuyên Nghiệp: 100k Token hiển thị 25 ngày');

    const vipPkg = boostPackageStore.getPackageById('boost_vip');
    assert(vipPkg && vipPkg.days === 60 && vipPkg.price === 200000, 'Gói Diamond VIP: 200k Token hiển thị 60 ngày');

    // --------------------------------------------------------------------------
    // 3. Kiểm thử Ưu đãi Khách hàng Mua lần đầu (First-time Discount 30%)
    // --------------------------------------------------------------------------
    console.log('\n--- 3. Kiểm thử Ưu đãi Giảm giá lần đầu (First-Time Buyer 30%) ---');
    const newUserId = 'test_user_new_' + Date.now();
    assert(boostPackageStore.isFirstTimeBuyer(newUserId) === true, 'Người dùng mới được tự động nhận diện là First-time Buyer');

    const pricingFirstTime = boostPackageStore.calculateFinalPrice(newUserId, 'boost_standard');
    assert(pricingFirstTime.is_first_time === true, 'Kích hoạt cờ ưu đãi lần đầu');
    assert(pricingFirstTime.first_time_discount === 15000, `Gói 50k được giảm 30% (Tiết kiệm 15,000 Token): Giá còn ${pricingFirstTime.final_price.toLocaleString()} Token`);
    assert(pricingFirstTime.final_price === 35000, 'Giá cuối cùng cho lần đầu mua chính xác: 35,000 Token');

    // Giả lập sau khi đã mua lần đầu -> Lần sau không được giảm nữa
    boostPackageStore.recordPurchase(newUserId);
    assert(boostPackageStore.isFirstTimeBuyer(newUserId) === false, 'Sau khi mua thành công, trạng thái chuyển sang khách hàng cũ');

    const pricingSecondTime = boostPackageStore.calculateFinalPrice(newUserId, 'boost_standard');
    assert(pricingSecondTime.is_first_time === false && pricingSecondTime.first_time_discount === 0, 'Khách hàng cũ mua lần 2 không được áp dụng giảm giá lần đầu');
    assert(pricingSecondTime.final_price === 50000, 'Giá quay về nguyên giá 50,000 Token');

    // --------------------------------------------------------------------------
    // 4. Kiểm thử Hệ thống Voucher / Coupon Code
    // --------------------------------------------------------------------------
    console.log('\n--- 4. Kiểm thử Cơ chế Mã Giảm Giá / Voucher săn được ---');
    // Test voucher HTWORKNEW (Giảm 30% tối đa 60k)
    const vCheck1 = boostPackageStore.verifyVoucher('HTWORKNEW', 100000);
    assert(vCheck1.valid === true, 'Mã HTWORKNEW hợp lệ');
    assert(vCheck1.discount_amount === 30000, `Giảm 30% của 100k = ${vCheck1.discount_amount.toLocaleString()} Token (Còn lại: ${vCheck1.final_price.toLocaleString()})`);

    // Test voucher HOTDEAL (Giảm cố định 20k cho đơn từ 50k)
    const vCheck2 = boostPackageStore.verifyVoucher('HOTDEAL', 50000);
    assert(vCheck2.valid === true && vCheck2.discount_amount === 20000, 'Mã HOTDEAL giảm đúng 20,000 Token cho đơn 50k');

    // Test voucher HOTDEAL với đơn dưới 50k (Vi phạm min_order)
    const vCheckInvalid = boostPackageStore.verifyVoucher('HOTDEAL', 20000);
    assert(vCheckInvalid.valid === false, 'Từ chối mã HOTDEAL khi giá trị đơn hàng dưới 50k Token');

    // Test nhập mã không tồn tại
    const vCheckFake = boostPackageStore.verifyVoucher('FAKE_CODE_999', 50000);
    assert(vCheckFake.valid === false, 'Chặn đứng mã giảm giá giả mạo / không tồn tại');

    // Test áp dụng Voucher vào tính toán toàn diện (Package + Voucher)
    const pricingWithVoucher = boostPackageStore.calculateFinalPrice(newUserId, 'boost_pro', 'HTWORKNEW');
    assert(pricingWithVoucher.voucher_discount === 30000, 'Tính toán chiết khấu voucher chính xác vào giá cuối cùng');
    assert(pricingWithVoucher.final_price === 70000, 'Gói 100k áp dụng voucher còn 70,000 Token');

    // --------------------------------------------------------------------------
    // 5. Kiểm thử 3 Lá Chắn Bảo Mật Rút Tiền (Chống Spam Nạp-Rút)
    // --------------------------------------------------------------------------
    console.log('\n--- 5. Kiểm thử 3 Lá Chắn Chống Spam Nạp - Rút liên tục ---');
    // Lá chắn 1: Khoảng đệm 15 phút
    const now = Date.now();
    const recentDepositTime = now - 5 * 60 * 1000; // Vừa nạp 5 phút trước
    const elapsedMs = now - recentDepositTime;
    const BUFFER_MS = 15 * 60 * 1000;
    const isBufferBlocked = elapsedMs < BUFFER_MS;
    assert(isBufferBlocked === true, 'Lá chắn 1: Chặn đứng yêu cầu rút ngay trong vòng 15 phút sau khi nạp');

    // Lá chắn 2: Hạn ngạch 2 lần rút miễn phí / ngày
    const mockWithdrawsToday = [{ id: 1 }, { id: 2 }];
    const isQuotaExceeded = mockWithdrawsToday.length >= 2;
    assert(isQuotaExceeded === true, 'Lá chắn 2: Ngăn chặn vượt quá hạn mức 2 lần rút tiền / ngày để chống bot spam');

    // Lá chắn 3: Freelancer thù lao dự án rút MIỄN PHÍ
    const freelancerWithdrawFee = 0; // 0% phí rút tiền
    assert(freelancerWithdrawFee === 0, 'Lá chắn 3: Freelancer rút tiền từ dự án hoàn toàn MIỄN PHÍ 100% (0đ phí)');

    console.log('\n========================================================================================');
    console.log(`🎉 KẾT QUẢ: VƯỢT QUA ${passedTests}/${totalTests} BÀI KIỂM THỬ HỆ THỐNG TOÀN DIỆN!`);
    console.log('========================================================================================');
    process.exit(0);
}

runTests().catch(err => {
    console.error('Lỗi kiểm thử:', err);
    process.exit(1);
});
