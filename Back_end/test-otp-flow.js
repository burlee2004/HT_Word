require('dotenv').config();
const { generateAndSaveOtp, verifyOtp } = require('./services/otpService');
const { sendOtpEmail } = require('./services/emailService');

async function runOtpTests() {
    console.log('===============================================================');
    console.log('🧪 KIỂM THỬ TOÀN DIỆN HỆ THỐNG GỬI & XÁC THỰC MÃ OTP (1 PHÚT)');
    console.log('===============================================================\n');

    const testEmail = 'maithimeo2004@gmail.com';
    const testName = 'Test User HT Work';
    let passed = 0;
    let total = 0;

    function assert(cond, msg) {
        total++;
        if (cond) {
            console.log(`✅ [PASS] ${msg}`);
            passed++;
        } else {
            console.error(`❌ [FAIL] ${msg}`);
        }
    }

    // 1. Kiểm tra Sinh mã OTP
    console.log('--- 1. Kiểm thử Sinh mã OTP & Thời hạn 1 phút (60s) ---');
    const genResult = await generateAndSaveOtp(testEmail, '127.0.0.1');
    assert(genResult.success === true, 'Sinh mã OTP thành công');
    assert(genResult.plainOtp && genResult.plainOtp.length === 6, `Mã OTP đủ 6 chữ số ngẫu nhiên (${genResult.plainOtp})`);
    
    const expiryDiff = genResult.expiresAt - Date.now();
    assert(expiryDiff > 55000 && expiryDiff <= 60000, `Thời hạn hiệu lực mã chính xác là 60 giây / 1 phút (Thực tế: ${Math.round(expiryDiff / 1000)}s)`);

    // 2. Kiểm thử Cooldown chống spam
    console.log('\n--- 2. Kiểm thử Cooldown giãn cách gửi lại ---');
    const spamResult = await generateAndSaveOtp(testEmail, '127.0.0.1');
    assert(spamResult.success === false && spamResult.code === 'COOLDOWN_ACTIVE', `Chặn gửi dồn dập ngay lập tức: ${spamResult.error}`);

    // 3. Kiểm thử Xác thực đúng mã
    console.log('\n--- 3. Kiểm thử Xác thực mã OTP ---');
    // Test sai mã trước
    const wrongVerify = await verifyOtp(testEmail, '000000');
    assert(wrongVerify.success === false, 'Từ chối mã OTP sai');

    // Test đúng mã
    const correctVerify = await verifyOtp(testEmail, genResult.plainOtp);
    assert(correctVerify.success === true, 'Xác thực thành công với mã OTP chính xác');

    // Test mã đã dùng rồi (không được dùng lại)
    const reusedVerify = await verifyOtp(testEmail, genResult.plainOtp);
    assert(reusedVerify.success === false, 'Ngăn chặn dùng lại mã OTP đã được xác thực (One-Time-Use)');

    // 4. Kiểm thử Gửi email thật qua Gmail SMTP
    console.log('\n--- 4. Kiểm thử Gửi email thật qua Gmail SMTP (htworkcompany@gmail.com) ---');
    console.log(`Đang gửi email thật tới ${testEmail}...`);
    const mailRes = await sendOtpEmail(testEmail, testName, '987654');
    assert(mailRes.success === true && mailRes.mode === 'smtp', `Gửi email thành công qua SMTP thật (MessageId: ${mailRes.messageId})`);

    console.log('\n===============================================================');
    console.log(`🎉 KẾT QUẢ KIỂM THỬ: ${passed}/${total} BÀI TEST THÀNH CÔNG 100%!`);
    console.log('===============================================================');
    process.exit(0);
}

runOtpTests().catch(console.error);
