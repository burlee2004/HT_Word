require('dotenv').config();
const cryptoService = require('./services/cryptoService');

console.log('===============================================================');
console.log('🔒 KIỂM THỬ BỘ KHIÊN BẢO MẬT HỆ THỐNG HT WORK (SECURITY SUITE)');
console.log('===============================================================\n');

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

// 1. Kiểm thử module mã hóa AES-256-GCM
console.log('--- 1. Kiểm thử Mã hóa & Che mờ Dữ liệu nhạy cảm (CryptoService) ---');
const rawSecretData = '0987654321_STK_BIDV_NGUYEN_VAN_A';
const encrypted = cryptoService.encrypt(rawSecretData);
assert(encrypted && encrypted.includes(':') && encrypted !== rawSecretData, 'Mã hóa AES-256-GCM chuỗi nhạy cảm thành công');

const decrypted = cryptoService.decrypt(encrypted);
assert(decrypted === rawSecretData, 'Giải mã chuỗi AES-256-GCM khớp 100% với dữ liệu gốc');

const maskedBank = cryptoService.maskAccountNumber('1029384756');
assert(maskedBank === '******4756', `Che mờ số tài khoản ngân hàng chính xác (Kq: ${maskedBank})`);

const maskedPhone = cryptoService.maskPhoneNumber('0834779397');
assert(maskedPhone === '083****397', `Che mờ số điện thoại chính xác (Kq: ${maskedPhone})`);

const signature = cryptoService.signPayload({ amount: 500000, user_id: 'usr_123' });
assert(cryptoService.verifySignature({ amount: 500000, user_id: 'usr_123' }, signature), 'Xác thực chữ ký số HMAC-SHA256 toàn vẹn dữ liệu thành công');
assert(!cryptoService.verifySignature({ amount: 999999, user_id: 'usr_123' }, signature), 'Phát hiện can thiệp số tiền giả mạo (HMAC Signature Mismatch)');

// 2. Kiểm thử Anti-Bot & Scraper Filter
console.log('\n--- 2. Kiểm thử Chặn Bot & Scraper tự động (Anti-Bot) ---');
const { antiBotMiddleware, xssSanitizerMiddleware } = require('./services/securityMiddleware');

let botBlocked = false;
const fakeScraperReq = {
    headers: { 'user-agent': 'python-requests/2.31.0' },
    originalUrl: '/api/jobs',
    ip: '127.0.0.1',
    path: '/api/jobs'
};
const fakeRes = {
    status: (code) => ({
        json: (data) => {
            if (code === 403 && data.error.includes('Automated Scraper')) botBlocked = true;
        }
    })
};
antiBotMiddleware(fakeScraperReq, fakeRes, () => {});
assert(botBlocked, 'Chặn đứng Scraper python-requests tự động cào dữ liệu (HTTP 403 Forbidden)');

let validBrowserAllowed = false;
const fakeBrowserReq = {
    headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
    originalUrl: '/api/jobs',
    ip: '127.0.0.1',
    path: '/api/jobs'
};
antiBotMiddleware(fakeBrowserReq, fakeRes, () => { validBrowserAllowed = true; });
assert(validBrowserAllowed, 'Cho phép trình duyệt người dùng thật truy cập bình thường');

// 3. Kiểm thử XSS Input Sanitizer
console.log('\n--- 3. Kiểm thử Làm sạch mã độc XSS Injection ---');
const maliciousReq = {
    body: {
        title: 'Tuyển lập trình viên <script>alert("Hacked!")</script>',
        description: 'Mô tả dự án <img src="x" onerror="stealCookie()">',
        safeText: 'Dự án Node.js & React bình thường'
    }
};
xssSanitizerMiddleware(maliciousReq, {}, () => {});
assert(!maliciousReq.body.title.includes('<script>'), 'Loại bỏ hoàn toàn thẻ <script> độc hại');
assert(!maliciousReq.body.description.includes('onerror='), 'Loại bỏ thuộc tính sự kiện onerror tấn công XSS');
assert(maliciousReq.body.safeText === 'Dự án Node.js & React bình thường', 'Bảo toàn văn bản an toàn không bị ảnh hưởng');

console.log('\n===============================================================');
console.log(`🎉 KẾT QUẢ: VƯỢT QUA ${passedTests}/${totalTests} BÀI KIỂM THỬ BẢO MẬT!`);
console.log('===============================================================');
