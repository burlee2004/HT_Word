/**
 * HT Work - Two-Factor Authentication (2FA / TOTP) Service
 * Supports Google Authenticator, Microsoft Authenticator, Authy, etc.
 * Uses RFC 6238 TOTP standard via otplib & qrcode
 */

const otplib = require('otplib');
const qrcode = require('qrcode');

/**
 * Sinh mã bí mật Base32 ngẫu nhiên cho tài khoản
 * @returns {string} Base32 Secret Key (ví dụ: 'JBSWY3DPEHPK3PXP')
 */
function generateSecret() {
    return otplib.generateSecret();
}

/**
 * Tạo mã QR Code dạng Data URL và URI cho ứng dụng Authenticator
 * @param {string} email Email người dùng hiển thị trên Authenticator
 * @param {string} secret Mã bí mật Base32 (nếu không truyền sẽ tự sinh mới)
 * @returns {Promise<{ secret: string, uri: string, qrCode: string }>}
 */
async function generate2FASetup(email, existingSecret = null) {
    const secret = existingSecret || generateSecret();
    const cleanEmail = (email || 'user@htwork.id.vn').trim().toLowerCase();
    
    // Tạo chuẩn URI theo RFC 6238
    const uri = otplib.generateURI({
        secret,
        label: cleanEmail,
        issuer: 'HT Work'
    });

    // Tạo ảnh QR Code base64 Data URL sắc nét
    const qrCode = await qrcode.toDataURL(uri, {
        errorCorrectionLevel: 'M',
        margin: 2,
        scale: 6,
        color: {
            dark: '#0f172a',  // Màu đen than hiện đại
            light: '#ffffff'
        }
    });

    return {
        secret,
        uri,
        qrCode
    };
}

/**
 * Xác thực mã OTP 6 số do người dùng nhập từ Google Authenticator
 * Hỗ trợ độ trễ mạng/đồng hồ +/- 60 giây (tương đương 2 chu kỳ)
 * @param {string|number} token Mã 6 chữ số người dùng nhập
 * @param {string} secret Mã bí mật Base32 lưu trong DB
 * @returns {boolean}
 */
function verify2FAToken(token, secret) {
    if (!token || !secret) return false;
    const cleanToken = String(token).replace(/\s+/g, '').trim();
    if (!/^\d{6}$/.test(cleanToken)) return false;

    const now = Math.floor(Date.now() / 1000);
    // Kiểm tra cửa sổ dung sai thời gian: Hiện tại, lệch -30s, lệch +30s, lệch -60s, lệch +60s
    const offsets = [0, -30, 30, -60, 60];
    
    for (const offset of offsets) {
        try {
            const res = otplib.verifySync({
                token: cleanToken,
                secret: secret.trim(),
                epoch: now + offset
            });
            if (res && res.valid === true) {
                return true;
            }
        } catch (e) {
            // Tiếp tục kiểm tra offset tiếp theo
        }
    }
    return false;
}

module.exports = {
    generateSecret,
    generate2FASetup,
    verify2FAToken
};
