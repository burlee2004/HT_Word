const crypto = require('crypto');

// Khóa mã hóa chính (32 bytes cho AES-256-GCM)
const RAW_SECRET = process.env.ENCRYPTION_SECRET || process.env.SUPABASE_KEY || 'htwork_super_secret_encryption_key_2026';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(RAW_SECRET).digest();
const ALGORITHM = 'aes-256-gcm';

/**
 * Mã hóa chuỗi văn bản sử dụng AES-256-GCM (Chuẩn mã hóa xác thực cao nhất)
 * @param {string} text - Văn bản cần mã hóa (VD: số tài khoản ngân hàng, CCCD)
 * @returns {string} - Chuỗi mã hóa dạng iv:authTag:encryptedHex
 */
function encrypt(text) {
    if (!text || typeof text !== 'string') return text;
    try {
        const iv = crypto.randomBytes(12); // GCM khuyến nghị 12 bytes IV
        const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag().toString('hex');
        return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    } catch (err) {
        console.error('❌ [CryptoService] Lỗi mã hóa:', err.message);
        return text;
    }
}

/**
 * Giải mã chuỗi văn bản đã được mã hóa bằng AES-256-GCM
 * @param {string} cipherText - Chuỗi dạng iv:authTag:encryptedHex
 * @returns {string} - Văn bản gốc sau giải mã
 */
function decrypt(cipherText) {
    if (!cipherText || typeof cipherText !== 'string' || !cipherText.includes(':')) {
        return cipherText;
    }
    try {
        const parts = cipherText.split(':');
        if (parts.length !== 3) return cipherText;

        const [ivHex, authTagHex, encryptedHex] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error('❌ [CryptoService] Lỗi giải mã:', err.message);
        return cipherText;
    }
}

/**
 * Che mờ số tài khoản ngân hàng trên giao diện công khai
 * @param {string} accountNo - Số tài khoản (VD: '1029384756')
 * @returns {string} - '******4756'
 */
function maskAccountNumber(accountNo) {
    if (!accountNo) return '';
    const clean = accountNo.toString().trim();
    if (clean.length <= 4) return clean;
    const last4 = clean.slice(-4);
    return '*'.repeat(Math.max(4, clean.length - 4)) + last4;
}

/**
 * Che mờ số điện thoại
 * @param {string} phone - Số điện thoại (VD: '0834779397')
 * @returns {string} - '083****397'
 */
function maskPhoneNumber(phone) {
    if (!phone) return '';
    const clean = phone.toString().trim();
    if (clean.length < 8) return clean;
    return clean.slice(0, 3) + '****' + clean.slice(-3);
}

/**
 * Tạo Idempotency Key (Mã giao dịch chống lặp độc nhất)
 */
function generateIdempotencyKey() {
    return crypto.randomUUID();
}

/**
 * Tạo chữ ký HMAC-SHA256 để kiểm tra tính toàn vẹn của payload
 */
function signPayload(data, secret = RAW_SECRET) {
    const raw = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}

/**
 * Kiểm tra chữ ký HMAC
 */
function verifySignature(data, signature, secret = RAW_SECRET) {
    if (!data || !signature) return false;
    const expected = signPayload(data, secret);
    try {
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

module.exports = {
    encrypt,
    decrypt,
    maskAccountNumber,
    maskPhoneNumber,
    generateIdempotencyKey,
    signPayload,
    verifySignature
};
