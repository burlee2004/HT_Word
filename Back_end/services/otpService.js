const crypto = require('crypto');
const bcrypt = require('bcrypt');
const supabase = require('../config/supabase');
const { logEvent } = require('./auditLogger');

/**
 * In-Memory Cache Store cho OTP (Thread-Safe & Instant Access)
 * Key: email (lowercase)
 * Value: {
 *   email: string,
 *   otpHash: string,
 *   expiresAt: number (timestamp ms),
 *   lastSentAt: number (timestamp ms),
 *   sendCount: number,
 *   windowStart: number (timestamp ms),
 *   failedAttempts: number
 * }
 */
const otpMemoryStore = new Map();

// Cấu hình thời gian & giới hạn bảo mật
const OTP_CONFIG = {
    EXPIRATION_MS: 5 * 60 * 1000,      // 5 phút
    COOLDOWN_MS: 60 * 1000,           // 60 giây giãn cách giữa 2 lần gửi
    MAX_SENDS_PER_WINDOW: 3,          // Tối đa 3 lần gửi trong 15 phút
    WINDOW_MS: 15 * 60 * 1000,        // Khung thời gian 15 phút
    MAX_FAILED_ATTEMPTS: 3            // Tối đa 3 lần nhập sai -> vô hiệu hóa mã
};

/**
 * Tự động dọn dẹp các mã OTP đã quá hạn khỏi bộ nhớ RAM định kỳ
 */
setInterval(() => {
    const now = Date.now();
    for (const [email, record] of otpMemoryStore.entries()) {
        if (now > record.expiresAt + OTP_CONFIG.WINDOW_MS) {
            otpMemoryStore.delete(email);
        }
    }
}, 5 * 60 * 1000); // Dọn dẹp mỗi 5 phút

/**
 * 1. Tạo và lưu mã OTP bảo mật
 * @param {string} rawEmail - Địa chỉ email người nhận
 * @param {string} clientIp - Địa chỉ IP client (để audit log)
 */
async function generateAndSaveOtp(rawEmail, clientIp = '127.0.0.1') {
    if (!rawEmail || typeof rawEmail !== 'string') {
        throw new Error('Email không hợp lệ!');
    }

    const email = rawEmail.trim().toLowerCase();
    const now = Date.now();

    // Lấy bản ghi OTP hiện tại của email này nếu có
    const existing = otpMemoryStore.get(email);

    if (existing) {
        // Kiểm tra Cooldown 60s
        const elapsedSinceLastSent = now - existing.lastSentAt;
        if (elapsedSinceLastSent < OTP_CONFIG.COOLDOWN_MS) {
            const remainingSeconds = Math.ceil((OTP_CONFIG.COOLDOWN_MS - elapsedSinceLastSent) / 1000);
            return {
                success: false,
                code: 'COOLDOWN_ACTIVE',
                error: `Vui lòng chờ ${remainingSeconds} giây nữa trước khi yêu cầu gửi lại mã OTP.`,
                remainingSeconds
            };
        }

        // Kiểm tra Rate Limit (Tối đa 3 lần trong 15 phút)
        if (now - existing.windowStart < OTP_CONFIG.WINDOW_MS) {
            if (existing.sendCount >= OTP_CONFIG.MAX_SENDS_PER_WINDOW) {
                const waitMinutes = Math.ceil((OTP_CONFIG.WINDOW_MS - (now - existing.windowStart)) / 60000);
                return {
                    success: false,
                    code: 'RATE_LIMIT_EXCEEDED',
                    error: `Bạn đã yêu cầu gửi OTP quá 3 lần trong 15 phút. Vui lòng thử lại sau ${waitMinutes} phút.`
                };
            }
        }
    }

    // Tạo mã ngẫu nhiên 6 chữ số cryptographic an toàn
    const plainOtp = crypto.randomInt(100000, 1000000).toString();

    // Băm mã OTP bằng bcrypt trước khi lưu
    const saltRounds = 10;
    const otpHash = await bcrypt.hash(plainOtp, saltRounds);

    const windowStart = (existing && (now - existing.windowStart < OTP_CONFIG.WINDOW_MS)) 
        ? existing.windowStart 
        : now;

    const sendCount = (existing && (now - existing.windowStart < OTP_CONFIG.WINDOW_MS)) 
        ? existing.sendCount + 1 
        : 1;

    // Lưu vào Memory Store
    otpMemoryStore.set(email, {
        email,
        otpHash,
        expiresAt: now + OTP_CONFIG.EXPIRATION_MS,
        lastSentAt: now,
        sendCount,
        windowStart,
        failedAttempts: 0
    });

    // Cố gắng đồng bộ lưu trữ vào Supabase bảng otp_verifications nếu bảng đã tồn tại
    try {
        await supabase
            .from('otp_verifications')
            .upsert({
                email,
                otp_hash: otpHash,
                expires_at: new Date(now + OTP_CONFIG.EXPIRATION_MS).toISOString(),
                attempts: 0,
                status: 'pending',
                created_at: new Date().toISOString()
            }, { onConflict: 'email' });
    } catch (dbErr) {
        // Bỏ qua lỗi schema nếu bảng chưa được tạo, vì Memory Store đã đảm bảo chạy 100%
        console.warn(`[OTP Supabase Sync Notice]: ${dbErr.message || 'Chưa có bảng otp_verifications, dùng Memory Cache'}`);
    }

    console.log(`🔑 [OTP GENERATED] Email: ${email} | Cooldown: 60s | SendCount: ${sendCount}/3`);

    return {
        success: true,
        plainOtp,
        expiresAt: now + OTP_CONFIG.EXPIRATION_MS,
        cooldownSeconds: 60
    };
}

/**
 * 2. Xác thực mã OTP người dùng nhập vào
 * @param {string} rawEmail - Địa chỉ email
 * @param {string} inputOtp - Mã OTP 6 chữ số người dùng nhập
 */
async function verifyOtp(rawEmail, inputOtp) {
    if (!rawEmail || !inputOtp) {
        return { success: false, error: 'Vui lòng cung cấp email và mã OTP đầy đủ!' };
    }

    const email = rawEmail.trim().toLowerCase();
    const cleanOtp = inputOtp.toString().trim();
    const now = Date.now();

    const record = otpMemoryStore.get(email);

    if (!record) {
        return { 
            success: false, 
            code: 'OTP_NOT_FOUND',
            error: 'Không tìm thấy yêu cầu xác thực OTP hoặc mã đã hết hạn. Vui lòng bấm gửi mã mới.' 
        };
    }

    // Kiểm tra quá hạn 5 phút
    if (now > record.expiresAt) {
        otpMemoryStore.delete(email);
        return { 
            success: false, 
            code: 'OTP_EXPIRED',
            error: 'Mã OTP đã hết hiệu lực (quá 5 phút). Vui lòng yêu cầu gửi mã mới.' 
        };
    }

    // Kiểm tra số lần thử sai
    if (record.failedAttempts >= OTP_CONFIG.MAX_FAILED_ATTEMPTS) {
        otpMemoryStore.delete(email);
        return { 
            success: false, 
            code: 'MAX_ATTEMPTS_EXCEEDED',
            error: 'Bạn đã nhập sai OTP quá 3 lần. Mã đã bị hủy để bảo mật tài khoản, vui lòng yêu cầu mã mới.' 
        };
    }

    // So khớp mã băm bằng bcrypt
    const isMatch = await bcrypt.compare(cleanOtp, record.otpHash);

    if (!isMatch) {
        record.failedAttempts += 1;
        const remaining = OTP_CONFIG.MAX_FAILED_ATTEMPTS - record.failedAttempts;

        await logEvent({
            module: 'AUTH',
            action: 'OTP_VERIFY_FAILED',
            level: 'WARN',
            details: `Nhập sai OTP cho email: ${email} (Lần ${record.failedAttempts}/${OTP_CONFIG.MAX_FAILED_ATTEMPTS})`,
            user_email: email,
            metadata: { email, failedAttempts: record.failedAttempts, remaining }
        });

        if (remaining <= 0) {
            otpMemoryStore.delete(email);
            return {
                success: false,
                code: 'MAX_ATTEMPTS_EXCEEDED',
                error: 'Mã OTP không chính xác. Bạn đã nhập sai quá 3 lần nên mã đã bị hủy. Vui lòng gửi lại mã mới.'
            };
        }

        return {
            success: false,
            code: 'INVALID_OTP',
            error: `Mã OTP không chính xác! Bạn còn ${remaining} lần thử.`,
            remainingAttempts: remaining
        };
    }

    // Xác thực THÀNH CÔNG -> Hủy mã OTP khỏi bộ nhớ để chống Replay Attack (tái sử dụng mã)
    otpMemoryStore.delete(email);

    // Cập nhật trạng thái trong Supabase nếu có bảng
    try {
        await supabase
            .from('otp_verifications')
            .update({ status: 'verified', updated_at: new Date().toISOString() })
            .eq('email', email);
    } catch (e) {
        // Ignore DB sync error
    }

    await logEvent({
        module: 'AUTH',
        action: 'OTP_VERIFY_SUCCESS',
        level: 'INFO',
        details: `Xác thực email OTP thành công cho: ${email}`,
        user_email: email,
        metadata: { email }
    });

    return {
        success: true,
        message: 'Xác thực OTP thành công!'
    };
}

module.exports = {
    generateAndSaveOtp,
    verifyOtp,
    OTP_CONFIG
};
