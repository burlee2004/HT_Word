const { logEvent } = require('./auditLogger');
const path = require('path');
const fs = require('fs');

let Client, LocalAuth, qrcode;
let waClient = null;
let latestQrCode = null;
let isWaReady = false;
let isInitializing = false;

/**
 * Khởi tạo WhatsApp Web Client tự động
 */
function initWhatsAppClient() {
    if (waClient || isInitializing) return;
    isInitializing = true;

    try {
        const wwebjs = require('whatsapp-web.js');
        Client = wwebjs.Client;
        LocalAuth = wwebjs.LocalAuth;
        qrcode = require('qrcode');

        const authDir = path.join(__dirname, '../.wwebjs_auth');
        if (!fs.existsSync(authDir)) {
            fs.mkdirSync(authDir, { recursive: true });
        }

        console.log('🤖 [WHATSAPP BOT] Đang khởi tạo client WhatsApp Web tự động...');

        waClient = new Client({
            authStrategy: new LocalAuth({
                dataPath: authDir
            }),
            puppeteer: {
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu'
                ]
            }
        });

        // 1. Khi có mã QR để quét đăng nhập
        waClient.on('qr', async (qr) => {
            console.log('\n===============================================================');
            console.log('📱 [WHATSAPP QR CODE] Quét mã QR dưới đây bằng ứng dụng WhatsApp trên điện thoại:');
            console.log('👉 Hoặc mở API /api/admin/whatsapp-qr trên trình duyệt để quét trực tiếp!');
            console.log('===============================================================\n');

            try {
                // Tạo Data URL ảnh QR để hiển thị lên web
                latestQrCode = await qrcode.toDataURL(qr);
            } catch (e) {
                latestQrCode = qr;
            }
            isWaReady = false;
        });

        // 2. Khi đăng nhập thành công
        waClient.on('ready', () => {
            console.log('✅ [WHATSAPP BOT READY] WhatsApp Bot đã kết nối thành công và sẵn sàng gửi OTP!');
            isWaReady = true;
            latestQrCode = null;
        });

        // 3. Khi xác thực thành công
        waClient.on('authenticated', () => {
            console.log('🔐 [WHATSAPP BOT] Phiên đăng nhập WhatsApp đã được lưu trữ (Session Saved)!');
        });

        // 4. Khi mất kết nối hoặc đăng xuất
        waClient.on('auth_failure', (msg) => {
            console.warn('⚠️ [WHATSAPP BOT] Xác thực thất bại:', msg);
            isWaReady = false;
        });

        waClient.on('disconnected', (reason) => {
            console.warn('⚠️ [WHATSAPP BOT] WhatsApp bị ngắt kết nối:', reason);
            isWaReady = false;
            waClient = null;
            isInitializing = false;
        });

        waClient.initialize().catch(err => {
            console.warn('⚠️ [WHATSAPP BOT INIT NOTICE]:', err.message);
            isInitializing = false;
        });

    } catch (err) {
        console.warn('⚠️ [WHATSAPP BOT MODULE NOTICE]: Thư viện whatsapp-web.js chưa sẵn sàng, kích hoạt chế độ Fallback Sandbox.', err.message);
        isInitializing = false;
    }
}

/**
 * Chuẩn hóa số điện thoại Việt Nam sang định dạng WhatsApp Chat ID (VD: 0834779397 -> 84834779397@c.us)
 */
function formatPhoneNumberToWhatsAppId(phone) {
    if (!phone) return null;
    let clean = phone.toString().replace(/[^0-9+]/g, '');

    // Nếu bắt đầu bằng +84 -> bỏ dấu +
    if (clean.startsWith('+84')) {
        clean = '84' + clean.slice(3);
    } 
    // Nếu bắt đầu bằng 84 (ví dụ 84834779397)
    else if (clean.startsWith('84') && clean.length >= 11) {
        // Giữ nguyên
    }
    // Nếu bắt đầu bằng 0 (ví dụ 0834779397)
    else if (clean.startsWith('0')) {
        clean = '84' + clean.slice(1);
    }

    return `${clean}@c.us`;
}

/**
 * Gửi tin nhắn OTP qua WhatsApp
 * @param {string} phone - Số điện thoại người nhận
 * @param {string} otpCode - Mã OTP 6 chữ số
 * @returns {Promise<{ success: boolean, mode: string, messageId?: string, error?: string }>}
 */
async function sendWhatsAppOtp(phone, otpCode) {
    const waChatId = formatPhoneNumberToWhatsAppId(phone);

    const messageText = `🔒 *[HT WORK - XÁC THỰC SỐ ĐIỆN THOẠI]*\n\n` +
        `Mã OTP xác thực tài khoản của bạn là: *${otpCode}*\n\n` +
        `⏱️ Mã có hiệu lực trong vòng *5 phút*.\n` +
        `⚠️ Tuyệt đối không chia sẻ mã này cho bất kỳ ai để bảo vệ an toàn thông tin tài khoản!\n\n` +
        `_© 2026 HT Work Platform - Sàn IT & Freelancer Hub_`;

    // 1. Chế độ Gửi Thật nếu WhatsApp Bot đang online
    if (waClient && isWaReady && waChatId) {
        try {
            const msg = await waClient.sendMessage(waChatId, messageText);
            console.log(`✅ [WHATSAPP SENT] Đã gửi OTP thật tới WhatsApp: ${phone} (ID: ${waChatId})`);

            await logEvent({
                module: 'AUTH_WHATSAPP',
                action: 'PHONE_OTP_SENT_PROD',
                level: 'INFO',
                details: `Đã gửi OTP qua WhatsApp tới: ${phone}`,
                metadata: { phone, waChatId, messageId: msg.id._serialized }
            });

            return {
                success: true,
                mode: 'whatsapp_real',
                messageId: msg.id._serialized
            };
        } catch (sendErr) {
            console.warn(`⚠️ [WHATSAPP SEND ERROR] Không gửi được qua WhatsApp tới ${phone}:`, sendErr.message);
        }
    }

    // 2. Chế độ Fallback / Sandbox Mode (In OTP ra Terminal & log Event)
    console.log(`\n===============================================================`);
    console.log(`📱 [HT WORK PHONE OTP SERVICE - WHATSAPP SANDBOX / DEV MODE]`);
    console.log(`👉 Số điện thoại nhận: ${phone} (WhatsApp ID: ${waChatId || 'N/A'})`);
    console.log(`👉 MÃ XÁC THỰC OTP SĐT: [ ${otpCode} ]`);
    console.log(`👉 Trạng thái Bot: ${isWaReady ? 'Đã kết nối' : 'Đang chờ quét QR Code'}`);
    console.log(`===============================================================\n`);

    await logEvent({
        module: 'AUTH_WHATSAPP',
        action: 'PHONE_OTP_SENT_DEV',
        level: 'INFO',
        details: `[DEV SANDBOX] Gửi mã OTP SĐT tới: ${phone} | Mã: ${otpCode}`,
        metadata: { phone, otpCode, sandbox: true }
    });

    return {
        success: true,
        mode: 'sandbox',
        message: `Mã OTP xác thực đã được gửi tới số điện thoại ${phone}! (Mã thử nghiệm: ${otpCode})`
    };
}

/**
 * Lấy trạng thái hiện tại của WhatsApp Bot
 */
function getWhatsAppStatus() {
    return {
        isReady: isWaReady,
        hasQr: Boolean(latestQrCode),
        qrCode: latestQrCode
    };
}

module.exports = {
    initWhatsAppClient,
    sendWhatsAppOtp,
    getWhatsAppStatus,
    formatPhoneNumberToWhatsAppId
};
