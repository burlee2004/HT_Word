const crypto = require('crypto');
const { logEvent } = require('./auditLogger');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8963688224:AAH0UHy82q_Rynxr9bvsSRG-y4F4EtyvDk4';
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || 'kgswork_hoang_otp_bot';

/**
 * Lưu trữ phiên OTP Telegram trong Memory
 * Key: sessionToken (string)
 * Value: { token, phone, otpCode, userId, createdAt, expiresAt, sent: boolean }
 */
const telegramOtpSessions = new Map();
const phoneToSessionMap = new Map();

// Trạng thái bot
let isPollingActive = false;
let lastUpdateOffset = 0;
let pollingAbortController = null;

/**
 * Tự động dọn dẹp các session OTP quá hạn (sau 10 phút)
 */
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of telegramOtpSessions.entries()) {
        if (now > session.expiresAt + 5 * 60 * 1000) {
            telegramOtpSessions.delete(token);
            if (phoneToSessionMap.get(session.phone) === token) {
                phoneToSessionMap.delete(session.phone);
            }
        }
    }
}, 5 * 60 * 1000);

/**
 * Gọi API Telegram Bot chính thức qua HTTPS
 */
async function callTelegramApi(endpoint, body = {}) {
    if (!TELEGRAM_BOT_TOKEN) {
        throw new Error('Chưa cấu hình TELEGRAM_BOT_TOKEN trong .env');
    }

    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${endpoint}`;
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        return data;
    } catch (err) {
        console.error(`❌ [TELEGRAM API ERROR] ${endpoint}:`, err.message);
        return { ok: false, description: err.message };
    }
}

/**
 * Gửi tin nhắn Text tới Telegram Chat ID
 */
async function sendTelegramMessage(chatId, text, extra = {}) {
    return await callTelegramApi('sendMessage', {
        chat_id: chatId,
        text: text,
        parse_mode: 'Markdown',
        ...extra
    });
}

/**
 * Tạo phiên OTP Telegram mới cho số điện thoại
 * @param {string} phone - Số điện thoại
 * @param {string} otpCode - Mã OTP 6 chữ số
 * @param {string} userId - ID người dùng
 * @returns {{ token: string, deepLink: string, botUsername: string }}
 */
function createTelegramOtpSession(phone, otpCode, userId = null) {
    // Xóa session cũ nếu có
    const existingToken = phoneToSessionMap.get(phone);
    if (existingToken) {
        telegramOtpSessions.delete(existingToken);
    }

    // Tạo mã token ngẫu nhiên cho deep link
    const token = crypto.randomBytes(4).toString('hex');
    const now = Date.now();

    const session = {
        token,
        phone,
        otpCode,
        userId,
        createdAt: now,
        expiresAt: now + 5 * 60 * 1000, // 5 phút
        sent: false
    };

    telegramOtpSessions.set(token, session);
    phoneToSessionMap.set(phone, token);

    const deepLink = `https://t.me/${TELEGRAM_BOT_USERNAME}?start=otp_${token}`;

    console.log(`📱 [TELEGRAM OTP CREATED] SĐT: ${phone} | OTP: ${otpCode} | DeepLink: ${deepLink}`);

    return {
        token,
        deepLink,
        botUsername: TELEGRAM_BOT_USERNAME,
        expiresAt: session.expiresAt
    };
}

/**
 * Lấy session OTP theo token
 */
function getTelegramOtpSession(token) {
    return telegramOtpSessions.get(token);
}

/**
 * Vòng lặp Long Polling nhận tin nhắn từ Telegram
 */
async function startLongPolling() {
    if (isPollingActive) return;
    isPollingActive = true;
    console.log(`🤖 [TELEGRAM BOT POLLING] Đang lắng nghe tin nhắn từ bot @${TELEGRAM_BOT_USERNAME}...`);

    while (isPollingActive) {
        try {
            const res = await callTelegramApi('getUpdates', {
                offset: lastUpdateOffset,
                timeout: 25,
                allowed_updates: ['message']
            });

            if (res.ok && Array.isArray(res.result)) {
                for (const update of res.result) {
                    lastUpdateOffset = update.update_id + 1;
                    await handleTelegramUpdate(update);
                }
            } else if (!res.ok) {
                // Đợi 4s trước khi thử lại nếu có lỗi từ server Telegram
                await new Promise(r => setTimeout(r, 4000));
            }
        } catch (pollErr) {
            console.warn('⚠️ [TELEGRAM POLL NOTICE]:', pollErr.message);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
}

/**
 * Xử lý từng tin nhắn từ người dùng Telegram
 */
async function handleTelegramUpdate(update) {
    const message = update.message;
    if (!message || !message.text) return;

    const chatId = message.chat.id;
    const text = message.text.trim();
    const senderName = message.from ? `${message.from.first_name || ''} ${message.from.last_name || ''}`.trim() : 'Bạn';

    console.log(`📩 [TELEGRAM INCOMING] Từ @${message.from?.username || chatId}: "${text}"`);

    // 1. Trường hợp người dùng click deep-link: /start otp_<token>
    if (text.startsWith('/start otp_')) {
        const token = text.replace('/start otp_', '').trim();
        const session = telegramOtpSessions.get(token);

        if (!session) {
            await sendTelegramMessage(chatId, 
                `⚠️ *Mã xác thực không hợp lệ hoặc đã hết hạn.*\n\n` +
                `Vui lòng quay lại website [KGS Work](https://trinhhuyhoang.id.vn) và bấm *"Gửi mã OTP"* để nhận liên kết mới nhé!`
            );
            return;
        }

        if (Date.now() > session.expiresAt) {
            telegramOtpSessions.delete(token);
            await sendTelegramMessage(chatId, 
                `⏱️ *Mã OTP đã hết hiệu lực (quá 5 phút).*\n\n` +
                `Vui lòng bấm *"Gửi lại mã OTP"* trên trang Hồ sơ website KGS Work để nhận mã mới.`
            );
            return;
        }

        // Gửi ngay mã OTP 6 số cho người dùng
        session.sent = true;
        const otpText = 
            `🔒 *[KGS WORK - MÃ XÁC THỰC SỐ ĐIỆN THOẠI]*\n\n` +
            `Xin chào *${senderName || 'bạn'}*!\n` +
            `Mã OTP xác thực số điện thoại *${session.phone}* của bạn trên hệ thống KGS Work là:\n\n` +
            `👉 \`${session.otpCode}\` 👈\n\n` +
            `*(Chạm vào số ở trên để tự động sao chép)*\n\n` +
            `⏱️ Mã có hiệu lực trong vòng *5 phút*.\n` +
            `⚠️ Tuyệt đối không chia sẻ mã này cho bất kỳ ai để bảo mật tài khoản!\n\n` +
            `_🌐 KGS Work - Nền tảng Freelancer IT Việt Nam_`;

        await sendTelegramMessage(chatId, otpText);

        console.log(`✅ [TELEGRAM OTP SENT] Đã gửi mã OTP ${session.otpCode} tới Telegram chatId: ${chatId} cho SĐT: ${session.phone}`);

        await logEvent({
            module: 'AUTH_TELEGRAM',
            action: 'TELEGRAM_OTP_DELIVERED',
            level: 'INFO',
            details: `Gửi OTP Telegram thành công cho SĐT: ${session.phone} (Mã: ${session.otpCode})`,
            metadata: { phone: session.phone, chatId, token }
        });

        return;
    }

    // 2. Lệnh /start mặc định hoặc chào hỏi
    if (text === '/start' || text.toLowerCase() === 'start') {
        const welcomeText = 
            `👋 Xin chào *${senderName}*!\n\n` +
            `Chào mừng bạn đến với *KGS Work OTP Bot* 🤖\n\n` +
            `Đây là hệ thống cấp mã OTP xác thực số điện thoại tức thì và hoàn toàn miễn phí cho nền tảng:\n` +
            `🌐 *KGS Work - Freelancer IT Platform*\n` +
            `🔗 https://trinhhuyhoang.id.vn\n\n` +
            `👉 *Cách nhận mã OTP xác thực SĐT:*\n` +
            `1. Vào trang Hồ sơ của bạn trên website KGS Work.\n` +
            `2. Nhập số điện thoại và bấm nút *"Gửi mã OTP"*.\n` +
            `3. Bấm vào liên kết mở Telegram, bot sẽ tự động gửi mã 6 số về đây ngay lập tức!\n\n` +
            `Chúc bạn có trải nghiệm tuyệt vời cùng KGS Work! ✨`;

        await sendTelegramMessage(chatId, welcomeText);
        return;
    }

    // 3. Tin nhắn khác / Help
    const helpText = 
        `💡 *HƯỚNG DẪN XÁC THỰC SỐ ĐIỆN THOẠI KGS WORK*\n\n` +
        `Để nhận mã OTP cho tài khoản của bạn, vui lòng truy cập website và bấm nút *"Xác thực số điện thoại"*, sau đó chọn nhận mã qua Telegram.\n\n` +
        `🌐 Website: https://trinhhuyhoang.id.vn`;

    await sendTelegramMessage(chatId, helpText);
}

/**
 * Khởi tạo Telegram Bot
 */
async function initTelegramBot() {
    if (!TELEGRAM_BOT_TOKEN) {
        console.warn('⚠️ [TELEGRAM BOT] Chưa có TELEGRAM_BOT_TOKEN. Bỏ qua khởi động Telegram Bot.');
        return;
    }

    try {
        const me = await callTelegramApi('getMe');
        if (me && me.ok) {
            console.log(`✅ [TELEGRAM BOT READY] Đã kết nối thành công Bot: @${me.result.username} (${me.result.first_name})`);
            // Bắt đầu lắng nghe tin nhắn
            startLongPolling();
        } else {
            console.warn('⚠️ [TELEGRAM BOT] Không thể kết nối với Telegram API:', me?.description);
        }
    } catch (e) {
        console.warn('⚠️ [TELEGRAM BOT INIT FAILED]:', e.message);
    }
}

/**
 * Lấy trạng thái bot
 */
function getTelegramBotStatus() {
    return {
        isPolling: isPollingActive,
        botUsername: TELEGRAM_BOT_USERNAME,
        activeSessions: telegramOtpSessions.size
    };
}

module.exports = {
    initTelegramBot,
    createTelegramOtpSession,
    getTelegramOtpSession,
    sendTelegramMessage,
    getTelegramBotStatus,
    TELEGRAM_BOT_USERNAME
};
