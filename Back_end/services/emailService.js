const nodemailer = require('nodemailer');
const { logEvent } = require('./auditLogger');

// Khởi tạo Transporter cho Nodemailer
function createTransporter() {
    const host = (process.env.SMTP_HOST || 'smtp.gmail.com').trim();
    const port = parseInt(process.env.SMTP_PORT || '587');
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;
    const user = (process.env.SMTP_USER || '').trim();
    const pass = (process.env.SMTP_PASS || '').replace(/\s+/g, ''); // Tự động làm sạch mọi dấu cách từ Google App Password

    if (!user || !pass || user.includes('your_email') || pass.includes('your_app_password')) {
        return null; // Chế độ DEV/Sandbox (chưa cấu hình mail thật)
    }

    // Tối ưu riêng cho Gmail SMTP
    if (host.includes('gmail') || host.includes('google')) {
        return nodemailer.createTransport({
            service: 'gmail',
            auth: { user, pass }
        });
    }

    return nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass },
        pool: true,
        maxConnections: 5,
        maxMessages: 100
    });
}

/**
 * Tạo giao diện HTML Email thương hiệu HT Work cao cấp
 */
function generateOtpHtmlTemplate(fullName, otpCode) {
    return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Mã xác thực OTP - HT Work</title>
        <style>
            body { margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
            .container { max-width: 560px; margin: 30px auto; background: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }
            .header { background: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%); padding: 32px 24px; text-align: center; }
            .logo-text { font-size: 26px; font-weight: 900; color: #ffffff; letter-spacing: -0.5px; margin: 0; }
            .badge { display: inline-block; background: rgba(255,255,255,0.18); color: #e0e7ff; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 4px 12px; border-radius: 9999px; margin-top: 8px; }
            .content { padding: 36px 32px; color: #334155; }
            .greeting { font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 12px; }
            .desc { font-size: 14px; line-height: 1.6; color: #475569; margin-bottom: 24px; }
            .otp-box { background: linear-gradient(145deg, #eef2ff 0%, #f8fafc 100%); border: 2px dashed #6366f1; border-radius: 16px; padding: 24px; text-align: center; margin: 24px 0; }
            .otp-label { font-size: 12px; font-weight: 700; text-transform: uppercase; color: #4f46e5; letter-spacing: 1px; margin-bottom: 6px; }
            .otp-code { font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #1e1b4b; font-family: monospace; display: inline-block; padding: 6px 12px; }
            .expiry-notice { font-size: 12px; color: #64748b; margin-top: 8px; font-weight: 500; }
            .warning { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 8px; font-size: 13px; color: #92400e; margin: 24px 0; line-height: 1.5; }
            .footer { background: #f1f5f9; padding: 20px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="logo-text">HT Work</h1>
                <span class="badge">Nền tảng IT & Freelancer Hub</span>
            </div>
            <div class="content">
                <div class="greeting">Xin chào ${fullName || 'Quý khách'},</div>
                <p class="desc">Cảm ơn bạn đã đăng ký tài khoản trên nền tảng <strong>HT Work</strong>. Để hoàn tất kích hoạt tài khoản và bảo vệ an toàn thông tin, vui lòng nhập mã xác thực OTP 6 số dưới đây:</p>
                
                <div class="otp-box">
                    <div class="otp-label">MÃ XÁC THỰC CỦA BẠN</div>
                    <div class="otp-code">${otpCode}</div>
                    <div class="expiry-notice">⏱️ Mã có hiệu lực trong vòng <strong>5 phút</strong></div>
                </div>

                <div class="warning">
                    ⚠️ <strong>Lưu ý bảo mật:</strong> Tuyệt đối không chia sẻ mã này cho bất kỳ ai, kể cả nhân viên hỗ trợ của HT Work. Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.
                </div>
            </div>
            <div class="footer">
                <p style="margin: 0 0 6px 0;">© 2026 HT Work Platform. All rights reserved.</p>
                <p style="margin: 0;">Email này được gửi tự động từ hệ thống xác thực của HT Work.</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Gửi email OTP (Xử lý bất đồng bộ, không làm nghẽn API)
 */
async function sendOtpEmail(email, fullName, otpCode) {
    const transporter = createTransporter();

    // 1. Chế độ Sandbox / Dev nếu chưa cấu hình SMTP thật
    if (!transporter) {
        console.log(`\n===============================================================`);
        console.log(`📧 [HT WORK DEV EMAIL OTP SERVICE - SANDBOX MODE]`);
        console.log(`👉 Người nhận: ${fullName} <${email}>`);
        console.log(`👉 MÃ XÁC THỰC OTP: [ ${otpCode} ]`);
        console.log(`👉 Hiệu lực: 5 phút | Trạng thái: Sẵn sàng nhận cấu hình SMTP thật trong .env`);
        console.log(`===============================================================\n`);

        await logEvent({
            module: 'AUTH',
            action: 'OTP_SENT_DEV',
            level: 'INFO',
            details: `[SANDBOX] Gửi mã OTP thành công tới: ${email} | Mã: ${otpCode}`,
            user_email: email,
            metadata: { email, fullName, sandbox: true }
        });

        return { success: true, mode: 'sandbox', message: 'Mã OTP đã được tạo (Sandbox Mode)' };
    }

    // 2. Chế độ Gửi Thật qua SMTP (Gmail / Resend / SendGrid)
    try {
        const fromEmail = process.env.EMAIL_FROM || `HT Work <${process.env.SMTP_USER}>`;
        
        // Gửi mail bất đồng bộ
        const mailOptions = {
            from: fromEmail,
            to: email,
            subject: `[HT Work] ${otpCode} là mã xác thực đăng ký tài khoản của bạn`,
            html: generateOtpHtmlTemplate(fullName, otpCode)
        };

        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ [EMAIL SENT] Đã gửi OTP thật tới ${email} | MessageId: ${info.messageId}`);

        await logEvent({
            module: 'AUTH',
            action: 'OTP_SENT_PROD',
            level: 'INFO',
            details: `Đã gửi email OTP thực tế tới: ${email}`,
            user_email: email,
            metadata: { email, fullName, messageId: info.messageId }
        });

        return { success: true, mode: 'smtp', messageId: info.messageId };
    } catch (error) {
        console.error(`❌ [EMAIL ERROR] Lỗi gửi email tới ${email}:`, error);

        // Fallback: Vẫn in OTP ra console để không gián đoạn quá trình test của DEV
        console.log(`⚠️ [FALLBACK OTP CONSOLE]: Mã OTP của ${email} là: [ ${otpCode} ]`);

        await logEvent({
            module: 'AUTH',
            action: 'OTP_SEND_ERROR',
            level: 'ERROR',
            details: `Lỗi SMTP khi gửi email OTP tới ${email}: ${error.message}`,
            user_email: email,
            metadata: { error: error.message }
        });

        return { success: false, error: error.message, fallbackOtp: otpCode };
    }
}

module.exports = {
    sendOtpEmail,
    generateOtpHtmlTemplate
};

function generateResetOtpHtmlTemplate(fullName, otpCode) {
    return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <style>
            body { margin: 0; padding: 0; background-color: #fef2f2; font-family: -apple-system, sans-serif; }
            .container { max-width: 560px; margin: 30px auto; background: #ffffff; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.06); border: 1px solid #fee2e2; }
            .header { background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); padding: 32px 24px; text-align: center; }
            .logo-text { font-size: 26px; font-weight: 900; color: #ffffff; margin: 0; }
            .content { padding: 36px 32px; color: #334155; }
            .greeting { font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 12px; }
            .otp-box { background: #fef2f2; border: 2px dashed #ef4444; border-radius: 16px; padding: 24px; text-align: center; margin: 24px 0; }
            .otp-code { font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #7f1d1d; font-family: monospace; }
            .footer { background: #f8fafc; padding: 20px 24px; text-align: center; font-size: 12px; color: #94a3b8; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="logo-text">HT Work</h1>
                <div style="color:white; font-size: 14px; margin-top: 5px;">Yêu cầu Đặt Lại Mật Khẩu</div>
            </div>
            <div class="content">
                <div class="greeting">Xin chào ${fullName || 'Quý khách'},</div>
                <p>Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản <strong>HT Work</strong> của bạn.</p>
                <p>Vui lòng sử dụng mã xác thực (OTP) dưới đây để thay đổi mật khẩu mới:</p>
                <div class="otp-box"><div class="otp-code">${otpCode}</div><div style="font-size: 12px; color: #ef4444; margin-top: 10px;">⏱️ Mã có hiệu lực trong 5 phút</div></div>
                <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 8px; font-size: 13px; color: #92400e;">
                    ⚠️ Nếu bạn không yêu cầu đổi mật khẩu, vui lòng bỏ qua email này. Tài khoản của bạn vẫn an toàn.
                </div>
            </div>
            <div class="footer">© 2026 HT Work Platform. All rights reserved.</div>
        </div>
    </body>
    </html>
    `;
}

async function sendResetPasswordEmail(email, fullName, otpCode) {
    const transporter = createTransporter();
    if (!transporter) {
        console.log(`\n===============================================================`);
        console.log(`📧 [HT WORK DEV EMAIL OTP SERVICE - SANDBOX MODE] (RESET PASSWORD)`);
        console.log(`👉 Người nhận: ${fullName} <${email}>`);
        console.log(`👉 MÃ XÁC THỰC OTP: [ ${otpCode} ]`);
        console.log(`===============================================================\n`);
        return { success: true, mode: 'sandbox', demo_otp: otpCode };
    }
    try {
        const fromEmail = process.env.EMAIL_FROM || `HT Work <${process.env.SMTP_USER}>`;
        const mailOptions = {
            from: fromEmail,
            to: email,
            subject: `[HT Work] ${otpCode} là mã xác thực đặt lại mật khẩu của bạn`,
            html: generateResetOtpHtmlTemplate(fullName, otpCode)
        };
        const info = await transporter.sendMail(mailOptions);
        return { success: true, mode: 'smtp', messageId: info.messageId };
    } catch (error) {
        console.error('Lỗi gửi email reset', error);
        return { success: false, error: error.message, fallbackOtp: otpCode };
    }
}
module.exports.sendResetPasswordEmail = sendResetPasswordEmail;
