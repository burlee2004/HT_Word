const nodemailer = require('nodemailer');
const { logEvent } = require('./auditLogger');

// Khởi tạo Transporter cho Nodemailer (Hỗ trợ chuẩn STARTTLS Port 587 trên DirectAdmin Mail Server)
function createTransporter() {
    const host = (process.env.SMTP_HOST || 'mail92112.maychuemail.com').trim();
    const port = parseInt(process.env.SMTP_PORT || '587');
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;
    const user = (process.env.SMTP_USER || 'no-reply@htwork.id.vn').trim();
    const pass = (process.env.SMTP_PASS || 'Htwork@2026Secure').trim();

    if (!user || !pass || user.includes('your_email') || pass.includes('your_app_password')) {
        return null; // Chế độ DEV/Sandbox (chưa cấu hình mail thật)
    }

    return nodemailer.createTransport({
        host: host || 'mail92112.maychuemail.com',
        port: port || 587,
        secure: secure,
        auth: { user, pass },
        connectionTimeout: 8000,
        greetingTimeout: 8000,
        socketTimeout: 8000,
        tls: {
            rejectUnauthorized: false
        }
    });
}

function getFromAddress() {
    return process.env.EMAIL_FROM || '"HT Work Platform" <no-reply@htwork.id.vn>';
}

/**
 * 1. Template Email OTP Kích Hoạt Tài Khoản
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
                <span class="badge">Nền tảng IT Freelancer & Ký Quỹ Escrow</span>
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
                <p style="margin: 0 0 6px 0;">© 2026 HT Work Platform - Dự án Startup Công nghệ số (Created by Trịnh Huy Hoàng). All rights reserved.</p>
                <p style="margin: 0;">Email tự động từ no-reply@htwork.id.vn. Hỗ trợ đối tác: <a href="mailto:support@htwork.vn" style="color: #4f46e5; text-decoration: none;">support@htwork.vn</a></p>
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Gửi email OTP đăng ký
 */
async function sendOtpEmail(email, fullName, otpCode) {
    const transporter = createTransporter();

    if (!transporter) {
        console.log(`\n===============================================================`);
        console.log(`📧 [HT WORK DEV EMAIL OTP SERVICE - SANDBOX MODE]`);
        console.log(`👉 Người nhận: ${fullName} <${email}>`);
        console.log(`👉 MÃ XÁC THỰC OTP: [ ${otpCode} ]`);
        console.log(`===============================================================\n`);
        return { success: true, mode: 'sandbox', demo_otp: otpCode, message: 'Mã OTP đã được tạo (Sandbox Mode)' };
    }

    try {
        const mailOptions = {
            from: getFromAddress(),
            to: email,
            subject: `[HT Work] ${otpCode} là mã xác thực đăng ký tài khoản của bạn`,
            html: generateOtpHtmlTemplate(fullName, otpCode)
        };

        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ [EMAIL SENT] Đã gửi OTP thành công tới ${email} qua no-reply@htwork.id.vn | MessageId: ${info.messageId}`);

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
        console.error(`❌ [EMAIL ERROR] Lỗi gửi email tới ${email}:`, error.message);
        return { success: false, mode: 'error', error: error.message, demo_otp: otpCode, fallbackOtp: otpCode };
    }
}

/**
 * 2. Template Email Quên Mật Khẩu
 */
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
            .footer { background: #f8fafc; padding: 20px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
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
                <div class="otp-box">
                    <div style="font-size: 11px; text-transform: uppercase; color: #dc2626; font-weight: 700; margin-bottom: 6px;">MÃ ĐẶT LẠI MẬT KHẨU</div>
                    <div class="otp-code">${otpCode}</div>
                    <div style="font-size: 12px; color: #ef4444; margin-top: 10px;">⏱️ Mã có hiệu lực trong 5 phút</div>
                </div>
                <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 8px; font-size: 13px; color: #92400e;">
                    ⚠️ Nếu bạn không yêu cầu đổi mật khẩu, vui lòng bỏ qua email này. Tài khoản của bạn vẫn an toàn.
                </div>
            </div>
            <div class="footer">
                <p style="margin: 0 0 6px 0;">© 2026 HT Work Platform - Dự án Startup Công nghệ số (Created by Trịnh Huy Hoàng). All rights reserved.</p>
                <p style="margin: 0;">Email tự động từ no-reply@htwork.id.vn. Hỗ trợ: support@htwork.vn</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Gửi email OTP đặt lại mật khẩu
 */
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
        const mailOptions = {
            from: getFromAddress(),
            to: email,
            subject: `[HT Work] ${otpCode} là mã xác thực đặt lại mật khẩu của bạn`,
            html: generateResetOtpHtmlTemplate(fullName, otpCode)
        };
        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ [RESET EMAIL SENT] Đã gửi email khôi phục tới ${email} | MessageId: ${info.messageId}`);
        return { success: true, mode: 'smtp', messageId: info.messageId };
    } catch (error) {
        console.error('Lỗi gửi email reset:', error.message);
        return { success: false, mode: 'error', error: error.message, demo_otp: otpCode, fallbackOtp: otpCode };
    }
}

/**
 * 3. Template Email Biên Lai Biến Động Số Dư & Ký Quỹ Escrow
 */
function generateTransactionHtmlTemplate({ fullName, type, title, amount, balanceAfter, txCode, note, time }) {
    const isIncome = amount > 0;
    const amountFormatted = Math.abs(amount).toLocaleString('vi-VN');
    const colorTheme = isIncome ? '#059669' : '#4f46e5';

    return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <style>
            body { margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
            .container { max-width: 580px; margin: 30px auto; background: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }
            .header { background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); padding: 28px 24px; text-align: center; color: white; }
            .logo { font-size: 24px; font-weight: 900; letter-spacing: -0.5px; }
            .subtitle { font-size: 13px; color: #c7d2fe; margin-top: 4px; }
            .content { padding: 32px 28px; color: #334155; }
            .receipt-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 24px; text-align: center; margin: 20px 0; }
            .type-badge { display: inline-block; background: ${colorTheme}15; color: ${colorTheme}; font-weight: 700; font-size: 12px; padding: 4px 12px; border-radius: 9999px; text-transform: uppercase; }
            .amount { font-size: 32px; font-weight: 900; color: ${colorTheme}; margin: 12px 0 6px 0; }
            .details-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
            .details-table td { padding: 10px 0; border-bottom: 1px solid #f1f5f9; }
            .details-table td.label { color: #64748b; font-weight: 500; }
            .details-table td.val { text-align: right; color: #0f172a; font-weight: 700; }
            .btn { display: inline-block; background: #4f46e5; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 12px; font-weight: 700; font-size: 13px; margin-top: 24px; }
            .footer { background: #f1f5f9; padding: 20px 24px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">HT Work</div>
                <div class="subtitle">Chứng Từ Đối Soát & Giao Dịch Số</div>
            </div>
            <div class="content">
                <div style="font-size: 16px; font-weight: 700; color: #0f172a;">Kính gửi ${fullName || 'Quý khách'},</div>
                <p style="font-size: 13px; line-height: 1.6; color: #475569; margin: 8px 0 16px 0;">
                    Hệ thống HT Work xin thông báo giao dịch tài khoản của bạn đã được ghi nhận và xử lý thành công:
                </p>

                <div class="receipt-card">
                    <span class="type-badge">${title || 'Giao dịch thành công'}</span>
                    <div class="amount">${isIncome ? '+' : '-'}${amountFormatted} Token</div>
                    <div style="font-size: 12px; color: #64748b;">(Tương đương: ${amountFormatted} VNĐ)</div>

                    <table class="details-table">
                        <tr>
                            <td class="label">Mã giao dịch:</td>
                            <td class="val">${txCode || 'HT-' + Date.now().toString().slice(-8)}</td>
                        </tr>
                        <tr>
                            <td class="label">Thời gian:</td>
                            <td class="val">${time || new Date().toLocaleString('vi-VN')}</td>
                        </tr>
                        <tr>
                            <td class="label">Nội dung:</td>
                            <td class="val">${note || 'Giao dịch qua hệ thống HT Work'}</td>
                        </tr>
                        ${balanceAfter !== undefined ? `
                        <tr>
                            <td class="label">Số dư khả dụng sau GD:</td>
                            <td class="val" style="color: #059669;">${Number(balanceAfter).toLocaleString('vi-VN')} Token</td>
                        </tr>
                        ` : ''}
                    </table>
                </div>

                <div style="text-align: center;">
                    <a href="https://htwork.id.vn/user/wallet.html" class="btn">Xem Chi Tiết Số Dư & Lịch Sử Ví</a>
                </div>
            </div>
            <div class="footer">
                <p style="margin: 0 0 6px 0;">© 2026 HT Work Platform. Bảo chứng thanh toán Ký Quỹ Escrow chuẩn Core Banking & Smart Contract.</p>
                <p style="margin: 0;">Mọi thắc mắc đối soát giao dịch, vui lòng liên hệ: <a href="mailto:admin@htwork.id.vn" style="color: #4f46e5; text-decoration: none;">admin@htwork.id.vn</a></p>
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Gửi email thông báo biến động tài chính
 */
async function sendTransactionReceiptEmail({ toEmail, fullName, type, title, amount, balanceAfter, txCode, note }) {
    const transporter = createTransporter();
    if (!transporter) {
        console.log(`[TRANSACTION EMAIL SANDBOX] To: ${toEmail} | Amount: ${amount} Token | Note: ${note}`);
        return { success: true, mode: 'sandbox' };
    }
    try {
        const mailOptions = {
            from: getFromAddress(),
            to: toEmail,
            subject: `[HT Work] Thông báo biến động số dư: ${amount > 0 ? '+' : ''}${Number(amount).toLocaleString('vi-VN')} Token`,
            html: generateTransactionHtmlTemplate({
                fullName,
                type,
                title,
                amount,
                balanceAfter,
                txCode,
                note,
                time: new Date().toLocaleString('vi-VN')
            })
        };
        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ [RECEIPT EMAIL SENT] Đã gửi biên lai tới ${toEmail} | MessageId: ${info.messageId}`);
        return { success: true, mode: 'smtp', messageId: info.messageId };
    } catch (err) {
        console.error('Lỗi gửi email biên lai giao dịch:', err.message);
        return { success: false, error: err.message };
    }
}

/**
 * 4. Template Email Thông Báo Cột Mốc Dự Án (Milestone / Escrow Notification)
 */
function generateMilestoneHtmlTemplate({ fullName, projectTitle, milestoneTitle, statusText, note, actionUrl }) {
    return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <style>
            body { margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
            .container { max-width: 580px; margin: 30px auto; background: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.06); border: 1px solid #e2e8f0; }
            .header { background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 100%); padding: 28px 24px; text-align: center; color: white; }
            .logo { font-size: 24px; font-weight: 900; }
            .content { padding: 32px 28px; color: #334155; }
            .status-box { background: #f0fdf4; border-left: 4px solid #10b981; padding: 14px 18px; border-radius: 8px; margin: 18px 0; }
            .btn { display: inline-block; background: #2563eb; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 12px; font-weight: 700; font-size: 13px; margin-top: 20px; }
            .footer { background: #f1f5f9; padding: 20px 24px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">HT Work</div>
                <div style="font-size: 13px; color: #e0f2fe; margin-top: 4px;">Cập Nhật Tiến Độ & Nghiệm Thu Dự Án</div>
            </div>
            <div class="content">
                <div style="font-size: 16px; font-weight: 700; color: #0f172a;">Kính gửi ${fullName || 'Quý đối tác'},</div>
                <p style="font-size: 13px; line-height: 1.6; color: #475569; margin: 8px 0;">
                    Dự án <strong>"${projectTitle}"</strong> trên nền tảng HT Work vừa có cập nhật trạng thái mới:
                </p>

                <div class="status-box">
                    <div style="font-size: 12px; text-transform: uppercase; color: #047857; font-weight: 700;">TRẠNG THÁI TIẾN ĐỘ</div>
                    <div style="font-size: 16px; font-weight: 800; color: #065f46; margin: 4px 0;">${statusText || 'Bàn giao cột mốc mới'}</div>
                    <div style="font-size: 13px; color: #047857;">Cột mốc: <strong>${milestoneTitle || 'Toàn bộ dự án'}</strong></div>
                    ${note ? `<div style="font-size: 12px; color: #374151; margin-top: 6px; font-style: italic;">"${note}"</div>` : ''}
                </div>

                <div style="text-align: center;">
                    <a href="${actionUrl || 'https://htwork.id.vn'}" class="btn">Mở Dự Án Kiểm Tra & Nghiệm Thu</a>
                </div>
            </div>
            <div class="footer">
                <p style="margin: 0 0 6px 0;">© 2026 HT Work Platform. Hỗ trợ giải quyết tranh chấp Escrow 24/7: support@htwork.vn</p>
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Gửi email thông báo tiến độ Milestone
 */
async function sendMilestoneNoticeEmail({ toEmail, fullName, projectTitle, milestoneTitle, statusText, note, actionUrl }) {
    const transporter = createTransporter();
    if (!transporter) {
        console.log(`[MILESTONE NOTICE SANDBOX] To: ${toEmail} | Project: ${projectTitle} | Status: ${statusText}`);
        return { success: true, mode: 'sandbox' };
    }
    try {
        const mailOptions = {
            from: getFromAddress(),
            to: toEmail,
            subject: `[HT Work] Cập nhật tiến độ dự án: ${projectTitle}`,
            html: generateMilestoneHtmlTemplate({
                fullName,
                projectTitle,
                milestoneTitle,
                statusText,
                note,
                actionUrl
            })
        };
        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ [MILESTONE EMAIL SENT] Đã gửi thông báo tới ${toEmail} | MessageId: ${info.messageId}`);
        return { success: true, mode: 'smtp', messageId: info.messageId };
    } catch (err) {
        console.error('Lỗi gửi email tiến độ:', err.message);
        return { success: false, error: err.message };
    }
}

module.exports = {
    sendOtpEmail,
    sendResetPasswordEmail,
    sendTransactionReceiptEmail,
    sendMilestoneNoticeEmail,
    generateOtpHtmlTemplate
};
