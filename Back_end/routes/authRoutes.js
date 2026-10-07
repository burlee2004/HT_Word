const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');
const uploadImage = require('../config/cloudinary');
const uploadFile = require('../config/s3');
const { logEvent } = require('../services/auditLogger');
const { sendOtpEmail } = require('../services/emailService');
const { generateAndSaveOtp, verifyOtp } = require('../services/otpService');
const { sendWhatsAppOtp, getWhatsAppStatus, initWhatsAppClient } = require('../services/whatsappService');
const crypto = require('crypto');

// In-Memory store cho Phone OTP (WhatsApp)
const phoneOtpStore = new Map();

// ==========================================
// 📧 EMAIL OTP VERIFICATION & REGISTRATION FLOW
// ==========================================

// 1. API Gửi mã OTP xác thực email khi đăng ký
router.post(['/send-otp', '/api/auth/send-otp'], async (req, res) => {
    const { email, full_name, role } = req.body;
    try {
        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Địa chỉ email không hợp lệ!' });
        }

        // Kiểm tra xem email đã tồn tại trong DB chưa
        const { data: existingUser } = await supabase
            .from('users')
            .select('id, email')
            .eq('email', email.trim().toLowerCase())
            .maybeSingle();

        if (existingUser) {
            return res.status(400).json({ error: 'Email này đã được sử dụng. Vui lòng đăng nhập hoặc chọn email khác!' });
        }

        // Sinh mã OTP và lưu vào Memory Store
        const otpResult = await generateAndSaveOtp(email, req.ip);
        if (!otpResult.success) {
            return res.status(otpResult.code === 'COOLDOWN_ACTIVE' ? 429 : 400).json({
                error: otpResult.error,
                remainingSeconds: otpResult.remainingSeconds,
                code: otpResult.code
            });
        }

        // Gửi email OTP (Bất đồng bộ trong background - Phản hồi ngay < 100ms)
        sendOtpEmail(email.trim().toLowerCase(), full_name || 'Quý khách', otpResult.plainOtp)
            .then(mailRes => {
                console.log(`[AUTH BG EMAIL] Đã xử lý gửi OTP tới ${email} (Mode: ${mailRes.mode})`);
            })
            .catch(mailErr => {
                console.error(`[AUTH BG EMAIL ERROR] Lỗi gửi OTP tới ${email}:`, mailErr.message);
            });

        return res.status(200).json({
            success: true,
            message: `Mã OTP xác thực đã được gửi đến email ${email}!`,
            cooldownSeconds: otpResult.cooldownSeconds,
            expiresAt: otpResult.expiresAt
        });
    } catch (error) {
        console.error('Lỗi khi gửi OTP:', error);
        return res.status(500).json({ error: error.message || 'Lỗi xử lý gửi OTP từ máy chủ' });
    }
});

// 2. API Gửi lại mã OTP (Resend OTP kèm Cooldown 60s)
router.post(['/resend-otp', '/api/auth/resend-otp'], async (req, res) => {
    const { email, full_name } = req.body;
    try {
        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Địa chỉ email không hợp lệ!' });
        }

        const otpResult = await generateAndSaveOtp(email, req.ip);
        if (!otpResult.success) {
            return res.status(otpResult.code === 'COOLDOWN_ACTIVE' ? 429 : 400).json({
                error: otpResult.error,
                remainingSeconds: otpResult.remainingSeconds,
                code: otpResult.code
            });
        }

        // Dispatch email trong background
        sendOtpEmail(email.trim().toLowerCase(), full_name || 'Quý khách', otpResult.plainOtp)
            .then(mailRes => console.log(`[RESEND BG EMAIL] Đã gửi lại tới ${email}: ${mailRes.mode}`))
            .catch(mailErr => console.error(`[RESEND BG EMAIL ERROR]:`, mailErr.message));

        return res.status(200).json({
            success: true,
            message: `Đã gửi lại mã OTP mới tới email ${email}!`,
            cooldownSeconds: otpResult.cooldownSeconds
        });
    } catch (error) {
        return res.status(500).json({ error: error.message || 'Lỗi gửi lại mã OTP' });
    }
});

// 3. API Xác thực mã OTP & Hoàn tất tạo tài khoản
router.post(['/verify-otp', '/api/auth/verify-otp'], async (req, res) => {
    const { email, otp, full_name, password, role, main_category, skills } = req.body;
    try {
        if (!email || !otp) {
            return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ email và mã OTP!' });
        }

        // 1. Xác thực mã OTP qua otpService
        const verifyResult = await verifyOtp(email, otp);
        if (!verifyResult.success) {
            return res.status(400).json({
                error: verifyResult.error,
                remainingAttempts: verifyResult.remainingAttempts,
                code: verifyResult.code
            });
        }

        // 2. Nếu có gửi kèm password và full_name -> Thực hiện Đăng ký & Kích hoạt tài khoản luôn
        if (password && full_name) {
            // Kiểm tra trùng email lại 1 lần nữa để đảm bảo an toàn
            const { data: existingUser } = await supabase
                .from('users')
                .select('id')
                .eq('email', email.trim().toLowerCase())
                .maybeSingle();

            if (existingUser) {
                return res.status(400).json({ error: 'Email này đã được đăng ký tài khoản trước đó!' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const userRole = role || 'client';

            const { data: newUser, error: userError } = await supabase
                .from('users')
                .insert([{
                    email: email.trim().toLowerCase(),
                    password: hashedPassword,
                    full_name: full_name.trim(),
                    role: userRole,
                    is_email_verified: true
                }])
                .select()
                .single();

            if (userError) throw userError;

            // Nếu là freelancer, tạo profile
            if (userRole === 'freelancer') {
                const { error: profileError } = await supabase
                    .from('freelancer_profiles')
                    .insert([{
                        user_id: newUser.id,
                        main_category: main_category || 'Other',
                        skills: skills || []
                    }]);

                if (profileError) {
                    console.warn('[Profile Create Notice]:', profileError.message);
                }
            }

            // Ghi audit log
            await logEvent({
                module: 'AUTH',
                action: 'REGISTER_VERIFIED_EMAIL',
                level: 'INFO',
                details: `Đăng ký & xác thực email thành công: ${email} | Role: [${userRole.toUpperCase()}] | Họ tên: ${full_name}`,
                user_id: newUser.id,
                user_email: email,
                user_role: userRole,
                metadata: { full_name, role: userRole }
            });

            return res.status(201).json({
                success: true,
                message: 'Đăng ký và xác thực tài khoản thành công!',
                user: {
                    id: newUser.id,
                    email: newUser.email,
                    full_name: newUser.full_name,
                    role: newUser.role,
                    is_email_verified: true
                }
            });
        }

        // Trường hợp chỉ xác thực OTP thông thường
        return res.status(200).json({
            success: true,
            message: 'Xác thực mã OTP thành công!'
        });
    } catch (error) {
        console.error('Lỗi khi xác thực OTP:', error);
        return res.status(400).json({ error: error.message || 'Lỗi xác thực OTP' });
    }
});

// Route Đăng ký Cũ (Vẫn giữ để tương thích ngược nếu cần)
router.post('/register', async (req, res) => {
    const { email, password, full_name, role, main_category, skills } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const { data: newUser, error: userError } = await supabase
            .from('users')
            .insert([{ email, password: hashedPassword, full_name, role }])
            .select()
            .single();

        if (userError) throw userError;

        if (role === 'freelancer') {
            const { error: profileError } = await supabase
                .from('freelancer_profiles')
                .insert([{
                    user_id: newUser.id,
                    main_category: main_category || 'Other',
                    skills: skills || []
                }]);

            if (profileError) {
                await supabase.from('users').delete().eq('id', newUser.id);
                throw profileError;
            }
        }

        await logEvent({
            module: 'AUTH',
            action: 'REGISTER',
            level: 'INFO',
            details: `Người dùng mới đăng ký: ${email} | Vai trò: [${role.toUpperCase()}] | Họ tên: ${full_name}`,
            user_id: newUser.id,
            user_email: email,
            user_role: role,
            metadata: { full_name, role, main_category }
        });

        res.status(201).json({ message: 'Đăng ký thành công!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Route Đăng nhập (Login)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Lấy thông tin user (bao gồm cả role)
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            await logEvent({
                module: 'AUTH',
                action: 'LOGIN_FAILED',
                level: 'WARN',
                details: `Đăng nhập thất bại: Email không tồn tại (${email})`,
                user_email: email
            });
            throw new Error('Email không tồn tại!');
        }

        // Kiểm tra mật khẩu (Sử dụng bcrypt)
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            await logEvent({
                module: 'AUTH',
                action: 'LOGIN_FAILED',
                level: 'WARN',
                details: `Đăng nhập thất bại: Sai mật khẩu cho tài khoản ${email}`,
                user_id: user.id,
                user_email: email,
                user_role: user.role
            });
            throw new Error('Mật khẩu không đúng!');
        }

        // Ghi log đăng nhập thành công
        await logEvent({
            module: 'AUTH',
            action: 'LOGIN_SUCCESS',
            level: 'INFO',
            details: `Người dùng ${email} (${user.role.toUpperCase()}) đăng nhập thành công vào hệ thống.`,
            user_id: user.id,
            user_email: email,
            user_role: user.role
        });

        // Trả về thông tin user (để Frontend biết đường điều hướng)
        res.status(200).json({ 
            message: 'Đăng nhập thành công', 
            user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role } 
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Cấu hình Multer Local Disk Storage làm lưu trữ cục bộ trực tiếp & dự phòng
const multer = require('multer');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const s3Client = new S3Client({
    region: (process.env.AWS_REGION || '').trim(),
    credentials: {
        accessKeyId: (process.env.AWS_ACCESS_KEY_ID || '').trim(),
        secretAccessKey: (process.env.AWS_SECRET_ACCESS_KEY || '').trim()
    }
});

const localDiskStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const upDir = path.join(__dirname, '../uploads');
        if (!fs.existsSync(upDir)) fs.mkdirSync(upDir, { recursive: true });
        cb(null, upDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const originalName = file.originalname ? file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_') : 'upload.bin';
        cb(null, uniqueSuffix + '-' + originalName);
    }
});
const uploadLocal = multer({ storage: localDiskStorage, limits: { fileSize: 50 * 1024 * 1024 } });

// Helper tra cứu MIME Type khi tải/xem tệp tin
function getMimeType(fileName) {
    if (!fileName) return 'application/octet-stream';
    const ext = path.extname(fileName).toLowerCase();
    const mimeMap = {
        '.pdf': 'application/pdf',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml',
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.mp3': 'audio/mpeg',
        '.wav': 'audio/wav',
        '.txt': 'text/plain; charset=utf-8',
        '.toml': 'text/plain; charset=utf-8',
        '.json': 'application/json',
        '.js': 'text/javascript',
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css',
        '.md': 'text/markdown; charset=utf-8',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.doc': 'application/msword',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.xls': 'application/vnd.ms-excel',
        '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        '.zip': 'application/zip',
        '.rar': 'application/x-rar-compressed',
        '.7z': 'application/x-7z-compressed'
    };
    return mimeMap[ext] || 'application/octet-stream';
}

// Route Upload Ảnh (Cloudinary + Local Fallback)

// LOGGER UPLOAD YÊU CẦU
function writeUploadLog(req, type, status, detail) {
    try {
        const fs = require('fs');
        const path = require('path');
        const logFile = path.join(__dirname, '../upload_debug.log');
        const time = new Date().toISOString();
        const ip = req.ip || req.connection.remoteAddress;
        let fileInfo = 'No file info';
        if (req.file) {
            fileInfo = `Name: ${req.file.originalname}, Size: ${req.file.size} bytes, Mime: ${req.file.mimetype}`;
        }
        const logLine = `[${time}] IP: ${ip} | Type: ${type} | Status: ${status} | Detail: ${detail} | File: ${fileInfo}\n`;
        fs.appendFileSync(logFile, logLine);
        console.log(logLine.trim());
    } catch(e) {}
}

router.post('/upload-image', (req, res) => {
    writeUploadLog(req, '/upload-image', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('image')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/upload-image', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/upload-image', 'ERROR', 'Thiếu file ảnh');
            return res.status(400).json({ error: 'Thiếu file ảnh' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/upload-image', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({
            message: 'Upload ảnh thành công!',
            imageUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/upload-file', (req, res) => {
    writeUploadLog(req, '/upload-file', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/upload-file', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/upload-file', 'ERROR', 'Thiếu file tải lên');
            return res.status(400).json({ error: 'Thiếu file tải lên' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/upload-file', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({
            message: 'Upload file thành công!',
            fileUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/api/upload/image', (req, res) => {
    writeUploadLog(req, '/api/upload/image', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/api/upload/image', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/api/upload/image', 'ERROR', 'Không thể upload ảnh (thiếu file)');
            return res.status(400).json({ error: 'Không thể upload ảnh' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/api/upload/image', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        res.status(200).json({ url: localUrl, imageUrl: localUrl, type: 'image' });
    });
});

router.post('/api/upload/file', (req, res) => {
    writeUploadLog(req, '/api/upload/file', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/api/upload/file', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/api/upload/file', 'ERROR', 'Thiếu file tải lên');
            return res.status(400).json({ error: 'Thiếu file tải lên' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        let type = 'document';
        if (req.file.mimetype && req.file.mimetype.startsWith('video/')) type = 'video';
        else if (req.file.mimetype && req.file.mimetype.startsWith('audio/')) type = 'audio';
        writeUploadLog(req, '/api/upload/file', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({ url: localUrl, fileUrl: localUrl, type: type });
    });
});
router.post('/api/upload/base64', (req, res) => {
    try {
        const { base64, filename, file_type } = req.body;
        if (!base64) return res.status(400).json({ error: 'Thiếu dữ liệu base64' });

        const matches = base64.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
        const dataBuffer = matches ? Buffer.from(matches[2], 'base64') : Buffer.from(base64, 'base64');
        
        if (dataBuffer.length > 50 * 1024 * 1024) {
            return res.status(400).json({ error: 'File đã vượt quá 50MB' });
        }

        const ext = (file_type && file_type.includes('png')) ? '.png' : (file_type && file_type.includes('jpeg')) ? '.jpg' : '.png';
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const savedName = 'clipboard_' + uniqueSuffix + ext;
        const filePath = path.join(__dirname, '../uploads', savedName);
        
        fs.writeFileSync(filePath, dataBuffer);
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const fileUrl = `${protocol}://${host}/uploads/${savedName}`;
        res.status(200).json({ success: true, url: fileUrl, imageUrl: fileUrl, file_name: filename || savedName, file_type: file_type || 'image/png' });
    } catch (e) {
        res.status(500).json({ error: 'Lỗi lưu base64: ' + e.message });
    }
});

// 1. Xem Hồ sơ cá nhân (Profile) kèm Thống kê Client
router.get('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    console.log(`
👤 [API GET /api/users/${id}] Tải thông tin hồ sơ`);
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, full_name, email, role, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner, phone_number, is_email_verified, is_phone_verified, kyc_status, created_at')
            .eq('id', id)
            .single();
            
        if (error || !user) throw (error || new Error('Không tìm thấy người dùng'));

        // Parse skills if it contains JSON for location, nickname, primary_category
        let location = 'TP. Hồ Chí Minh';
        let nickname = '';
        let primary_category = '';
        let rawSkills = user.skills || '';
        let portfolios = [];
        if (user.skills) {
            try {
                const parsed = JSON.parse(user.skills);
                location = parsed.location || location;
                nickname = parsed.nickname || '';
                primary_category = parsed.primary_category || '';
                rawSkills = parsed.skills || parsed.skillsText || '';
                portfolios = parsed.portfolios || [];
            } catch (e) {
                // If not JSON, it's raw text
                rawSkills = user.skills;
                nickname = user.skills;
            }
        }

        // Tính toán Thống kê cho Khách hàng (Client Stats) & Freelancer
        let totalSpent = 0;
        let hireRate = 0;
        let jobsPosted = 0;
        let completedCount = 0;
        let recentJobs = [];
        let creditTier = 'Khách mới';
        let tierBadge = 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';

        let totalEarnings = 0;
        let completionRateDisplay = 'Chưa có';
        let ratingDisplay = 'Chưa có';
        let ratingScore = 0;
        let totalReviewsCount = 0;

        if (user.role === 'client') {
            const { data: jobs } = await supabase
                .from('jobs')
                .select('id, title, status, budget, created_at')
                .eq('client_id', id)
                .order('created_at', { ascending: false });

            if (jobs && jobs.length > 0) {
                jobsPosted = jobs.length;
                const hiredList = jobs.filter(j => ['planning', 'pending_plan_approval', 'in_progress', 'completed'].includes(j.status));
                const completedList = jobs.filter(j => j.status === 'completed');
                completedCount = completedList.length;
                hireRate = jobsPosted > 0 ? Math.round((hiredList.length / jobsPosted) * 100) : 0;

                // Tỷ lệ hoàn thành dự án
                if (jobsPosted > 0 && completedCount > 0) {
                    completionRateDisplay = `${Math.round((completedCount / jobsPosted) * 100)}%`;
                } else {
                    completionRateDisplay = 'Chưa có';
                }

                // Tính tổng chi tiêu
                totalSpent = jobs
                    .filter(j => j.status === 'completed' || j.status === 'in_progress')
                    .reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);

                recentJobs = jobs.slice(0, 5);
            } else {
                hireRate = 0;
                completionRateDisplay = 'Chưa có';
            }

            // Đánh giá thực tế từ reviews.json
            try {
                const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
                let allReviews = [];
                if (fs.existsSync(reviewFilePath)) {
                    const rawRev = fs.readFileSync(reviewFilePath, 'utf-8').replace(/^\uFEFF/, '').trim();
                    allReviews = rawRev ? JSON.parse(rawRev) : [];
                }
                const cReviews = allReviews.filter(r => r.client_id === id);
                totalReviewsCount = cReviews.length;

                if (totalReviewsCount > 0) {
                    const sum = cReviews.reduce((acc, cur) => acc + (parseFloat(cur.rating) || 5), 0);
                    ratingScore = Math.round((sum / totalReviewsCount) * 10) / 10;
                    ratingDisplay = `${ratingScore.toFixed(1)} / 5.0`;
                } else {
                    ratingDisplay = 'Chưa có';
                    ratingScore = 0;
                }
            } catch (rErr) {
                ratingDisplay = 'Chưa có';
            }

            // Xếp hạng cấp bậc uy tín Khách hàng
            if (totalSpent >= 10000 && completedCount >= 5 && ratingScore >= 4.8) {
                creditTier = 'Kim Cương (VIP)';
                tierBadge = 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800';
            } else if (completedCount >= 2 || totalSpent >= 2000) {
                creditTier = 'Hạng A (Uy Tín Cao)';
                tierBadge = 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800';
            } else if (jobsPosted > 0) {
                creditTier = 'Thành viên mới';
                tierBadge = 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800';
            } else {
                creditTier = 'Khách mới';
                tierBadge = 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
            }
        } else if (user.role === 'freelancer') {
            // 1. Thống kê dự án của Freelancer
            const { data: apps } = await supabase
                .from('job_applications')
                .select(`
                    id, status, bid_amount, created_at,
                    jobs (id, title, status, budget)
                `)
                .eq('freelancer_id', id);

            const acceptedApps = (apps || []).filter(a => a.status === 'accepted' || (a.jobs && ['planning', 'pending_plan_approval', 'in_progress', 'completed'].includes(a.jobs.status)));
            const completedJobs = (acceptedApps || []).filter(a => a.jobs && a.jobs.status === 'completed');
            
            completedCount = completedJobs.length;
            const totalAssigned = acceptedApps.length;

            if (totalAssigned > 0) {
                const percent = Math.round((completedCount / totalAssigned) * 100);
                completionRateDisplay = `${percent}%`;
            } else {
                completionRateDisplay = 'Chưa có';
            }

            // Tính tổng doanh thu tích lũy
            totalEarnings = completedJobs.reduce((sum, a) => {
                const amount = parseFloat(a.bid_amount) || parseFloat(a.jobs?.budget) || 0;
                return sum + amount;
            }, 0);

            // 2. Lấy đánh giá thực tế từ reviews.json
            try {
                const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
                let allReviews = [];
                if (fs.existsSync(reviewFilePath)) {
                    const rawRev = fs.readFileSync(reviewFilePath, 'utf-8').replace(/^\uFEFF/, '').trim();
                    allReviews = rawRev ? JSON.parse(rawRev) : [];
                }
                const fReviews = allReviews.filter(r => r.freelancer_id === id);
                totalReviewsCount = fReviews.length;

                if (totalReviewsCount > 0) {
                    const sum = fReviews.reduce((acc, cur) => acc + (parseFloat(cur.rating) || 5), 0);
                    ratingScore = Math.round((sum / totalReviewsCount) * 10) / 10;
                    ratingDisplay = `${ratingScore.toFixed(1)} / 5.0`;
                } else {
                    ratingDisplay = 'Chưa có';
                    ratingScore = 0;
                }
            } catch (rErr) {
                ratingDisplay = 'Chưa có';
            }

            // 3. Cấp bậc uy tín thợ
            if (completedCount >= 10 && ratingScore >= 4.8) {
                creditTier = 'Cấp Pro';
                tierBadge = 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800';
            } else if (completedCount >= 3) {
                creditTier = 'Tiềm năng';
                tierBadge = 'bg-indigo-100 text-indigo-800 border-indigo-300 dark:bg-indigo-950 dark:text-indigo-300 dark:border-indigo-800';
            } else if (completedCount > 0) {
                creditTier = 'Tích cực';
                tierBadge = 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800';
            } else {
                creditTier = 'Mới bắt đầu';
                tierBadge = 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
            }
        }

        console.log(`✅ [API GET /api/users] Hồ sơ: ${user.full_name} | Role: ${user.role} | Tier: ${creditTier} | Category: ${primary_category || 'N/A'}`);

        res.status(200).json({
            ...user,
            skills: rawSkills,
            location,
            nickname,
            primary_category,
            portfolios,
            recent_jobs: recentJobs,
            stats: {
                total_spent: totalSpent,
                hire_rate: hireRate,
                jobs_posted: jobsPosted,
                completed_count: completedCount,
                rating: ratingScore,
                rating_display: ratingDisplay,
                total_reviews: totalReviewsCount,
                completion_rate: completionRateDisplay,
                total_earnings: totalEarnings,
                earnings_display: `${totalEarnings.toLocaleString()} Token`,
                response_rate: '100%',
                response_time: '~15 phút',
                credit_tier: creditTier,
                tier_badge: tierBadge
            }
        });
    } catch (err) {
        console.error(`❌ [API GET /api/users] Lỗi: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
});

// 2. Cập nhật Hồ sơ cá nhân (Hỗ trợ Tỉnh Thành, Nickname, Chuyên Môn, Ngân hàng, SĐT)
router.put('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { full_name, avatar_url, cover_url, bio, bank_name, bank_account, bank_owner, phone_number, location, nickname, primary_category, skills } = req.body;
    console.log(`\n📝 [API PUT /api/users/${id}] Cập nhật hồ sơ: ${full_name}`);
    
    try {
        // Lấy thông tin user hiện tại để merge JSON
        const { data: currentUser } = await supabase.from('users').select('skills').eq('id', id).single();
        let existingSkills = {};
        if (currentUser && currentUser.skills) {
            try { existingSkills = JSON.parse(currentUser.skills); } catch(e) { existingSkills.skills = currentUser.skills; }
        }

        // Đóng gói metadata vào trường skills (JSON) để lưu trữ an toàn
        const skillsPayload = JSON.stringify({
            location: location !== undefined ? location : (existingSkills.location || 'TP. Hồ Chí Minh'),
            nickname: nickname !== undefined ? nickname : (existingSkills.nickname || ''),
            primary_category: primary_category !== undefined ? primary_category : (existingSkills.primary_category || ''),
            skills: skills !== undefined ? skills : (existingSkills.skills || existingSkills.skillsText || ''),
            portfolios: req.body.portfolios !== undefined ? req.body.portfolios : (existingSkills.portfolios || [])
        });

        const updateData = {
            full_name: full_name ? full_name.trim() : undefined,
            avatar_url,
            cover_url,
            bio,
            bank_name,
            bank_account,
            bank_owner: bank_owner ? bank_owner.toUpperCase().trim() : undefined,
            phone_number: phone_number || undefined,
            skills: skillsPayload
        };

        // Loại bỏ các trường undefined
        Object.keys(updateData).forEach(key => updateData[key] === undefined && delete updateData[key]);

        const { data, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', id)
            .select('id, full_name, email, role, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner, phone_number, is_email_verified, is_phone_verified, kyc_status, created_at')
            .single();

        if (error) throw error;
        
        console.log(`✅ [API PUT /api/users] Cập nhật thành công cho: ${data.full_name}`);
        res.status(200).json({ 
            message: 'Cập nhật hồ sơ thành công!', 
            user: {
                ...data,
                skills: skills || '',
                location: location || 'TP. Hồ Chí Minh',
                nickname: nickname || '',
                primary_category: primary_category || ''
            }
        });
    } catch (err) {
        console.error(`❌ [API PUT /api/users] Lỗi cập nhật: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
});

// 3. API: Kích hoạt / Xác thực Email
router.post('/api/auth/verify-email', async (req, res) => {
    const { user_id } = req.body;
    console.log(`
✉️ [API POST /api/auth/verify-email] Yêu cầu xác thực email cho user: ${user_id}`);
    try {
        const { data, error } = await supabase
            .from('users')
            .update({ is_email_verified: true })
            .eq('id', user_id)
            .select()
            .single();

        if (error) throw error;
        console.log(`✅ [API POST /api/auth/verify-email] Xác thực email thành công!`);
        res.status(200).json({ message: 'Xác thực Email thành công!', is_email_verified: true });
    } catch (err) {
        console.error(`❌ [API POST /api/auth/verify-email] Lỗi: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
});

// 4. API: Gửi mã OTP xác thực Số điện thoại qua WhatsApp Bot
router.post('/api/auth/send-phone-otp', async (req, res) => {
    const { phone_number, user_id } = req.body;
    console.log(`\n📱 [API POST /api/auth/send-phone-otp] Yêu cầu OTP WhatsApp tới: ${phone_number}`);
    try {
        if (!phone_number || phone_number.length < 9) {
            return res.status(400).json({ error: 'Số điện thoại không hợp lệ! Vui lòng nhập tối thiểu 9-10 chữ số.' });
        }

        const cleanPhone = phone_number.replace(/[^0-9+]/g, '');
        const now = Date.now();
        const existing = phoneOtpStore.get(cleanPhone);

        // Cooldown 60s
        if (existing && (now - existing.lastSentAt < 60000)) {
            const remaining = Math.ceil((60000 - (now - existing.lastSentAt)) / 1000);
            return res.status(429).json({ 
                error: `Vui lòng chờ ${remaining} giây nữa trước khi yêu cầu gửi lại mã OTP WhatsApp.`,
                remainingSeconds: remaining 
            });
        }

        // Tạo mã ngẫu nhiên 6 chữ số cryptographic
        const otpCode = crypto.randomInt(100000, 1000000).toString();
        const otpHash = await bcrypt.hash(otpCode, 10);

        phoneOtpStore.set(cleanPhone, {
            phone: cleanPhone,
            otpHash,
            expiresAt: now + 5 * 60 * 1000,
            lastSentAt: now,
            failedAttempts: 0
        });

        // Gửi qua WhatsApp Service
        const waResult = await sendWhatsAppOtp(cleanPhone, otpCode);

        return res.status(200).json({
            success: true,
            message: `Mã OTP xác thực đã được gửi tới số điện thoại WhatsApp ${cleanPhone}!`,
            cooldownSeconds: 60,
            mode: waResult.mode,
            demo_otp: waResult.mode === 'sandbox' ? otpCode : undefined
        });
    } catch (err) {
        console.error('Lỗi gửi Phone OTP:', err);
        res.status(500).json({ error: err.message });
    }
});

// 5. API: Xác nhận mã OTP Số điện thoại (So khớp bcrypt)
router.post('/api/auth/verify-phone-otp', async (req, res) => {
    const { user_id, phone_number, otp } = req.body;
    console.log(`\n📱 [API POST /api/auth/verify-phone-otp] Xác thực OTP cho user: ${user_id} - SĐT: ${phone_number} - OTP: ${otp}`);
    try {
        if (!phone_number || !otp) {
            return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ số điện thoại và mã OTP!' });
        }

        const cleanPhone = phone_number.replace(/[^0-9+]/g, '');
        const cleanOtp = otp.toString().trim();
        const now = Date.now();

        const record = phoneOtpStore.get(cleanPhone);

        // Hỗ trợ mã test cố định nếu không có record
        let isMatch = false;
        if (record) {
            if (now > record.expiresAt) {
                phoneOtpStore.delete(cleanPhone);
                return res.status(400).json({ error: 'Mã OTP đã hết hiệu lực (quá 5 phút). Vui lòng yêu cầu mã mới.' });
            }

            if (record.failedAttempts >= 3) {
                phoneOtpStore.delete(cleanPhone);
                return res.status(400).json({ error: 'Bạn đã nhập sai OTP quá 3 lần. Mã đã bị hủy để đảm bảo an toàn!' });
            }

            isMatch = await bcrypt.compare(cleanOtp, record.otpHash);
            if (!isMatch) {
                record.failedAttempts += 1;
                const remaining = 3 - record.failedAttempts;
                if (remaining <= 0) {
                    phoneOtpStore.delete(cleanPhone);
                    return res.status(400).json({ error: 'Mã OTP không đúng. Bạn đã nhập sai quá 3 lần, mã đã bị hủy!' });
                }
                return res.status(400).json({ error: `Mã OTP không đúng! Bạn còn ${remaining} lần thử.` });
            }

            phoneOtpStore.delete(cleanPhone);
        } else if (cleanOtp === '123456') {
            isMatch = true;
        } else {
            return res.status(400).json({ error: 'Không tìm thấy yêu cầu xác thực hoặc mã OTP đã hết hạn. Vui lòng bấm gửi lại mã.' });
        }

        if (user_id) {
            const { data, error } = await supabase
                .from('users')
                .update({ 
                    phone_number: cleanPhone,
                    is_phone_verified: true 
                })
                .eq('id', user_id)
                .select()
                .single();

            if (error) throw error;
        }

        await logEvent({
            module: 'AUTH_WHATSAPP',
            action: 'PHONE_VERIFY_SUCCESS',
            level: 'INFO',
            details: `Xác thực SĐT thành công qua WhatsApp cho SĐT: ${cleanPhone}`,
            user_id: user_id || undefined,
            metadata: { phone: cleanPhone }
        });

        console.log(`✅ [API POST /api/auth/verify-phone-otp] Xác thực SĐT thành công: ${cleanPhone}`);
        res.status(200).json({ 
            success: true,
            message: 'Xác thực Số điện thoại qua WhatsApp thành công!', 
            is_phone_verified: true,
            phone_number: cleanPhone 
        });
    } catch (err) {
        console.error(`❌ [API POST /api/auth/verify-phone-otp] Lỗi: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
});

// 5.1 API: Lấy trạng thái WhatsApp Bot
router.get('/api/admin/whatsapp-status', (req, res) => {
    res.json(getWhatsAppStatus());
});

// 6. API: Lấy danh sách Freelancer (Dành cho Chợ Nhân Sự & Talent Hunting)
router.get('/api/freelancers', async (req, res) => {
    try {
        const { category, skill, search } = req.query;
        console.log(`\n🔍 [API GET /api/freelancers] Tìm kiếm nhân sự: Category="${category || 'Tất cả'}" | Skill="${skill || 'Tất cả'}" | Search="${search || ''}"`);

        const { data: freelancers, error } = await supabase
            .from('users')
            .select('id, full_name, email, avatar_url, cover_url, bio, skills, created_at, phone_number, is_email_verified, is_phone_verified')
            .eq('role', 'freelancer')
            .order('created_at', { ascending: false });

        if (error) throw error;

        // Lấy danh sách các jobs đã hoàn thành để tính số lượng và đánh giá cho từng freelancer
        const { data: completedApps } = await supabase
            .from('job_applications')
            .select('freelancer_id, status, job:jobs(status)')
            .eq('status', 'accepted');

        let enrichedFreelancers = (freelancers || []).map(f => {
            let location = f.location || 'TP. Hồ Chí Minh';
            let nickname = '';
            let primary_category = 'Phát triển Website & Web App';
            let skillList = [];

            if (f.skills) {
                try {
                    const parsed = JSON.parse(f.skills);
                    location = parsed.location || location;
                    nickname = parsed.nickname || '';
                    primary_category = parsed.primary_category || primary_category;
                    const rawSkills = parsed.skills || parsed.skillsText || '';
                    skillList = typeof rawSkills === 'string' ? rawSkills.split(',').map(s => s.trim()).filter(Boolean) : (Array.isArray(rawSkills) ? rawSkills : []);
                } catch (e) {
                    skillList = typeof f.skills === 'string' ? f.skills.split(',').map(s => s.trim()).filter(Boolean) : [];
                }
            }

            // Đếm số dự án đã làm
            const fApps = (completedApps || []).filter(a => a.freelancer_id === f.id);
            const completedCount = fApps.length;

            // Tính điểm đánh giá thực tế từ reviews.json
            let ratingScore = null;
            let ratingDisplay = 'Chưa có';
            let reviewCount = 0;
            try {
                const reviewPath = path.join(__dirname, '..', 'data', 'reviews.json');
                if (fs.existsSync(reviewPath)) {
                    const rawRev = fs.readFileSync(reviewPath, 'utf-8').replace(/^\uFEFF/, '').trim();
                    const allRev = rawRev ? JSON.parse(rawRev) : [];
                    const fRev = allRev.filter(r => r.freelancer_id === f.id);
                    if (fRev.length > 0) {
                        reviewCount = fRev.length;
                        const sumScore = fRev.reduce((acc, cur) => acc + (cur.rating || 5), 0);
                        ratingScore = Math.round((sumScore / fRev.length) * 10) / 10;
                        ratingDisplay = `${ratingScore.toFixed(1)} / 5.0`;
                    }
                }
            } catch (err) {
                console.warn('Lỗi đọc reviews cho freelancer:', err.message);
            }

            return {
                id: f.id,
                full_name: f.full_name || 'Freelancer Ẩn Danh',
                email: f.email,
                avatar_url: f.avatar_url,
                bio: f.bio || 'Chuyên viên lập trình và phát triển phần mềm trên sàn KGS Work.',
                location,
                nickname,
                primary_category,
                skills: skillList.length > 0 ? skillList : ['ReactJS', 'NodeJS', 'TypeScript'],
                completed_projects: completedCount,
                rating_score: ratingScore,
                rating_display: ratingDisplay,
                reviews_count: reviewCount,
                hourly_rate: 150000, // Token / giờ hoặc ngân sách gợi ý
                is_email_verified: Boolean(f.is_email_verified),
                is_phone_verified: Boolean(f.is_phone_verified),
                created_at: f.created_at
            };
        });

        // Áp dụng bộ lọc
        if (category && category !== 'all') {
            const catLower = category.toLowerCase();
            enrichedFreelancers = enrichedFreelancers.filter(f => 
                f.primary_category.toLowerCase().includes(catLower) ||
                f.skills.some(s => s.toLowerCase().includes(catLower)) ||
                f.bio.toLowerCase().includes(catLower)
            );
        }

        if (skill && skill !== 'all') {
            const skillLower = skill.toLowerCase();
            enrichedFreelancers = enrichedFreelancers.filter(f => 
                f.skills.some(s => s.toLowerCase().includes(skillLower)) ||
                f.bio.toLowerCase().includes(skillLower)
            );
        }

        if (search) {
            const searchLower = search.toLowerCase();
            enrichedFreelancers = enrichedFreelancers.filter(f => 
                f.full_name.toLowerCase().includes(searchLower) ||
                f.bio.toLowerCase().includes(searchLower) ||
                f.skills.some(s => s.toLowerCase().includes(searchLower)) ||
                f.primary_category.toLowerCase().includes(searchLower)
            );
        }

        console.log(`✅ [API GET /api/freelancers] Trả về ${enrichedFreelancers.length} nhân sự`);
        res.status(200).json({ success: true, freelancers: enrichedFreelancers });
    } catch (err) {
        console.error(`❌ [API GET /api/freelancers] Lỗi: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
});

// 7. API: Lấy danh sách Ngân hàng chính quy & Tra cứu số tài khoản (Chuẩn VietQR/NAPAS)
const { getVietnamBanks, lookupAccountName } = require('../services/bankService');

router.get('/api/banks', async (req, res) => {
    try {
        const banks = await getVietnamBanks();
        res.status(200).json({ success: true, banks });
    } catch (err) {
        console.error('Lỗi lấy danh sách ngân hàng:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

router.post('/api/banks/lookup-account', async (req, res) => {
    try {
        const { bin, bank_code, bank_name, account_number, user_id, current_user_name } = req.body;
        
        let userName = current_user_name;
        if (!userName && user_id) {
            const { data: user } = await supabase.from('users').select('full_name').eq('id', user_id).single();
            if (user) userName = user.full_name;
        }

        const result = await lookupAccountName({
            bin,
            bank_code,
            bank_name,
            account_number,
            user_id,
            current_user_name: userName
        });

        res.status(200).json(result);
    } catch (err) {
        console.error('Lỗi tra cứu tài khoản ngân hàng:', err);
        res.status(400).json({ success: false, error: err.message });
    }
});


// -------------------------------------------------------------
// FORGOT PASSWORD FLOW
// -------------------------------------------------------------
const passwordResetStore = new Map();

router.post(['/forgot-password', '/api/auth/forgot-password'], async (req, res) => {
    const { email } = req.body;
    console.log(`[API POST /api/auth/forgot-password] Email: ${email}`);
    try {
        if (!email) {
            return res.status(400).json({ error: 'Vui lòng cung cấp email!' });
        }

        // Kiểm tra email tồn tại
        const { data: user, error } = await supabase
            .from('users')
            .select('id, full_name, email')
            .eq('email', email)
            .single();

        if (error || !user) {
            // Để bảo mật, không trả về lỗi "Email không tồn tại", cứ báo là đã gửi email.
            return res.status(200).json({ success: true, message: 'Nếu email tồn tại trong hệ thống, chúng tôi đã gửi mã xác thực đến đó.' });
        }

        const now = Date.now();
        const existing = passwordResetStore.get(email);
        if (existing) {
            const remaining = Math.ceil((60000 - (now - existing.lastSentAt)) / 1000);
            if (remaining > 0) {
                return res.status(429).json({
                    error: `Vui lòng chờ ${remaining} giây nữa trước khi yêu cầu gửi lại mã OTP.`,
                    remainingSeconds: remaining
                });
            }
        }

        // Tạo mã ngẫu nhiên 6 chữ số
        const crypto = require('crypto');
        const otpCode = crypto.randomInt(100000, 1000000).toString();
        const bcrypt = require('bcrypt');
        const otpHash = await bcrypt.hash(otpCode, 10);

        passwordResetStore.set(email, {
            otpHash,
            expiresAt: now + 5 * 60 * 1000,
            lastSentAt: now,
            failedAttempts: 0
        });

        const { sendResetPasswordEmail } = require('../services/emailService');
        const emailResult = await sendResetPasswordEmail(user.email, user.full_name, otpCode);

        return res.status(200).json({
            success: true,
            message: 'Mã OTP đặt lại mật khẩu đã được gửi đến email của bạn!',
            demo_otp: emailResult.demo_otp // Trả về nếu ở mode sandbox
        });

    } catch (err) {
        console.error('Lỗi forgot-password:', err);
        return res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});

router.post(['/reset-password', '/api/auth/reset-password'], async (req, res) => {
    const { email, otp, newPassword } = req.body;
    console.log(`[API POST /api/auth/reset-password] Email: ${email}`);
    try {
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ thông tin!' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Mật khẩu mới phải có ít nhất 6 ký tự.' });
        }

        const record = passwordResetStore.get(email);
        if (!record) {
            return res.status(400).json({ error: 'Yêu cầu đặt lại mật khẩu không tồn tại hoặc đã hết hạn.' });
        }

        const now = Date.now();
        if (now > record.expiresAt) {
            passwordResetStore.delete(email);
            return res.status(400).json({ error: 'Mã OTP đã hết hiệu lực. Vui lòng yêu cầu lại.' });
        }

        if (record.failedAttempts >= 3) {
            passwordResetStore.delete(email);
            return res.status(400).json({ error: 'Nhập sai quá nhiều lần. Yêu cầu đã bị hủy.' });
        }

        const bcrypt = require('bcrypt');
        const isMatch = await bcrypt.compare(otp.toString().trim(), record.otpHash);
        
        if (!isMatch && otp.toString().trim() !== '123456') { // Fallback for dev
            record.failedAttempts += 1;
            const remaining = 3 - record.failedAttempts;
            if (remaining <= 0) {
                passwordResetStore.delete(email);
                return res.status(400).json({ error: 'Mã OTP không đúng quá 3 lần, yêu cầu đã bị hủy.' });
            }
            return res.status(400).json({ error: `Mã OTP không đúng! Bạn còn ${remaining} lần thử.` });
        }

        // Hash mật khẩu mới
        const newPasswordHash = await bcrypt.hash(newPassword, 10);

        // Cập nhật vào DB
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: newPasswordHash })
            .eq('email', email);

        if (updateError) {
            throw updateError;
        }

        // Xóa record
        passwordResetStore.delete(email);

        return res.status(200).json({
            success: true,
            message: 'Đặt lại mật khẩu thành công! Bạn có thể đăng nhập ngay.'
        });

    } catch (err) {
        console.error('Lỗi reset-password:', err);
        return res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});


// ==========================================
// 🔴 GOOGLE LOGIN & REGISTRATION
// ==========================================
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post(['/google-login', '/api/auth/google-login'], async (req, res) => {
    const { credential, role } = req.body;
    
    try {
        if (!credential) {
            return res.status(400).json({ error: 'Missing Google credential' });
        }

        // Verify Google token
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { email, name, picture } = payload;

        // Check if user exists
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (user) {
            // LOGIN SUCCESSFUL
            await logEvent({
                module: 'AUTH',
                action: 'GOOGLE_LOGIN_SUCCESS',
                level: 'INFO',
                details: `Người dùng ${email} (${user.role.toUpperCase()}) đăng nhập bằng Google thành công.`,
                user_id: user.id,
                user_email: email,
                user_role: user.role
            });
            return res.status(200).json({ success: true, user });
        } else {
            // USER DOES NOT EXIST -> REGISTRATION REQUIRED
            if (!role) {
                // Tell frontend to ask for a role
                return res.status(200).json({ 
                    requires_registration: true, 
                    message: 'Vui lòng chọn vai trò để hoàn tất đăng ký.',
                    email, 
                    name, 
                    picture 
                });
            }

            // PROCEED TO REGISTER
            // Validate role
            if (!['freelancer', 'client'].includes(role)) {
                return res.status(400).json({ error: 'Vai trò không hợp lệ!' });
            }

            // Create a random secure password for Google users
            const crypto = require('crypto');
            const randomPassword = crypto.randomBytes(16).toString('hex');
            const hashedPassword = await bcrypt.hash(randomPassword, 10);

            // Insert into Database
            const { data: newUser, error: insertError } = await supabase
                .from('users')
                .insert([
                    {
                        full_name: name,
                        email: email,
                        password: hashedPassword,
                        role: role,
                        phone: '', 
                        is_verified: true, // Google email is already verified
                        avatar_url: picture,
                        created_at: new Date().toISOString()
                    }
                ])
                .select('*')
                .single();

            if (insertError) {
                console.error('Lỗi khi insert user Google:', insertError);
                throw new Error('Không thể tạo tài khoản từ Google!');
            }

            await logEvent({
                module: 'AUTH',
                action: 'GOOGLE_REGISTER_SUCCESS',
                level: 'INFO',
                details: `Tạo tài khoản thành công qua Google cho ${email} (${role.toUpperCase()})`,
                user_id: newUser.id,
                user_email: email,
                user_role: role
            });

            // LOGIN AFTER REGISTRATION
            return res.status(200).json({ success: true, user: newUser, message: 'Tạo tài khoản và đăng nhập thành công!' });
        }

    } catch (err) {
        console.error('Lỗi Google Auth:', err);
        return res.status(401).json({ error: 'Xác thực Google thất bại hoặc có lỗi xảy ra.' });
    }
});

module.exports = router;
