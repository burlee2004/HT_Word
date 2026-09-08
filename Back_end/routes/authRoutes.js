const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');
const uploadImage = require('../config/cloudinary');
const uploadFile = require('../config/s3');
const { logEvent } = require('../services/auditLogger');

// Route Đăng ký (Register)
router.post('/register', async (req, res) => {
    const { email, password, full_name, role, main_category, skills } = req.body;

    try {
        // 1. Mã hóa mật khẩu (Giả sử bạn đã dùng bcrypt)
        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Tạo User trong bảng public.users
        const { data: newUser, error: userError } = await supabase
            .from('users')
            .insert([{ email, password: hashedPassword, full_name, role }])
            .select()
            .single();

        if (userError) throw userError;

        // 3. Nếu là Freelancer, tạo thêm Profile
        if (role === 'freelancer') {
            const { error: profileError } = await supabase
                .from('freelancer_profiles')
                .insert([{
                    user_id: newUser.id,
                    main_category: main_category || 'Other',
                    skills: skills || [] // Mảng JSON chứa tối đa 5 skills
                }]);

            if (profileError) {
                // Rollback: Xóa user nếu tạo profile thất bại để tránh rác dữ liệu
                await supabase.from('users').delete().eq('id', newUser.id);
                throw profileError;
            }
        }

        // Ghi log kiểm toán đăng ký
        await logEvent({
            module: 'AUTH',
            action: 'REGISTER',
            level: 'INFO',
            details: `Người dùng mới đăng ký thành công: ${email} | Vai trò: [${role.toUpperCase()}] | Họ tên: ${full_name}`,
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
router.post('/upload-image', (req, res) => {
    uploadImage.single('image')(req, res, function (err) {
        if (err && err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File đã vượt quá 50MB' });
        }
        if (!err && req.file && (req.file.path || req.file.secure_url)) {
            return res.status(200).json({
                message: 'Upload ảnh thành công!',
                imageUrl: req.file.path || req.file.secure_url
            });
        }
        // Fallback sang local disk nếu Cloudinary bị lỗi mạng/cấu hình
        uploadLocal.single('image')(req, res, function (localErr) {
            if (localErr) {
                if (localErr.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'File đã vượt quá 50MB' });
                }
                return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
            }
            if (!req.file) {
                return res.status(400).json({ error: 'Thiếu file ảnh' });
            }
            const host = req.get('host') || 'localhost:5000';
            const protocol = req.protocol || 'http';
            const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
            return res.status(200).json({
                message: 'Upload ảnh thành công (Local Storage)!',
                imageUrl: localUrl
            });
        });
    });
});

// Route Upload File/Video (Local Storage trực tiếp + S3 Fallback)
router.post('/upload-file', (req, res) => {
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (req.file) {
            const host = req.get('host') || 'localhost:5000';
            const protocol = req.protocol || 'http';
            const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
            return res.status(200).json({
                message: 'Upload file thành công!',
                fileUrl: localUrl,
                url: localUrl
            });
        }
        
        // Dự phòng nếu local không nhận được file
        uploadFile.single('file')(req, res, function (err) {
            if (err) {
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'File đã vượt quá 50MB' });
                }
                return res.status(400).json({ error: 'Lỗi tải tệp: ' + err.message });
            }
            if (!req.file) return res.status(400).json({ error: 'Thiếu file tải lên' });
            return res.status(200).json({
                message: 'Upload file thành công!',
                fileUrl: req.file.location || req.file.path,
                url: req.file.location || req.file.path
            });
        });
    });
});

// Upload Ảnh API mới (Cloudinary + Local)
router.post('/api/upload/image', (req, res) => {
    uploadImage.single('file')(req, res, function (err) {
        if (err && err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File đã vượt quá 50MB' });
        }
        if (!err && req.file && (req.file.path || req.file.secure_url)) {
            return res.status(200).json({ url: req.file.path || req.file.secure_url, type: 'image' });
        }
        uploadLocal.single('file')(req, res, function (localErr) {
            if (localErr) {
                if (localErr.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'File đã vượt quá 50MB' });
                }
                return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
            }
            if (!req.file) return res.status(400).json({ error: 'Không thể upload ảnh' });
            const host = req.get('host') || 'localhost:5000';
            const protocol = req.protocol || 'http';
            const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
            res.status(200).json({ url: localUrl, imageUrl: localUrl, type: 'image' });
        });
    });
});

// Upload File nặng/Video API mới (Local Disk Storage trực tiếp + S3)
router.post('/api/upload/file', (req, res) => {
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (req.file) {
            const host = req.get('host') || 'localhost:5000';
            const protocol = req.protocol || 'http';
            const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
            let type = 'document';
            if (req.file.mimetype && req.file.mimetype.startsWith('video/')) type = 'video';
            else if (req.file.mimetype && req.file.mimetype.startsWith('audio/')) type = 'audio';
            return res.status(200).json({ url: localUrl, fileUrl: localUrl, type: type });
        }

        // Dự phòng sang S3
        uploadFile.single('file')(req, res, function (err) {
            if (err) {
                if (err.code === 'LIMIT_FILE_SIZE') {
                    return res.status(400).json({ error: 'File đã vượt quá 50MB' });
                }
                return res.status(400).json({ error: 'Không thể upload file: ' + err.message });
            }
            if (!req.file) return res.status(400).json({ error: 'Thiếu file' });
            let type = 'document';
            if (req.file.mimetype && req.file.mimetype.startsWith('video/')) type = 'video';
            else if (req.file.mimetype && req.file.mimetype.startsWith('audio/')) type = 'audio';
            return res.status(200).json({ url: req.file.location || req.file.path, fileUrl: req.file.location || req.file.path, type: type });
        });
    });
});

// Route Tải xuống & Xem tệp tin (Khắc phục triệt để lỗi S3 AccessDenied và hỗ trợ mọi định dạng)
router.get(['/api/download-file', '/api/view-file'], async (req, res) => {
    try {
        const targetUrl = req.query.url || req.query.file_url || '';
        const customName = req.query.name || req.query.filename || '';
        const isView = (req.path === '/api/view-file' || req.query.action === 'view');

        if (!targetUrl) {
            return res.status(400).json({ error: 'Thiếu đường dẫn tệp tin (url)' });
        }

        // 1. Trường hợp file cục bộ trong thư mục /uploads
        if (targetUrl.includes('/uploads/')) {
            const parts = targetUrl.split('/uploads/');
            const filename = decodeURIComponent(parts[1].split('?')[0]);
            const filePath = path.join(__dirname, '../uploads', filename);

            if (fs.existsSync(filePath)) {
                const displayName = customName || filename;
                const mimeType = getMimeType(displayName);
                res.setHeader('Content-Type', mimeType);
                if (isView) {
                    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(displayName)}"`);
                } else {
                    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(displayName)}"`);
                }
                return res.sendFile(filePath);
            }
        }

        // 2. Trường hợp file nằm trên AWS S3
        if (targetUrl.includes('amazonaws.com') || targetUrl.includes('htwork_files/')) {
            let s3Key = '';
            if (targetUrl.includes('amazonaws.com/')) {
                const parts = targetUrl.split('amazonaws.com/');
                s3Key = decodeURIComponent(parts[1].split('?')[0]);
            } else if (targetUrl.includes('htwork_files/')) {
                s3Key = 'htwork_files/' + targetUrl.split('htwork_files/')[1].split('?')[0];
            } else {
                s3Key = targetUrl;
            }

            const command = new GetObjectCommand({
                Bucket: process.env.AWS_S3_BUCKET_NAME || 'htwork-app-storage',
                Key: s3Key
            });

            try {
                const s3Res = await s3Client.send(command);
                const originalFilename = customName || path.basename(s3Key);
                const mimeType = getMimeType(originalFilename) || s3Res.ContentType || 'application/octet-stream';

                res.setHeader('Content-Type', mimeType);
                if (isView) {
                    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(originalFilename)}"`);
                } else {
                    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalFilename)}"`);
                }
                if (s3Res.ContentLength) {
                    res.setHeader('Content-Length', s3Res.ContentLength);
                }
                return s3Res.Body.pipe(res);
            } catch (s3Err) {
                console.error('S3 GetObject Error:', s3Err.message);
                return res.status(404).json({ error: 'Không thể truy xuất tệp từ máy chủ lưu trữ: ' + s3Err.message });
            }
        }

        // 3. Fallback cho URL khác (Cloudinary, external link)
        return res.redirect(targetUrl);
    } catch (err) {
        console.error('Lỗi khi tải hoặc xem tệp:', err);
        res.status(500).json({ error: 'Lỗi khi tải hoặc mở tệp: ' + err.message });
    }
});

// Route Upload Base64 (Hỗ trợ Dán ảnh trực tiếp từ Clipboard / Ctrl+V)
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
        if (user.skills) {
            try {
                const parsed = JSON.parse(user.skills);
                location = parsed.location || location;
                nickname = parsed.nickname || '';
                primary_category = parsed.primary_category || '';
                rawSkills = parsed.skills || parsed.skillsText || '';
            } catch (e) {
                // If not JSON, it's raw text
                rawSkills = user.skills;
                nickname = user.skills;
            }
        }

        // Tính toán Thống kê cho Khách hàng (Client Stats)
        let totalSpent = 0;
        let hireRate = 100;
        let jobsPosted = 0;
        let completedCount = 0;
        let recentJobs = [];
        let creditTier = 'Hạng A (Uy tín cao)';
        let tierBadge = 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800';

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
                hireRate = jobsPosted > 0 ? Math.round((hiredList.length / jobsPosted) * 100) : 100;

                // Tính tổng chi tiêu
                totalSpent = jobs
                    .filter(j => j.status === 'completed' || j.status === 'in_progress')
                    .reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);

                if (totalSpent >= 10000 && hireRate >= 80) {
                    creditTier = 'Kim Cương (VIP)';
                    tierBadge = 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950 dark:text-purple-300 dark:border-purple-800';
                } else if (totalSpent === 0 && jobsPosted <= 1) {
                    creditTier = 'Khách mới (Đã nạp Escrow)';
                    tierBadge = 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800';
                }

                recentJobs = jobs.slice(0, 5);
            }
        }

        console.log(`✅ [API GET /api/users] Hồ sơ: ${user.full_name} | Role: ${user.role} | Tier: ${creditTier} | Category: ${primary_category || 'N/A'}`);

        res.status(200).json({
            ...user,
            skills: rawSkills,
            location,
            nickname,
            primary_category,
            recent_jobs: recentJobs,
            stats: {
                total_spent: totalSpent,
                hire_rate: hireRate,
                jobs_posted: jobsPosted,
                completed_count: completedCount,
                rating: 5.0, // Đánh giá mặc định
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
        // Đóng gói metadata vào trường skills (JSON) để lưu trữ an toàn
        const skillsPayload = JSON.stringify({
            location: location || 'TP. Hồ Chí Minh',
            nickname: nickname || '',
            primary_category: primary_category || '',
            skills: skills || ''
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

// 4. API: Gửi mã OTP xác thực Số điện thoại
router.post('/api/auth/send-phone-otp', async (req, res) => {
    const { phone_number } = req.body;
    console.log(`
📱 [API POST /api/auth/send-phone-otp] Gửi OTP tới: ${phone_number}`);
    try {
        if (!phone_number || phone_number.length < 9) {
            throw new Error('Số điện thoại không hợp lệ!');
        }
        // Demo OTP cố định hoặc ngẫu nhiên
        const demoOtp = '123456';
        res.status(200).json({ 
            message: `Mã OTP xác thực đã được gửi tới ${phone_number}! (Mã xác minh thử nghiệm: ${demoOtp})`,
            demo_otp: demoOtp
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 5. API: Xác nhận mã OTP Số điện thoại
router.post('/api/auth/verify-phone-otp', async (req, res) => {
    const { user_id, phone_number, otp } = req.body;
    console.log(`
📱 [API POST /api/auth/verify-phone-otp] Xác thực OTP cho user: ${user_id} - OTP: ${otp}`);
    try {
        if (otp !== '123456') {
            throw new Error('Mã OTP không chính xác hoặc đã hết hạn! (Mã thử nghiệm là 123456)');
        }

        const { data, error } = await supabase
            .from('users')
            .update({ 
                phone_number: phone_number,
                is_phone_verified: true 
            })
            .eq('id', user_id)
            .select()
            .single();

        if (error) throw error;
        console.log(`✅ [API POST /api/auth/verify-phone-otp] Xác thực SĐT thành công!`);
        res.status(200).json({ message: 'Xác thực Số điện thoại thành công!', is_phone_verified: true });
    } catch (err) {
        console.error(`❌ [API POST /api/auth/verify-phone-otp] Lỗi: ${err.message}`);
        res.status(400).json({ error: err.message });
    }
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
            let ratingScore = 5.0;
            let reviewCount = 0;
            try {
                const reviewPath = path.join(__dirname, '..', 'data', 'reviews.json');
                if (fs.existsSync(reviewPath)) {
                    const allRev = JSON.parse(fs.readFileSync(reviewPath, 'utf-8'));
                    const fRev = allRev.filter(r => r.freelancer_id === f.id);
                    if (fRev.length > 0) {
                        reviewCount = fRev.length;
                        const sumScore = fRev.reduce((acc, cur) => acc + (cur.rating || 5), 0);
                        ratingScore = Math.round((sumScore / fRev.length) * 10) / 10;
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
                bio: f.bio || 'Chuyên viên lập trình và phát triển phần mềm trên sàn HT Work.',
                location,
                nickname,
                primary_category,
                skills: skillList.length > 0 ? skillList : ['ReactJS', 'NodeJS', 'TypeScript'],
                completed_projects: completedCount,
                rating_score: ratingScore,
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

module.exports = router;
