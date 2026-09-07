const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
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

// Route Upload Ảnh (Cloudinary)
router.post('/upload-image', uploadImage.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Không có file ảnh' });
    
    res.status(200).json({
        message: 'Upload ảnh thành công!',
        imageUrl: req.file.path // Đường dẫn ảnh trên Cloudinary
    });
});

// Route Upload File/Video (AWS S3)
router.post('/upload-file', uploadFile.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Không có file' });
    
    res.status(200).json({
        message: 'Upload file thành công!',
        fileUrl: req.file.location // Đường dẫn file trên S3
    });
});

// Upload Ảnh API mới (Cloudinary)
router.post('/api/upload/image', (req, res) => {
    uploadImage.single('file')(req, res, function (err) {
        if (err) return res.status(500).json({ error: 'Cloudinary Error: ' + err.message });
        if (!req.file) return res.status(400).json({ error: 'Không có file ảnh' });
        res.status(200).json({ url: req.file.path, type: 'image' });
    });
});

// Upload File nặng/Video API mới (S3)
router.post('/api/upload/file', (req, res) => {
    uploadFile.single('file')(req, res, function (err) {
        if (err) return res.status(500).json({ error: 'S3 Error: ' + err.message });
        if (!req.file) return res.status(400).json({ error: 'Không có file' });
        
        let type = 'document';
        if (req.file.mimetype.startsWith('video/')) type = 'video';
        else if (req.file.mimetype.startsWith('audio/')) type = 'audio';

        res.status(200).json({ url: req.file.location, type: type });
    });
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
        let hireRate = 0;
        let jobsPosted = 0;

        if (user.role === 'client') {
            const { data: jobs } = await supabase
                .from('jobs')
                .select('id, status, budget')
                .eq('client_id', id);

            if (jobs && jobs.length > 0) {
                jobsPosted = jobs.length;
                const hiredCount = jobs.filter(j => ['planning', 'pending_plan_approval', 'in_progress', 'completed'].includes(j.status)).length;
                hireRate = Math.round((hiredCount / jobsPosted) * 100);

                // Tính tổng chi tiêu
                totalSpent = jobs
                    .filter(j => j.status === 'completed' || j.status === 'in_progress')
                    .reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);
            }
        }

        console.log(`✅ [API GET /api/users] Hồ sơ: ${user.full_name} | Role: ${user.role} | Category: ${primary_category || 'N/A'}`);

        res.status(200).json({
            ...user,
            skills: rawSkills,
            location,
            nickname,
            primary_category,
            stats: {
                total_spent: totalSpent,
                hire_rate: hireRate,
                jobs_posted: jobsPosted,
                rating: 5.0 // Đánh giá mặc định
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
