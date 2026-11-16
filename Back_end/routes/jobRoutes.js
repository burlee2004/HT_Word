const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');
const { logEvent } = require('../services/auditLogger');
const settingsStore = require('../services/settingsStore');
const aiModeration = require('../services/aiModeration');
const subscriptionService = require('../services/subscriptionService');

// 1. API: Khách hàng đăng Job mới (Miễn phí đăng tin + AI Kiểm duyệt Llama/GPT-OSS)
router.post('/api/jobs', async (req, res) => {
    const { client_id, title, description, budget, category_id, category_name, tags, is_negotiable } = req.body;
    const parsedBudget = (is_negotiable || !budget || isNaN(budget) || parseFloat(budget) <= 0) ? 0 : parseFloat(budget);
    console.log(`\n📢 [API POST /api/jobs] Nhận yêu cầu tạo dự án: "${title}" | Danh mục: "${category_name || 'Mặc định'}" | Ngân sách: ${parsedBudget} Token | Client: ${client_id}`);
    
    try {
        if (!title || !title.trim()) throw new Error('Vui lòng nhập tiêu đề dự án');
        if (!description || !description.trim()) throw new Error('Vui lòng nhập mô tả chi tiết dự án');

        // Đóng gói Danh mục & Tags vào nội dung mô tả một cách chuyên nghiệp
        let fullDescription = description ? description.trim() : '';
        if (category_name) {
            fullDescription = `[Danh mục: ${category_name.trim()}]\n` + fullDescription;
        }
        if (tags && ((Array.isArray(tags) && tags.length > 0) || (typeof tags === 'string' && tags.trim()))) {
            const tagList = Array.isArray(tags) ? tags.join(', ') : tags.trim();
            fullDescription += `\n\n🏷️ [Kỹ năng yêu cầu: ${tagList}]`;
        }

        // --- KIỂM DUYỆT BÀI ĐĂNG BẰNG AI HOẶC QUẢN TRỊ VIÊN ---
        const isAiEnabled = settingsStore.getAiModerationEnabled();
        let jobStatus = 'open';
        let moderationResult = {
            is_approved: true,
            score: 100,
            reason: 'Tự động duyệt bài đăng',
            flagged: false,
            model: 'Direct'
        };

        if (isAiEnabled) {
            moderationResult = await aiModeration.moderateJobContent({
                title,
                description: fullDescription,
                category_name
            });

            if (!moderationResult.is_approved) {
                jobStatus = 'pending_review'; // Tạm giữ bài để Admin hậu kiểm
            } else {
                jobStatus = 'open'; // AI phê duyệt, hiển thị ngay tức thì
            }
        } else {
            jobStatus = 'pending_review'; // Admin tắt AI tự duyệt -> Chờ duyệt thủ công
            moderationResult = {
                is_approved: false,
                score: 50,
                reason: 'Đang chờ Admin duyệt thủ công (Tính năng AI tự duyệt đang tạm tắt)',
                flagged: false,
                model: 'Manual-Queue'
            };
        }

        const { data, error } = await supabase
            .from('jobs')
            .insert([{ client_id, title: title.trim(), description: fullDescription, budget: parsedBudget, status: jobStatus }])
            .select();

        if (error) throw error;
        const createdJob = data[0];

        // Lưu thông tin kiểm duyệt vào bộ nhớ & file
        aiModeration.saveModeration(createdJob.id, {
            ...moderationResult,
            client_id,
            title: title.trim(),
            job_status: jobStatus
        });

        // Gửi thông báo cho Client
        if (jobStatus === 'open') {
            await supabase.from('notifications').insert([{
                user_id: client_id,
                title: '🎉 Dự án đã được AI phê duyệt tự động!',
                content: `Dự án "${title}" (${moderationResult.score}/100đ) đã được AI duyệt và mở công khai trên Sàn để Freelancer ứng tuyển.`
            }]);
        } else {
            await supabase.from('notifications').insert([{
                user_id: client_id,
                title: '⏳ Dự án đang chờ Quản trị viên xét duyệt',
                content: `Dự án "${title}" của bạn đang được Ban Quản Trị xem xét trước khi đăng tải. ${moderationResult.reason}`
            }]);
        }

        // Ghi log kiểm toán
        await logEvent({
            module: 'JOB_MODERATION',
            action: jobStatus === 'open' ? 'AI_APPROVED' : 'PENDING_MODERATION',
            level: jobStatus === 'open' ? 'INFO' : 'WARN',
            details: `Tạo dự án: "${title}" | Trạng thái: ${jobStatus} | AI Điểm: ${moderationResult.score}/100 | ${moderationResult.reason}`,
            user_id: client_id,
            metadata: { job_id: createdJob.id, title, budget: parsedBudget, moderation: moderationResult }
        });

        console.log(`✅ [API POST /api/jobs] Tạo dự án thành công! ID: ${createdJob.id} | Trạng thái: ${jobStatus}`);
        res.status(201).json({
            message: jobStatus === 'open' ? 'Đăng dự án thành công! AI đã duyệt bài của bạn.' : 'Đăng dự án thành công! Tin đang chờ Ban Quản Trị xét duyệt.',
            job: { ...createdJob, moderation: moderationResult }
        });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs] Thất bại: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 1b. API: Lấy thông tin chi tiết một Job theo ID
router.get('/api/jobs/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { data: job, error } = await supabase
            .from('jobs')
            .select(`*, users (id, full_name, avatar_url, skills, created_at)`)
            .eq('id', id)
            .single();

        if (error || !job) throw new Error('Không tìm thấy dự án');
        const moderation = aiModeration.getModeration(id);
        res.status(200).json({ success: true, job: { ...job, moderation } });
    } catch (error) {
        res.status(404).json({ success: false, error: error.message });
    }
});

// 1c. API: Admin lấy toàn bộ Jobs kèm thông tin AI Moderation
router.get('/api/admin/jobs', async (req, res) => {
    try {
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select(`*, users:client_id (id, full_name, email, avatar_url)`)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const allMods = aiModeration.getAllModerations();
        const enriched = (jobs || []).map(j => ({
            ...j,
            moderation: allMods[j.id] || {
                is_approved: j.status !== 'pending_review' && j.status !== 'rejected',
                score: j.status === 'open' ? 90 : (j.status === 'rejected' ? 10 : 50),
                reason: j.status === 'open' ? 'Bài đăng chuẩn mực' : (j.status === 'rejected' ? 'Đã từ chối' : 'Đang chờ xét duyệt'),
                flagged: j.status === 'pending_review'
            }
        }));

        res.status(200).json({ success: true, jobs: enriched });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// 1d. API: Admin Phê duyệt / Từ chối bài đăng (Override AI)
router.post('/api/admin/jobs/:id/moderate', async (req, res) => {
    const { id } = req.params;
    const { action, note, admin_id } = req.body; // action: 'approve' | 'reject'
    try {
        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).json({ error: 'Hành động không hợp lệ. Chỉ chấp nhận approve hoặc reject.' });
        }

        const newStatus = action === 'approve' ? 'open' : 'rejected';
        const { data: job, error } = await supabase
            .from('jobs')
            .update({ status: newStatus })
            .eq('id', id)
            .select()
            .single();

        if (error || !job) throw new Error('Không tìm thấy dự án hoặc không thể cập nhật trạng thái');

        // Ghi đè quyết định của Admin
        const modRecord = aiModeration.adminOverride(id, { action, note, admin_id });

        // Gửi thông báo cho khách hàng
        const notiTitle = action === 'approve' ? '✅ Dự án của bạn đã được Admin phê duyệt' : '❌ Dự án của bạn đã bị Admin từ chối';
        const notiContent = action === 'approve'
            ? `Dự án "${job.title}" đã được Quản trị viên duyệt công khai trên Sàn việc làm.`
            : `Dự án "${job.title}" không được phê duyệt. Lý do: ${note || 'Vi phạm tiêu chuẩn cộng đồng'}`;

        await supabase.from('notifications').insert([{
            user_id: job.client_id,
            title: notiTitle,
            content: notiContent
        }]);

        // Ghi log kiểm toán
        await logEvent({
            module: 'ADMIN_MODERATION',
            action: action === 'approve' ? 'ADMIN_APPROVE_JOB' : 'ADMIN_REJECT_JOB',
            level: action === 'approve' ? 'INFO' : 'WARN',
            details: `Admin ${action === 'approve' ? 'phê duyệt' : 'từ chối'} dự án #${id}: "${job.title}". Ghi chú: ${note || 'Không có'}`,
            user_id: admin_id || 'ADMIN',
            metadata: { job_id: id, action, note }
        });

        res.status(200).json({
            success: true,
            message: action === 'approve' ? 'Đã phê duyệt và mở công khai dự án!' : 'Đã từ chối bài đăng dự án.',
            job: { ...job, moderation: modRecord }
        });
    } catch (error) {
        console.error('Lỗi Admin Moderate Job:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

// 2. API: Freelancer xem danh sách Job đang Open kèm Điểm Tín Dụng & Danh Mục
router.get('/api/jobs', async (req, res) => {
    try {
        const { category, search } = req.query;

        const { data: jobs, error } = await supabase
            .from('jobs')
            .select(`*, users (id, full_name, avatar_url, skills, created_at)`)
            .eq('status', 'open')
            .order('created_at', { ascending: false });
        
        if (error) throw error;

        // Lấy tất cả jobs để tính toán uy tín tự động cho từng client
        const { data: allJobs } = await supabase
            .from('jobs')
            .select('client_id, status, budget');

        const boostedJobsMap = subscriptionService.getBoostedJobsMap();

        let jobsEnriched = (jobs || []).map(job => {
            const clientJobs = (allJobs || []).filter(j => j.client_id === job.client_id);
            const totalPosted = clientJobs.length;
            const completedJobs = clientJobs.filter(j => ['completed', 'in_progress', 'planning', 'pending_plan_approval'].includes(j.status));
            const totalSpent = clientJobs
                .filter(j => j.status === 'completed' || j.status === 'in_progress')
                .reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);

            // Kiểm tra trạng thái Đẩy Top / Tuyển Gấp từ Hệ thống Monetization
            const boostRecord = boostedJobsMap[job.id] || null;
            const isUrgent = !!boostRecord && boostRecord.boost_type === 'urgent_tag';
            const isBoosted = !!boostRecord && (boostRecord.boost_type === 'job_boost' || !isUrgent);

            // Phân tích Category & Tags từ Description
            const catMatch = (job.description || '').match(/\[Danh mục:\s*([^\]]+)\]/i);
            const tagsMatch = (job.description || '').match(/\[Kỹ năng yêu cầu:\s*([^\]]+)\]/i);

            const jobCategory = catMatch ? catMatch[1].trim() : 'Phát triển Website & Web App';
            const jobTags = tagsMatch ? tagsMatch[1].split(',').map(t => t.trim()).filter(Boolean) : [];

            // Làm sạch description hiển thị (bỏ phần header tag nếu muốn)
            const cleanDesc = (job.description || '')
                .replace(/\[Danh mục:\s*[^\]]+\]\n?/gi, '')
                .replace(/\n\n🏷️ \[Kỹ năng yêu cầu:\s*[^\]]+\]/gi, '')
                .trim();
            
            const completionRate = totalPosted > 0 && completedJobs.length > 0 ? `${Math.round((completedJobs.length / totalPosted) * 100)}%` : 'Chưa có';
            
            // Lấy rating thực tế của client từ reviews.json
            let clientRatingScore = null;
            let clientRatingDisplay = 'Chưa có';
            try {
                const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
                if (fs.existsSync(reviewFilePath)) {
                    const rawRev = fs.readFileSync(reviewFilePath, 'utf-8').replace(/^\uFEFF/, '').trim();
                    const allRev = rawRev ? JSON.parse(rawRev) : [];
                    const cRev = allRev.filter(r => r.client_id === job.client_id);
                    if (cRev.length > 0) {
                        const sumScore = cRev.reduce((acc, cur) => acc + (parseFloat(cur.rating) || 5), 0);
                        clientRatingScore = Math.round((sumScore / cRev.length) * 10) / 10;
                        clientRatingDisplay = `${clientRatingScore.toFixed(1)} / 5.0`;
                    }
                }
            } catch (rErr) {}

            let creditTier = 'Khách mới';
            let tierBadge = 'bg-gray-100 text-gray-800 border-gray-300';
            if (totalSpent >= 10000 && completedJobs.length >= 5 && (clientRatingScore || 0) >= 4.8) {
                creditTier = 'Kim Cương (VIP)';
                tierBadge = 'bg-purple-100 text-purple-800 border-purple-300';
            } else if (completedJobs.length >= 2 || totalSpent >= 2000) {
                creditTier = 'Hạng A (Uy tín cao)';
                tierBadge = 'bg-emerald-100 text-emerald-800 border-emerald-300';
            } else if (totalPosted > 0) {
                creditTier = 'Thành viên mới';
                tierBadge = 'bg-blue-100 text-blue-800 border-blue-300';
            }

            return {
                ...job,
                category_name: jobCategory,
                tags: jobTags,
                clean_description: cleanDesc,
                client_trust: {
                    total_tokens_spent: totalSpent,
                    total_projects_posted: totalPosted,
                    total_projects_completed: completedJobs.length,
                    completion_rate: completionRate,
                    rating_score: clientRatingScore,
                    rating_display: clientRatingDisplay,
                    credit_tier: creditTier,
                    tier_badge: tierBadge
                },
                is_boosted: isBoosted,
                is_urgent: isUrgent,
                boost_details: boostRecord
            };
        });

        // Sắp xếp ưu tiên: Tin Đẩy Top & Tuyển Gấp luôn nằm ở vị trí đầu tiên
        jobsEnriched.sort((a, b) => {
            if (a.is_boosted && !b.is_boosted) return -1;
            if (!a.is_boosted && b.is_boosted) return 1;
            if (a.is_urgent && !b.is_urgent) return -1;
            if (!a.is_urgent && b.is_urgent) return 1;
            return new Date(b.created_at) - new Date(a.created_at);
        });

        if (category && category !== 'all') {
            const catLower = category.toLowerCase();
            jobsEnriched = jobsEnriched.filter(j => 
                (j.category_name || '').toLowerCase().includes(catLower) ||
                (j.description || '').toLowerCase().includes(catLower) ||
                (j.title || '').toLowerCase().includes(catLower)
            );
        }

        res.status(200).json({ jobs: jobsEnriched });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. API: Freelancer ứng tuyển (Báo giá & Kiểm soát Hạn Mức Chào Thầu Bids Hàng Ngày)
router.get('/api/jobs/freelancer-bid-quota/:freelancer_id', async (req, res) => {
    try {
        const { freelancer_id } = req.params;
        const quota = await subscriptionService.getFreelancerBidQuota(freelancer_id, supabase);
        res.status(200).json(quota);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/api/jobs/apply', async (req, res) => {
    const { job_id, freelancer_id, cover_letter, bid_amount } = req.body;
    try {
        if (!job_id || !freelancer_id) {
            return res.status(400).json({ error: 'Thiếu thông tin dự án hoặc chuyên gia ứng tuyển' });
        }

        const parsedBid = parseFloat(bid_amount);
        if (isNaN(parsedBid) || parsedBid <= 0) {
            return res.status(400).json({ error: 'Mức giá chào thầu không hợp lệ' });
        }

        // 1. Kiểm tra dự án có đang mở không
        const { data: job, error: jobErr } = await supabase
            .from('jobs')
            .select('id, title, client_id, status, budget')
            .eq('id', job_id)
            .single();

        if (jobErr || !job) {
            return res.status(404).json({ error: 'Dự án không tồn tại hoặc đã bị xóa' });
        }

        if (job.status !== 'open') {
            return res.status(400).json({ error: 'Dự án này đã đóng hoặc đang trong giai đoạn triển khai' });
        }

        if (job.client_id === freelancer_id) {
            return res.status(400).json({ error: 'Bạn không thể tự chào thầu cho dự án do chính bạn đăng tuyển!' });
        }

        // 2. Kiểm tra xem Freelancer đã nộp hồ sơ cho dự án này chưa (tránh nộp trùng lặp lãng phí lượt)
        const { data: existingApp } = await supabase
            .from('job_applications')
            .select('id, status')
            .eq('job_id', job_id)
            .eq('freelancer_id', freelancer_id)
            .maybeSingle();

        if (existingApp) {
            return res.status(400).json({ error: 'Bạn đã nộp hồ sơ ứng tuyển cho dự án này rồi! Vui lòng chờ phản hồi từ phía khách hàng.' });
        }

        // 3. KIỂM TRA HẠN MỨC CHÀO THẦU (5 bids/ngày với Tân Binh, 25 bids/ngày với Pro, Không giới hạn với Agency, hoặc trừ extra_bids)
        const bidCheck = await subscriptionService.checkAndConsumeFreelancerBid(freelancer_id, supabase);
        if (!bidCheck.allowed) {
            return res.status(403).json({
                error: bidCheck.error,
                quota: bidCheck.quota
            });
        }

        // 4. Lưu hồ sơ ứng tuyển vào Cơ sở dữ liệu
        const { data, error } = await supabase
            .from('job_applications')
            .insert([{ job_id, freelancer_id, cover_letter, bid_amount: parsedBid, status: 'pending' }])
            .select();
        
        if (error) throw error;

        // 5. Gửi thông báo đến Client có ứng viên mới
        try {
            await supabase.from('notifications').insert([{
                user_id: job.client_id,
                title: '📩 Có Freelancer mới gửi hồ sơ chào thầu!',
                content: `Dự án "${job.title}" vừa nhận được báo giá ${parsedBid.toLocaleString('vi-VN')} Token. Hãy vào kiểm tra hồ sơ ứng viên ngay!`
            }]);
        } catch (nErr) {
            console.warn('[Notification Warning]:', nErr.message);
        }

        const successMsg = bidCheck.consumed_extra
            ? `Ứng tuyển thành công! (${bidCheck.message})`
            : 'Ứng tuyển thành công! Hồ sơ của bạn đã được chuyển tới khách hàng.';

        res.status(201).json({
            message: successMsg,
            application: data[0],
            quota: bidCheck.quota,
            consumed_extra: bidCheck.consumed_extra
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. API: Khách hàng Chấp nhận Freelancer & KHÓA ESCROW NGAY LẬP TỨC
router.post('/api/jobs/accept-freelancer', async (req, res) => {
    const { client_id, application_id } = req.body;
    try {
        // Lấy thông tin ứng tuyển (để biết số tiền trúng thầu)
        const { data: application, error: fetchErr } = await supabase
            .from('job_applications')
            .select('*')
            .eq('id', application_id)
            .single();
        if (fetchErr || !application) throw new Error('Không tìm thấy ứng viên');

        const bidAmount = parseFloat(application.bid_amount);

        // Kiểm tra ví Client
        const { data: wallet, error: walletErr } = await supabase
            .from('wallets')
            .select('balance, locked_balance')
            .eq('user_id', client_id)
            .single();

        if (walletErr || !wallet) throw new Error('Không tìm thấy ví người dùng');
        if (wallet.balance < bidAmount) throw new Error('Số dư không đủ để Khóa Escrow cho dự án này. Vui lòng nạp thêm Token.');

        // 1. Thực hiện Khóa Escrow: Trừ balance, cộng locked_balance
        const newBalance = wallet.balance - bidAmount;
        const newLocked = wallet.locked_balance + bidAmount;
        const { error: updateWalletErr } = await supabase
            .from('wallets')
            .update({ balance: newBalance, locked_balance: newLocked })
            .eq('user_id', client_id);
        if (updateWalletErr) throw new Error('Lỗi khi khóa tiền Escrow');

        // Ghi Log giao dịch Khóa Escrow
        await supabase.from('transactions').insert([{
            user_id: client_id,
            target_id: application.job_id, // Gắn ID dự án để dễ truy vết
            amount: bidAmount,
            type: 'escrow_lock',
            status: 'success'
        }]);

        // 2. Cập nhật trạng thái Application thành 'accepted'
        await supabase.from('job_applications').update({ status: 'accepted' }).eq('id', application_id);
            
        // 3. Đổi trạng thái Job sang 'planning' và cập nhật Ngân sách dự án thành Giá thỏa thuận của Freelancer
        await supabase.from('jobs').update({ status: 'planning', budget: bidAmount }).eq('id', application.job_id);

        // 4. Gửi thông báo cho Freelancer yêu cầu lập kế hoạch
        await supabase.from('notifications').insert([{
            user_id: application.freelancer_id,
            title: 'Trúng thầu dự án!',
            content: 'Khách hàng đã chọn bạn và khóa tiền an toàn (Escrow). Hãy vào mục Dự án đang làm để Lập Kế Hoạch (Milestones).'
        }]);

        res.status(200).json({ message: 'Đã khóa Escrow và chọn Freelancer thành công!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.2. API: Khách hàng Duyệt Kế hoạch (Bắt đầu dự án chính thức)
router.post('/api/jobs/start-project', async (req, res) => {
    const { client_id, job_id } = req.body;
    try {
        // Kiểm tra xem đã có kế hoạch chưa
        const { data: milestones, error: mErr } = await supabase.from('milestones').select('amount').eq('job_id', job_id);
        if (mErr || !milestones || milestones.length === 0) throw new Error('Không có kế hoạch nào để duyệt');
        
        // Đổi trạng thái Job sang in_progress
        await supabase.from('jobs').update({ status: 'in_progress' }).eq('id', job_id);

        // Chuyển status của Milestone đầu tiên sang IN_PROGRESS
        const sortedMilestones = await supabase.from('milestones').select('id').eq('job_id', job_id).order('created_at', { ascending: true }).limit(1);
        if (sortedMilestones.data.length > 0) {
            await supabase.from('milestones').update({ status: 'IN_PROGRESS' }).eq('id', sortedMilestones.data[0].id);
        }

        // Thông báo Freelancer
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        if (appData) {
            await supabase.from('notifications').insert([{
                user_id: appData.freelancer_id,
                title: 'Dự án chính thức bắt đầu!',
                content: `Khách hàng đã chốt kế hoạch. Bắt tay vào làm việc ngay!`
            }]);
        }

        res.status(200).json({ message: 'Đã duyệt kế hoạch và bắt đầu dự án thành công!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.3. API: Khách hàng Hủy Kế hoạch & Hoàn Tiền Escrow (Bảo vệ Client)
router.post('/api/jobs/cancel-planning', async (req, res) => {
    const { client_id, job_id } = req.body;
    try {
        if (!client_id || !job_id) {
            throw new Error('Thiếu thông tin client_id hoặc job_id');
        }

        // Kiểm tra trạng thái dự án
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        
        if (job.status !== 'planning' && job.status !== 'pending_plan_approval') {
            throw new Error('Chỉ có thể thu hồi dự án khi đang ở giai đoạn Lập Kế Hoạch (Planning/Pending Plan)');
        }

        const budget = parseFloat(job.budget || 0);

        // Lấy ví của Client
        const { data: wallet, error: walletError } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        if (walletError || !wallet) throw new Error('Không tìm thấy ví người dùng');

        // Hoàn tiền Escrow an toàn: Trừ locked_balance (nếu có), cộng lại vào balance khả dụng
        const currentLocked = parseFloat(wallet.locked_balance || 0);
        const newLocked = Math.max(0, currentLocked - budget);
        const newBalance = parseFloat(wallet.balance || 0) + budget;

        await supabase.from('wallets').update({ 
            balance: newBalance,
            locked_balance: newLocked 
        }).eq('user_id', client_id);

        // Ghi transaction Hoàn tiền Escrow
        await supabase.from('transactions').insert([{
            user_id: client_id,
            target_id: job_id,
            amount: budget,
            type: 'escrow_refund',
            status: 'success'
        }]);

        // Nếu là Direct Hire (hợp đồng chỉ định riêng cho mối ruột), đổi sang 'cancelled'
        // Nếu là job đấu thầu thông thường, đổi về 'open' để các Freelancer khác có thể ứng tuyển tiếp
        const isDirectHire = job.description && (job.description.includes('Hợp đồng chỉ định') || job.description.includes('Mối Ruột'));
        const nextStatus = isDirectHire ? 'cancelled' : 'open';

        await supabase.from('jobs').update({ status: nextStatus }).eq('id', job_id);
        
        // Đổi trạng thái Application sang revoked để ghi nhận đã bị thu hồi
        await supabase.from('job_applications').update({ status: 'revoked' }).eq('job_id', job_id).in('status', ['accepted', 'pending']);

        // Xóa các milestones nháp chưa duyệt nếu có
        await supabase.from('milestones').delete().eq('job_id', job_id);

        // Thông báo cho Freelancer & gửi tin nhắn vào khung chat 1-1
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'revoked').limit(1);
        if (appData && appData.length > 0) {
            const freelancerId = appData[0].freelancer_id;
            await supabase.from('notifications').insert([{
                user_id: freelancerId,
                title: 'Khách hàng thu hồi thỏa thuận',
                content: `Khách hàng đã thu hồi dự án "${job.title}" và hệ thống đã hoàn trả Token Escrow.`
            }]);

            try {
                const directMessageStore = require('../services/directMessageStore');
                await directMessageStore.sendDirectMessage({
                    sender_id: client_id,
                    receiver_id: freelancerId,
                    content: `🚫 [THU HỒI DỰ ÁN] (Mã dự án: #${job_id})\nKhách hàng đã thu hồi dự án "${job.title}". Toàn bộ Token ký quỹ Escrow (${budget.toLocaleString()} Token) đã được hoàn trả về ví của Khách hàng.`
                });
            } catch (e) {
                console.error('Lỗi gửi direct message khi thu hồi dự án:', e.message);
            }
        }

        // Ghi log kiểm toán
        logEvent({
            module: 'JOB',
            action: 'CANCEL_PLANNING_REFUND',
            actor_id: client_id,
            target_id: job_id,
            level: 'INFO',
            details: `Khách hàng thu hồi dự án "${job.title}" trong giai đoạn lập kế hoạch, hoàn trả ${budget.toLocaleString()} Token Escrow về ví.`,
            metadata: { job_id, budget, client_id, new_balance: newBalance, next_status: nextStatus }
        });

        res.status(200).json({ 
            success: true, 
            message: `Đã thu hồi thỏa thuận và hoàn trả ${budget.toLocaleString()} Token vào ví của bạn thành công!`,
            refunded_amount: budget,
            new_balance: newBalance
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. API: Khách hàng xem danh sách Freelancer ứng tuyển
router.get('/api/client/:client_id/applications', async (req, res) => {
    const { client_id } = req.params;
    try {
        // 1. Tìm các job do client này đăng
        const { data: jobs, error: jobsError } = await supabase
            .from('jobs')
            .select('id, title')
            .eq('client_id', client_id);
            
        if (jobsError) throw jobsError;
        if (!jobs || jobs.length === 0) return res.status(200).json({ applications: [] });

        const jobIds = jobs.map(j => j.id);

        // 2. Tìm các ứng tuyển thuộc về các job này
        const { data: apps, error: appsError } = await supabase
            .from('job_applications')
            .select(`
                *,
                jobs (title),
                users!job_applications_freelancer_id_fkey (full_name, email)
            `)
            .in('job_id', jobIds)
            .eq('status', 'pending');

        if (appsError) throw appsError;
        
        res.status(200).json({ applications: apps });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 6.5. API: Khách hàng xem danh sách các Yêu cầu (Job) mình đã tạo
router.get('/api/client/:client_id/my-jobs', async (req, res) => {
    const { client_id } = req.params;
    console.log(`\n📋 [API GET /api/client/my-jobs] Tải danh sách dự án cho Client ID: ${client_id}`);
    try {
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select('*')
            .eq('client_id', client_id)
            .order('created_at', { ascending: false });
            
        if (error) throw error;

        // Lấy đánh giá do khách hàng đã viết từ reviews.json
        try {
            const fs = require('fs');
            const path = require('path');
            const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
            if (fs.existsSync(reviewFilePath)) {
                const allRev = JSON.parse(fs.readFileSync(reviewFilePath, 'utf8') || '[]');
                for (let job of (jobs || [])) {
                    if (job.status === 'completed') {
                        const r = allRev.find(rev => rev.job_id === job.id && rev.client_id === client_id);
                        if (r) job.review = r;
                    }
                }
            }
        } catch (e) {
            console.error('Lỗi đọc reviews.json (client my-jobs):', e);
        }

        const allMods = aiModeration.getAllModerations();
        for (let job of (jobs || [])) {
            job.moderation = allMods[job.id] || null;
        }
        console.log(`✅ [API GET /api/client/my-jobs] Trả về ${jobs ? jobs.length : 0} dự án`);
        res.status(200).json({ jobs });
    } catch (error) {
        console.error(`❌ [API GET /api/client/my-jobs] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 7. API: Lấy danh sách job Freelancer đang làm (kể cả PLANNING và REVOKED)
router.get('/api/freelancer/:id/active-jobs', async (req, res) => {
    const { id } = req.params;
    console.log(`\n📋 [API GET /api/freelancer/active-jobs] Tải danh sách việc cho Freelancer ID: ${id}`);
    try {
        const { data: apps, error } = await supabase
            .from('job_applications')
            .select(`
                job_id,
                status,
                cover_letter,
                bid_amount,
                created_at,
                jobs (id, title, description, budget, client_id, status, created_at)
            `)
            .eq('freelancer_id', id)
            .in('status', ['accepted', 'revoked']);
            
        if (error) throw error;
        if (!apps || apps.length === 0) {
            console.log(`✅ [API GET /api/freelancer/active-jobs] Trả về 0 việc`);
            return res.status(200).json({ jobs: [] });
        }
        
        const jobs = apps.map(app => { 
            const j = app.jobs; 
            if (j) {
                j.app_status = app.status; // 'accepted' hoặc 'revoked'
                j.bid_amount = app.bid_amount;
                j.cover_letter = app.cover_letter;
                j.app_created_at = app.created_at;
            }
            return j; 
        }).filter(Boolean);

        // Sắp xếp dự án mới nhất lên đầu danh sách
        jobs.sort((a, b) => {
            const timeA = new Date(a.created_at || a.app_created_at || 0).getTime();
            const timeB = new Date(b.created_at || b.app_created_at || 0).getTime();
            if (timeB !== timeA) return timeB - timeA;
            return String(b.id).localeCompare(String(a.id));
        });
        
        console.log(`✅ [API GET /api/freelancer/active-jobs] Trả về ${jobs.length} việc (gồm cả việc đang làm & bị thu hồi)`);
        
        // Lấy thêm milestone và revision cho từng job
        for (let job of jobs) {
            const { data: milestones } = await supabase
                .from('milestones')
                .select('*, milestone_revisions(feedback_text, screenshot_urls, created_at)')
                .eq('job_id', job.id)
                .order('created_at', { ascending: true });
            job.milestones = milestones || [];
        }

        // Lấy đánh giá của khách hàng từ reviews.json
        try {
            const fs = require('fs');
            const path = require('path');
            const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
            if (fs.existsSync(reviewFilePath)) {
                const allRev = JSON.parse(fs.readFileSync(reviewFilePath, 'utf8') || '[]');
                for (let job of jobs) {
                    if (job.status === 'completed') {
                        const r = allRev.find(rev => rev.job_id === job.id && rev.freelancer_id === id);
                        if (r) job.review = r;
                    }
                }
            }
        } catch (e) {
            console.error('Lỗi đọc reviews.json:', e);
        }

        res.status(200).json({ jobs });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 17. API: Dọn dẹp dự án cũ
router.delete('/api/jobs/cleanup/:client_id', async (req, res) => {
    const { client_id } = req.params;
    try {
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
        
        const { data, error } = await supabase
            .from('jobs')
            .delete()
            .eq('client_id', client_id)
            .in('status', ['completed', 'closed'])
            .lt('created_at', oneMonthAgo.toISOString());
            
        if (error) throw error;
        res.status(200).json({ message: 'Đã dọn dẹp các dự án cũ đã hoàn thành quá 1 tháng!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


// API: Freelancer xóa dự án bị thu hồi khỏi danh sách
router.delete('/api/freelancer/:freelancer_id/applications/:job_id', async (req, res) => {
    const { freelancer_id, job_id } = req.params;
    try {
        const { error } = await supabase.from('job_applications')
            .delete()
            .eq('freelancer_id', freelancer_id)
            .eq('job_id', job_id)
            .eq('status', 'revoked');
            
        if (error) throw error;
        res.status(200).json({ message: 'Đã xóa dự án khỏi danh sách' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 8. API: Freelancer ứng tuyển lại dự án đã bị thu hồi
router.post('/api/jobs/reapply', async (req, res) => {
    const { job_id, freelancer_id, cover_letter, bid_amount } = req.body;
    console.log(`\n📢 [API POST /api/jobs/reapply] Freelancer ${freelancer_id} ứng tuyển lại Job: ${job_id}`);
    try {
        // Kiểm tra xem job có còn open không
        const { data: job, error: jobErr } = await supabase.from('jobs').select('status, title, client_id, budget').eq('id', job_id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        if (job.status !== 'open') throw new Error('Dự án hiện không còn mở để ứng tuyển');

        // Cập nhật lại application từ 'revoked' sang 'pending'
        const { data, error } = await supabase
            .from('job_applications')
            .update({ 
                status: 'pending',
                cover_letter: cover_letter || 'Freelancer gửi lại đề xuất ứng tuyển',
                bid_amount: bid_amount ? parseFloat(bid_amount) : parseFloat(job.budget)
            })
            .eq('job_id', job_id)
            .eq('freelancer_id', freelancer_id)
            .select();

        if (error) throw error;

        // Lấy tên freelancer
        const { data: user } = await supabase.from('users').select('full_name').eq('id', freelancer_id).single();

        // Gửi thông báo cho Client
        await supabase.from('notifications').insert([{
            user_id: job.client_id,
            title: 'Freelancer ứng tuyển lại',
            content: `Freelancer ${user?.full_name || 'Ứng viên'} đã gửi lại đề xuất ứng tuyển cho dự án "${job.title}".`
        }]);

        console.log(`✅ [API POST /api/jobs/reapply] Ứng tuyển lại thành công! Trả trạng thái về pending cho Client duyệt.`);
        res.status(200).json({ message: 'Đã ứng tuyển lại thành công! Dự án đã chuyển về danh sách chờ khách duyệt.', application: data ? data[0] : null });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/reapply] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 12. API: Khách hàng gửi Lời Mời Nhận Việc (Invite Freelancer to Job)
router.post('/api/jobs/invite', async (req, res) => {
    const { client_id, freelancer_id, job_id, message } = req.body;
    console.log(`\n💌 [API POST /api/jobs/invite] Client ${client_id} mời Freelancer ${freelancer_id} cho Job ${job_id}`);
    try {
        if (!client_id || !freelancer_id || !job_id) {
            throw new Error('Thiếu thông tin mời nhận việc!');
        }

        const { data: job } = await supabase.from('jobs').select('title, budget').eq('id', job_id).single();
        const { data: client } = await supabase.from('users').select('full_name').eq('id', client_id).single();

        if (!job) throw new Error('Không tìm thấy dự án tương ứng.');

        // Gửi thông báo đến Freelancer
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: '💌 Lời mời nhận dự án mới!',
            content: `Khách hàng ${client?.full_name || 'Khách hàng'} đã mời bạn tham gia dự án: "${job.title}" (Ngân sách: ${parseFloat(job.budget).toLocaleString()} Token). Lời nhắn: "${message || 'Rất mong được hợp tác cùng bạn!'}"`
        }]);

        console.log(`✅ [API POST /api/jobs/invite] Đã gửi lời mời thành công!`);
        res.status(200).json({ success: true, message: 'Đã gửi lời mời nhận việc thành công đến Freelancer!' });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/invite] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 13. API: Khách hàng chỉnh sửa hoặc Hủy/Đóng bài đăng dự án
router.put('/api/jobs/:id', async (req, res) => {
    const { id } = req.params;
    const { client_id, title, description, budget, category_id, category_name, tags, deadline, freelancer_type, files, status } = req.body;
    try {
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        if (client_id && job.client_id !== client_id) throw new Error('Bạn không có quyền chỉnh sửa dự án này');
        if (job.status !== 'open' && status === 'cancelled') {
            throw new Error('Chỉ có thể hủy dự án khi đang ở trạng thái Mở (Open)');
        }

        const updatePayload = {};
        if (title) updatePayload.title = title.trim();

        if (description !== undefined || category_name !== undefined || tags !== undefined || deadline !== undefined || freelancer_type !== undefined || files !== undefined) {
            let fullDescription = (description || '').trim();

            if (category_name && !fullDescription.includes('[Danh mục:')) {
                fullDescription = `[Danh mục: ${category_name.trim()}]\n` + fullDescription;
            }
            if (deadline && !fullDescription.includes('[Hạn chót')) {
                fullDescription += `\n\n⏰ [Hạn chót mong muốn: ${deadline}]`;
            }
            if (freelancer_type && !fullDescription.includes('[Đối tượng:')) {
                fullDescription += `\n👥 [Đối tượng: ${freelancer_type}]`;
            }
            if (tags && ((Array.isArray(tags) && tags.length > 0) || (typeof tags === 'string' && tags.trim())) && !fullDescription.includes('[Kỹ năng yêu cầu:')) {
                const tagList = Array.isArray(tags) ? tags.join(', ') : tags.trim();
                fullDescription += `\n\n🏷️ [Kỹ năng yêu cầu: ${tagList}]`;
            }
            if (files && Array.isArray(files) && files.length > 0 && !fullDescription.includes('[Tài liệu đính kèm:')) {
                fullDescription += `\n\n📎 [Tài liệu đính kèm:`;
                files.forEach((f, i) => {
                    fullDescription += `\n${i+1}. ${f.name} -> ${f.url}`;
                });
                fullDescription += `]`;
            }

            updatePayload.description = fullDescription;
        }

        if (budget !== undefined) {
            const newBudget = parseFloat(budget);
            if (isNaN(newBudget) || newBudget <= 0) throw new Error('Ngân sách không hợp lệ');
            
            // Nếu tăng ngân sách, kiểm tra số dư ví
            if (newBudget > (job.budget || 0)) {
                const diff = newBudget - (job.budget || 0);
                const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', job.client_id).single();
                if (!wallet || wallet.balance < newBudget) {
                    throw new Error(`Số dư ví không đủ để tăng ngân sách lên ${newBudget.toLocaleString()} Token (Ví hiện có: ${wallet ? wallet.balance.toLocaleString() : 0} Token)`);
                }
            }
            updatePayload.budget = newBudget;
        }

        if (status) updatePayload.status = status;

        const { data, error } = await supabase
            .from('jobs')
            .update(updatePayload)
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        try {
            await logEvent({
                module: 'JOB',
                action: 'UPDATE_JOB',
                level: 'INFO',
                details: `Cập nhật dự án #${id} - "${data.title}"`,
                user_id: job.client_id,
                metadata: { job_id: id, title: data.title, budget: data.budget }
            });
        } catch(e) {}

        res.status(200).json({ success: true, message: 'Cập nhật dự án thành công!', job: data });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// 13b. API: Khách hàng xóa dự án (Delete Job)
router.delete('/api/jobs/:id', async (req, res) => {
    const { id } = req.params;
    const client_id = req.body?.client_id || req.query?.client_id;
    try {
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        if (client_id && job.client_id !== client_id) throw new Error('Bạn không có quyền xóa dự án này');
        
        if (['in_progress', 'completed'].includes(job.status)) {
            throw new Error('Không thể xóa dự án đang trong quá trình thực hiện hoặc đã hoàn thành.');
        }

        // Xóa các applications liên quan trước nếu có
        try {
            await supabase.from('job_applications').delete().eq('job_id', id);
        } catch(e) {}
        
        // Thử xóa job trực tiếp
        const { error: delErr } = await supabase.from('jobs').delete().eq('id', id);
        if (delErr) {
            // Nếu có foreign key constraint, đổi status thành cancelled
            await supabase.from('jobs').update({ status: 'cancelled' }).eq('id', id);
        }

        try {
            await logEvent({
                module: 'JOB',
                action: 'DELETE_JOB',
                level: 'INFO',
                details: `Xóa dự án #${id} - "${job.title}"`,
                user_id: job.client_id,
                metadata: { job_id: id, title: job.title }
            });
        } catch(e) {}

        res.status(200).json({ success: true, message: 'Đã xóa dự án thành công!' });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// 14. API: Khách hàng Yêu Cầu Sửa Kế Hoạch Milestones (Request Plan Revision)
router.post('/api/jobs/request-plan-revision', async (req, res) => {
    const { client_id, job_id, feedback } = req.body;
    console.log(`\n✏️ [API POST /api/jobs/request-plan-revision] Client ${client_id} yêu cầu sửa kế hoạch Job: ${job_id}`);
    try {
        if (!client_id || !job_id) throw new Error('Thiếu thông tin yêu cầu sửa kế hoạch');

        const { data: job, error: jobErr } = await supabase
            .from('jobs')
            .select('*, job_applications(freelancer_id, status)')
            .eq('id', job_id)
            .single();
            
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        if (job.client_id !== client_id) throw new Error('Bạn không có quyền thao tác trên dự án này');
        if (job.status !== 'pending_plan_approval') throw new Error('Dự án không ở trạng thái chờ duyệt kế hoạch');

        // Xóa milestones cũ đang ở PENDING để Freelancer làm lại kế hoạch mới
        await supabase.from('milestones').delete().match({ job_id: job_id, status: 'PENDING' });

        // Cập nhật trạng thái job về lại planning
        const { error: updateErr } = await supabase
            .from('jobs')
            .update({ status: 'planning' })
            .eq('id', job_id);

        if (updateErr) throw updateErr;

        // Tìm Freelancer đang nhận job
        const acceptedApp = (job.job_applications || []).find(a => a.status === 'accepted');
        if (acceptedApp && acceptedApp.freelancer_id) {
            await supabase.from('notifications').insert([{
                user_id: acceptedApp.freelancer_id,
                title: '✏️ Khách hàng yêu cầu chỉnh sửa Kế hoạch Milestones',
                content: `Khách hàng đã xem kế hoạch dự án "${job.title}" và yêu cầu bạn chỉnh sửa lại:\n"${feedback || 'Vui lòng điều chỉnh lại các mốc công việc và hạn giao cho phù hợp hơn.'}"`
            }]);
        }

        console.log(`✅ [API POST /api/jobs/request-plan-revision] Đã trả trạng thái về planning cho Freelancer điều chỉnh!`);
        res.status(200).json({ success: true, message: 'Đã gửi yêu cầu chỉnh sửa kế hoạch cho Freelancer thành công!' });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/request-plan-revision] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 15. API: Lấy chi tiết Hồ Sơ Năng Lực & Lịch Sử Dự Án Đã Làm (Work History & Portfolio)
router.get('/api/freelancers/:id/work-history', async (req, res) => {
    const { id } = req.params;
    try {
        // Lấy thông tin user
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('id, full_name, email, avatar_url, skills, role, created_at, kyc_status, phone_number')
            .eq('id', id)
            .single();

        if (userErr || !user) throw new Error('Không tìm thấy Freelancer');

        // Lấy danh sách các ứng tuyển đã được duyệt (accepted)
        const { data: apps, error: appErr } = await supabase
            .from('job_applications')
            .select('job_id, status, created_at, jobs(*)')
            .eq('freelancer_id', id)
            .eq('status', 'accepted');

        // Lấy danh sách đánh giá từ reviews.json
        let reviews = [];
        try {
            const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');
            if (fs.existsSync(reviewFilePath)) {
                const rawRev = fs.readFileSync(reviewFilePath, 'utf-8').replace(/^\uFEFF/, '').trim();
                const allRev = rawRev ? JSON.parse(rawRev) : [];
                reviews = allRev.filter(r => r.freelancer_id === id);
            }
        } catch (e) {}

        const completedJobs = [];
        const inProgressJobs = [];

        (apps || []).forEach(app => {
            const j = app.jobs;
            if (!j) return;

            const review = reviews.find(r => r.job_id === j.id);

            const jobItem = {
                id: j.id,
                title: j.title,
                budget: parseFloat(j.budget) || 0,
                status: j.status,
                created_at: j.created_at,
                client: j.clients || { full_name: 'Khách Hàng' },
                rating: review ? review.rating : null,
                rating_display: review ? `${review.rating} ⭐` : 'Chưa có đánh giá',
                review_comment: review ? review.comment : 'Chưa có nhận xét.'
            };

            if (j.status === 'completed') {
                completedJobs.push(jobItem);
            } else if (['in_progress', 'planning', 'pending_plan_approval'].includes(j.status)) {
                inProgressJobs.push(jobItem);
            }
        });

        // Tính điểm đánh giá trung bình
        let avgRating = 'Chưa có';
        let ratingScore = null;
        if (reviews.length > 0) {
            let totalRating = reviews.reduce((sum, r) => sum + (parseFloat(r.rating) || 5), 0);
            ratingScore = Math.round((totalRating / reviews.length) * 10) / 10;
            avgRating = `${ratingScore.toFixed(1)} / 5.0`;
        }

        let rawSkills = [];
        let location = 'Việt Nam';
        let bio = 'Chuyên gia uy tín trên sàn KGS Work.';
        let portfolios = [];
        
        if (user.skills) {
            try {
                const parsed = JSON.parse(user.skills);
                location = parsed.location || location;
                portfolios = parsed.portfolios || [];
                if (parsed.skills) {
                    rawSkills = parsed.skills.split(',').map(s => s.trim()).filter(Boolean);
                }
            } catch(e) {
                if (typeof user.skills === 'string') {
                    rawSkills = user.skills.split(',').map(s => s.trim()).filter(Boolean);
                }
            }
        }
        
        if (!user.bio && rawSkills.length > 0) {
            bio = `Chuyên gia ${rawSkills.slice(0, 3).join(', ')} với ${completedJobs.length} dự án đã hoàn thành trên sàn KGS Work.`;
        } else if (user.bio) {
            bio = user.bio;
        }

        // Kiểm tra Gói VIP Freelancer
        let isVip = false;
        let vipTier = 'Cơ bản';
        let vipBadge = null;
        let vipDays = 0;
        let vipExpires = null;
        try {
            const sub = subscriptionService.getUserSubscription(id);
            if (sub && sub.is_active && !sub.is_expired) {
                isVip = true;
                vipTier = sub.plan_name;
                vipBadge = 'Tích Xanh Verified Pro Dev';
                vipDays = sub.days_remaining || 0;
                vipExpires = sub.expires_at;
            }
        } catch(subErr) {}

        res.status(200).json({
            success: true,
            freelancer: {
                ...user,
                location: location,
                skills: rawSkills,
                portfolios: portfolios,
                completed_count: completedJobs.length,
                in_progress_count: inProgressJobs.length,
                rating_score: ratingScore,
                rating_display: avgRating,
                bio: bio,
                is_vip: isVip,
                vip_tier: vipTier,
                vip_badge: vipBadge,
                vip_days_remaining: vipDays,
                vip_expires_at: vipExpires
            },
            completed_jobs: completedJobs,
            in_progress_jobs: inProgressJobs,
            reviews: reviews
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 16. API: Khách hàng Giao Việc Trực Tiếp Cho Mối Ruột (Direct Hire - 1-on-1 Job Offer)
router.post('/api/jobs/direct-hire', async (req, res) => {
    const { client_id, freelancer_id, title, description, budget, category_name, tags } = req.body;
    console.log(`\n🤝 [API POST /api/jobs/direct-hire] Client ${client_id} giao việc trực tiếp cho Freelancer ${freelancer_id}: "${title}"`);
    try {
        if (!client_id || !freelancer_id || !title || !budget) {
            throw new Error('Vui lòng điền đầy đủ tiêu đề, ngân sách và chọn freelancer mối ruột');
        }

        // 1. Kiểm tra quan hệ bạn bè / mối ruột & kiểm tra chặn
        const { isFriend, getBlockStatus } = require('../services/connectionStore');
        const blockStatus = getBlockStatus(client_id, freelancer_id);
        if (blockStatus.is_blocked) {
            return res.status(400).json({
                error: 'Không thể giao việc trực tiếp do một trong hai bên đã chặn liên lạc.'
            });
        }
        const areFriends = isFriend(client_id, freelancer_id);
        if (!areFriends) {
            return res.status(400).json({ 
                error: 'Bạn chỉ có thể giao việc trực tiếp khi hai bên đã kết bạn / là mối ruột của nhau. Vui lòng gửi lời mời kết bạn trước!' 
            });
        }

        // 2. Đóng gói mô tả chuyên nghiệp & hình thức làm việc
        let fullDescription = description ? description.trim() : '';
        if (category_name) {
            fullDescription = `[Danh mục: ${category_name.trim()}]\n` + fullDescription;
        }
        if (tags && ((Array.isArray(tags) && tags.length > 0) || (typeof tags === 'string' && tags.trim()))) {
            const tagList = Array.isArray(tags) ? tags.join(', ') : tags.trim();
            fullDescription += `\n\n🏷️ [Kỹ năng yêu cầu: ${tagList}]`;
        }
        fullDescription += `\n\n⭐ [Hợp đồng chỉ định trực tiếp cho Mối Ruột - Thỏa thuận 1-1]`;

        const numBudget = parseFloat(budget);

        // 3. Tạo Job mới ở trạng thái 'negotiating' (Thỏa thuận giá trước, CHƯA khóa tiền ví)
        const { data: jobData, error: jobErr } = await supabase
            .from('jobs')
            .insert([{
                client_id,
                title,
                description: fullDescription,
                budget: numBudget,
                status: 'negotiating'
            }])
            .select()
            .single();

        if (jobErr) throw jobErr;

        // 4. Gán Application với status 'negotiating'
        const { error: appErr } = await supabase.from('job_applications').insert([{
            job_id: jobData.id,
            freelancer_id: freelancer_id,
            bid_amount: numBudget,
            cover_letter: 'Đề xuất giao việc chỉ định trực tiếp từ Khách Hàng (Đang thỏa thuận giá).',
            status: 'negotiating'
        }]);
        if (appErr) console.error('Lỗi tạo application direct hire:', appErr.message);

        // 5. Thông báo cho Freelancer & Client
        const { data: clientUser } = await supabase.from('users').select('full_name').eq('id', client_id).single();
        const clientName = clientUser ? clientUser.full_name : 'Khách Hàng';

        await supabase.from('notifications').insert([
            {
                user_id: freelancer_id,
                title: '💼 Đề Xuất Giao Việc Mới!',
                content: `${clientName} đã gửi cho bạn đề xuất dự án: "${title}" (Ngân sách dự kiến: ${numBudget.toLocaleString()} Token). Hãy vào khung chat để trao đổi và thống nhất giá nhé!`
            },
            {
                user_id: client_id,
                title: '📋 Đã gửi đề xuất giao việc',
                content: `Bạn đã gửi đề xuất dự án "${title}" cho Freelancer mối ruột. Hãy cùng trao đổi và chốt giá trong khung chat.`
            }
        ]);

        // 6. Ghi log kiểm toán
        logEvent({
            module: 'JOB',
            action: 'DIRECT_HIRE_OFFER_SENT',
            actor_id: client_id,
            target_id: freelancer_id,
            level: 'INFO',
            details: `Khách hàng gửi đề xuất giao việc "${title}" cho Freelancer mối ruột (${numBudget.toLocaleString()} Token - Đang thỏa thuận)`,
            metadata: { job_id: jobData.id, title, budget: numBudget, client_id, freelancer_id }
        });

        console.log(`✅ [API POST /api/jobs/direct-hire] Thành công tạo đề xuất hợp đồng ID: ${jobData.id}`);
        res.status(201).json({ success: true, message: 'Đã gửi đề xuất giao việc thành công!', job: jobData });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/direct-hire] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 17. API: Cập nhật mức giá thương lượng (Update Offer Price in Chat)
router.post('/api/jobs/update-offer-price', async (req, res) => {
    const { job_id, user_id, new_budget, note } = req.body;
    console.log(`\n💬 [API POST /api/jobs/update-offer-price] User ${user_id} cập nhật giá Job ${job_id} thành: ${new_budget} Token`);
    try {
        if (!job_id || !new_budget || parseFloat(new_budget) <= 0) {
            throw new Error('Vui lòng nhập mức giá đề xuất hợp lệ!');
        }

        const numBudget = parseFloat(new_budget);

        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án!');

        if (job.status !== 'negotiating') {
            throw new Error('Chỉ có thể thay đổi giá khi dự án đang ở giai đoạn Thỏa Thuận (negotiating)');
        }

        // Cập nhật ngân sách mới
        await supabase.from('jobs').update({ budget: numBudget }).eq('id', job_id);

        logEvent({
            module: 'JOB',
            action: 'UPDATE_OFFER_PRICE',
            actor_id: user_id,
            target_id: job_id,
            level: 'INFO',
            details: `Cập nhật giá đề xuất cho Job "${job.title}" thành ${numBudget.toLocaleString()} Token`,
            metadata: { job_id, old_budget: job.budget, new_budget: numBudget, note }
        });

        res.status(200).json({ 
            success: true, 
            message: `Đã cập nhật mức giá thỏa thuận thành ${numBudget.toLocaleString()} Token!`, 
            job_id, 
            new_budget: numBudget 
        });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/update-offer-price] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 18. API: Khách hàng Chốt Giá & Khóa Escrow (Confirm Direct Hire & Lock Escrow)
router.post('/api/jobs/confirm-direct-hire', async (req, res) => {
    const { client_id, job_id, final_budget } = req.body;
    console.log(`\n🔒 [API POST /api/jobs/confirm-direct-hire] Client ${client_id} chốt giá Job ${job_id} (${final_budget} Token) & Khóa Escrow`);
    try {
        if (!client_id || !job_id) {
            throw new Error('Thiếu thông tin client_id hoặc job_id');
        }

        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy hợp đồng');

        if (job.client_id !== client_id) {
            throw new Error('Bạn không có quyền chốt hợp đồng này!');
        }

        if (job.status !== 'negotiating') {
            throw new Error('Hợp đồng này không ở trạng thái thỏa thuận giá!');
        }

        const budget = final_budget ? parseFloat(final_budget) : parseFloat(job.budget || 0);
        if (budget <= 0) throw new Error('Ngân sách không hợp lệ!');

        // 1. Kiểm tra số dư ví Client
        const { data: wallet, error: walletErr } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        if (walletErr || !wallet) throw new Error('Không tìm thấy ví của bạn');

        if (wallet.balance < budget) {
            throw new Error(`Số dư ví không đủ! Dự án yêu cầu ${budget.toLocaleString()} Token, ví hiện có: ${wallet.balance.toLocaleString()} Token. Vui lòng nạp thêm token vào ví.`);
        }

        // 2. Khóa Escrow từ ví Khách Hàng
        const newBalance = wallet.balance - budget;
        const newLocked = (wallet.locked_balance || 0) + budget;
        await supabase.from('wallets').update({ balance: newBalance, locked_balance: newLocked }).eq('user_id', client_id);

        // 3. Ghi log giao dịch Khóa Escrow
        await supabase.from('transactions').insert([{
            user_id: client_id,
            target_id: job.id,
            amount: budget,
            type: 'escrow_lock',
            status: 'success'
        }]);

        // 4. Chuyển Job sang trạng thái 'planning'
        const { data: updatedJob, error: updateErr } = await supabase
            .from('jobs')
            .update({ status: 'planning', budget: budget })
            .eq('id', job_id)
            .select()
            .single();

        if (updateErr) throw updateErr;

        // 5. Cập nhật Application sang 'accepted'
        await supabase.from('job_applications').update({ status: 'accepted', bid_amount: budget }).eq('job_id', job_id);

        // 6. Lấy thông tin Freelancer để thông báo
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).limit(1);
        const freelancerId = appData && appData.length > 0 ? appData[0].freelancer_id : null;

        if (freelancerId) {
            const { data: clientUser } = await supabase.from('users').select('full_name').eq('id', client_id).single();
            const clientName = clientUser ? clientUser.full_name : 'Khách Hàng';

            await supabase.from('notifications').insert([
                {
                    user_id: freelancerId,
                    title: '🟢 Hợp đồng đã chốt & Escrow đã khóa!',
                    content: `${clientName} đã chốt mức giá ${budget.toLocaleString()} Token cho dự án "${job.title}" và khóa quỹ Escrow an toàn. Hãy vào tạo Kế hoạch Milestones ngay!`
                },
                {
                    user_id: client_id,
                    title: '🎉 Khóa Escrow thành công',
                    content: `Bạn đã chốt giá và khóa ${budget.toLocaleString()} Token cho dự án "${job.title}". Hãy chờ Freelancer lập kế hoạch mốc nhé.`
                }
            ]);

            // Gửi tin nhắn tự động vào khung chat 1-1
            try {
                const directMessageStore = require('../services/directMessageStore');
                await directMessageStore.sendDirectMessage({
                    sender_id: client_id,
                    receiver_id: freelancerId,
                    content: `🟢 [CHỐT GIÁ & KHÓA ESCROW] (Mã dự án: #${job.id})\nKhách hàng đã chốt mức giá ${budget.toLocaleString()} Token và khóa quỹ Escrow an toàn!\n👉 Freelancer hãy nhấp vào nút bên dưới để lập Kế hoạch Milestones bàn giao nhé.`
                });
            } catch (e) {
                console.error('Lỗi gửi message chốt escrow:', e);
            }
        }

        // 7. Ghi log kiểm toán
        logEvent({
            module: 'JOB',
            action: 'CONFIRM_DIRECT_HIRE_ESCROW_LOCKED',
            actor_id: client_id,
            target_id: freelancerId,
            level: 'INFO',
            details: `Khách hàng chốt giá và khóa Escrow ${budget.toLocaleString()} Token cho dự án "${job.title}"`,
            metadata: { job_id, budget, client_id, freelancer_id: freelancerId }
        });

        console.log(`✅ [API POST /api/jobs/confirm-direct-hire] Thành công chốt giá & khóa Escrow Job ID: ${job.id}`);
        res.status(200).json({ 
            success: true, 
            message: `Đã chốt giá ${budget.toLocaleString()} Token và khóa quỹ Escrow thành công!`, 
            job: updatedJob 
        });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/confirm-direct-hire] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;



