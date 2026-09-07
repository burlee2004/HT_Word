const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const { logEvent } = require('../services/auditLogger');

// 1. API: Khách hàng đăng Job mới
router.post('/api/jobs', async (req, res) => {
    const { client_id, title, description, budget, category_id, category_name, tags } = req.body;
    console.log(`\n📢 [API POST /api/jobs] Nhận yêu cầu tạo dự án: "${title}" | Danh mục: "${category_name || 'Mặc định'}" | Ngân sách: ${budget} Token | Client: ${client_id}`);
    try {
        // KIỂM TRA SỐ DƯ VÍ TRƯỚC KHI CHO ĐĂNG DỰ ÁN
        const { data: wallet, error: walletErr } = await supabase.from('wallets').select('balance').eq('user_id', client_id).single();
        if (walletErr || !wallet) throw new Error('Không tìm thấy ví của bạn.');
        if (wallet.balance < budget) throw new Error(`Số dư ví không đủ! Dự án yêu cầu ${budget} Token, nhưng ví bạn chỉ có ${wallet.balance} Token. Vui lòng nạp thêm.`);

        // Đóng gói Danh mục & Tags vào nội dung mô tả một cách chuyên nghiệp
        let fullDescription = description ? description.trim() : '';
        if (category_name) {
            fullDescription = `[Danh mục: ${category_name.trim()}]\n` + fullDescription;
        }
        if (tags && ((Array.isArray(tags) && tags.length > 0) || (typeof tags === 'string' && tags.trim()))) {
            const tagList = Array.isArray(tags) ? tags.join(', ') : tags.trim();
            fullDescription += `\n\n🏷️ [Kỹ năng yêu cầu: ${tagList}]`;
        }

        const { data, error } = await supabase
            .from('jobs')
            .insert([{ client_id, title, description: fullDescription, budget, status: 'open' }])
            .select();

        if (error) throw error;

        // Gửi thông báo cho Client
        await supabase.from('notifications').insert([{
            user_id: client_id,
            title: 'Tạo Yêu cầu thành công',
            content: `Bạn đã đăng thành công yêu cầu: "${title}" [${category_name || 'Dự án mới'}]. Hãy chờ Freelancer ứng tuyển nhé.`
        }]);

        // Ghi log kiểm toán
        await logEvent({
            module: 'JOB',
            action: 'CREATE_JOB',
            level: 'INFO',
            details: `Khách hàng đăng dự án mới: "${title}" | Ngân sách: ${parseFloat(budget).toLocaleString()} Token | Danh mục: ${category_name || 'Mặc định'}`,
            user_id: client_id,
            metadata: { job_id: data[0].id, title, budget, category_name }
        });

        console.log(`✅ [API POST /api/jobs] Tạo dự án thành công! ID: ${data[0].id}`);
        res.status(201).json({ message: 'Đăng dự án thành công!', job: data[0] });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs] Thất bại: ${error.message}`);
        res.status(400).json({ error: error.message });
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

        let jobsEnriched = (jobs || []).map(job => {
            const clientJobs = (allJobs || []).filter(j => j.client_id === job.client_id);
            const totalPosted = clientJobs.length;
            const completedJobs = clientJobs.filter(j => ['completed', 'in_progress', 'planning', 'pending_plan_approval'].includes(j.status));
            const totalSpent = clientJobs
                .filter(j => j.status === 'completed' || j.status === 'in_progress')
                .reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);

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
            
            const completionRate = totalPosted > 0 ? Math.round((completedJobs.length / totalPosted) * 100) : 100;
            
            let creditTier = 'Hạng A (Uy tín cao)';
            let tierBadge = 'bg-emerald-100 text-emerald-800 border-emerald-300';
            if (totalSpent >= 10000 && completionRate >= 80) {
                creditTier = 'Kim Cương (VIP)';
                tierBadge = 'bg-purple-100 text-purple-800 border-purple-300';
            } else if (totalSpent === 0 && totalPosted <= 1) {
                creditTier = 'Khách mới (Đã nạp Escrow)';
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
                    rating_score: 5.0,
                    credit_tier: creditTier,
                    tier_badge: tierBadge
                }
            };
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

// 3. API: Freelancer ứng tuyển (Báo giá)
router.post('/api/jobs/apply', async (req, res) => {
    const { job_id, freelancer_id, cover_letter, bid_amount } = req.body;
    try {
        const { data, error } = await supabase
            .from('job_applications')
            .insert([{ job_id, freelancer_id, cover_letter, bid_amount, status: 'pending' }])
            .select();
        
        if (error) throw error;
        res.status(201).json({ message: 'Ứng tuyển thành công!', application: data[0] });
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

        // Thông báo cho Freelancer
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'revoked').limit(1);
        if (appData && appData.length > 0) {
            await supabase.from('notifications').insert([{
                user_id: appData[0].freelancer_id,
                title: 'Khách hàng thu hồi thỏa thuận',
                content: `Khách hàng đã thu hồi dự án "${job.title}" do phản hồi chậm trễ và hệ thống đã hoàn trả Token Escrow.`
            }]);
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
                jobs (id, title, description, budget, client_id, status)
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
            }
            return j; 
        }).filter(Boolean);
        
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
    const { client_id, title, description, budget, status } = req.body;
    try {
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án');
        if (job.client_id !== client_id) throw new Error('Bạn không có quyền chỉnh sửa dự án này');
        if (job.status !== 'open' && status === 'cancelled') {
            throw new Error('Chỉ có thể hủy dự án khi đang ở trạng thái Mở (Open)');
        }

        const updatePayload = {};
        if (title) updatePayload.title = title.trim();
        if (description) updatePayload.description = description.trim();
        
        if (budget !== undefined) {
            const newBudget = parseFloat(budget);
            if (isNaN(newBudget) || newBudget <= 0) throw new Error('Ngân sách không hợp lệ');
            
            // Nếu tăng ngân sách, kiểm tra số dư ví
            if (newBudget > (job.budget || 0)) {
                const diff = newBudget - (job.budget || 0);
                const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', client_id).single();
                if (!wallet || wallet.balance < newBudget) {
                    throw new Error(`Số dư ví không đủ để tăng ngân sách lên ${newBudget} Token (Ví hiện có: ${wallet ? wallet.balance : 0} Token)`);
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
        res.status(200).json({ success: true, message: 'Cập nhật dự án thành công!', job: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
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

        // Lấy danh sách đánh giá từ khách hàng
        let reviews = [];
        try {
            const { data: revData } = await supabase
                .from('reviews')
                .select('*')
                .eq('freelancer_id', id);
            reviews = revData || [];
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
                rating: review ? review.rating : 5.0,
                review_comment: review ? review.comment : 'Hoàn thành công việc xuất sắc, giao đúng hạn!'
            };

            if (j.status === 'completed') {
                completedJobs.push(jobItem);
            } else if (['in_progress', 'planning', 'pending_plan_approval'].includes(j.status)) {
                inProgressJobs.push(jobItem);
            }
        });

        // Tính điểm đánh giá trung bình
        let totalRating = completedJobs.reduce((sum, j) => sum + j.rating, 0);
        let avgRating = completedJobs.length > 0 ? (totalRating / completedJobs.length).toFixed(1) : 5.0;

        res.status(200).json({
            success: true,
            freelancer: {
                ...user,
                completed_count: completedJobs.length,
                in_progress_count: inProgressJobs.length,
                rating_score: avgRating,
                bio: user.skills && Array.isArray(user.skills) 
                    ? `Chuyên gia ${user.skills.slice(0, 3).join(', ')} với ${completedJobs.length} dự án đã hoàn thành trên sàn HT Work.` 
                    : 'Chuyên gia uy tín trên sàn HT Work.'
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

        // 1. Kiểm tra quan hệ bạn bè / mối ruột
        const { isFriend } = require('../services/connectionStore');
        const areFriends = isFriend(client_id, freelancer_id);
        if (!areFriends) {
            return res.status(400).json({ 
                error: 'Bạn chỉ có thể giao việc trực tiếp khi hai bên đã kết bạn / là mối ruột của nhau. Vui lòng gửi lời mời kết bạn trước!' 
            });
        }

        // 2. Kiểm tra số dư ví Client
        const { data: wallet, error: walletErr } = await supabase.from('wallets').select('balance').eq('user_id', client_id).single();
        if (walletErr || !wallet) throw new Error('Không tìm thấy ví của bạn.');
        if (wallet.balance < budget) {
            throw new Error(`Số dư ví không đủ! Dự án yêu cầu ${budget} Token, ví hiện có: ${wallet.balance} Token.`);
        }

        // 3. Đóng gói mô tả chuyên nghiệp
        let fullDescription = description ? description.trim() : '';
        if (category_name) {
            fullDescription = `[Danh mục: ${category_name.trim()}]\n` + fullDescription;
        }
        if (tags && ((Array.isArray(tags) && tags.length > 0) || (typeof tags === 'string' && tags.trim()))) {
            const tagList = Array.isArray(tags) ? tags.join(', ') : tags.trim();
            fullDescription += `\n\n🏷️ [Kỹ năng yêu cầu: ${tagList}]`;
        }
        fullDescription += `\n\n⭐ [Hợp đồng chỉ định trực tiếp cho Mối Ruột]`;

        // 4. Khóa Tiền Ký Quỹ Escrow: Trừ balance khả dụng, cộng vào locked_balance
        const numBudget = parseFloat(budget);
        const newBalance = wallet.balance - numBudget;
        const newLocked = (wallet.locked_balance || 0) + numBudget;
        await supabase.from('wallets').update({ balance: newBalance, locked_balance: newLocked }).eq('user_id', client_id);

        // 5. Tạo Job mới ở trạng thái 'planning'
        const { data: jobData, error: jobErr } = await supabase
            .from('jobs')
            .insert([{
                client_id,
                title,
                description: fullDescription,
                budget: numBudget,
                status: 'planning'
            }])
            .select()
            .single();

        if (jobErr) throw jobErr;

        // Ghi log giao dịch Khóa Escrow
        await supabase.from('transactions').insert([{
            user_id: client_id,
            target_id: jobData.id,
            amount: numBudget,
            type: 'escrow_lock',
            status: 'success'
        }]);

        // 6. Tự động gán Application với status 'accepted'
        await supabase.from('job_applications').insert([{
            job_id: jobData.id,
            freelancer_id: freelancer_id,
            cover_letter: 'Hợp đồng giao việc chỉ định trực tiếp từ Khách Hàng mối ruột.',
            status: 'accepted'
        }]);

        // 6. Thông báo cho Freelancer & Client
        const { data: clientUser } = await supabase.from('users').select('full_name').eq('id', client_id).single();
        const clientName = clientUser ? clientUser.full_name : 'Khách Hàng quen';

        await supabase.from('notifications').insert([
            {
                user_id: freelancer_id,
                title: '💼 Lời Mời Giao Việc Trực Tiếp!',
                content: `${clientName} đã giao trực tiếp cho bạn dự án: "${title}" (Ngân sách: ${parseFloat(budget).toLocaleString()} Token). Hãy vào tạo Kế hoạch Milestones ngay!`
            },
            {
                user_id: client_id,
                title: '🎉 Giao việc trực tiếp thành công',
                content: `Bạn đã chỉ định dự án "${title}" cho Freelancer mối ruột. Hãy chờ Freelancer lập kế hoạch mốc nhé.`
            }
        ]);

        // 7. Ghi log kiểm toán
        logEvent({
            module: 'JOB',
            action: 'DIRECT_HIRE_JOB',
            actor_id: client_id,
            target_id: freelancer_id,
            level: 'INFO',
            details: `Khách hàng giao việc trực tiếp "${title}" cho Freelancer mối ruột (${parseFloat(budget).toLocaleString()} Token)`,
            metadata: { job_id: jobData.id, title, budget, client_id, freelancer_id }
        });

        console.log(`✅ [API POST /api/jobs/direct-hire] Thành công tạo hợp đồng chỉ định ID: ${jobData.id}`);
        res.status(201).json({ success: true, message: 'Đã giao việc trực tiếp cho Freelancer mối ruột thành công!', job: jobData });
    } catch (error) {
        console.error(`❌ [API POST /api/jobs/direct-hire] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;



