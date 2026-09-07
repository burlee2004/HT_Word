const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');

// 4.1. API: Freelancer tạo Kế hoạch (Tạo nhiều Milestones)
router.post('/api/milestones/create-plan', async (req, res) => {
    const { job_id, milestones } = req.body; 
    // milestones là mảng: [{ title, description, expected_deliverables, amount, payment_mode }]
    try {
        // Gắn job_id và status mặc định vào từng milestone
        const inserts = milestones.map(m => ({
            ...m,
            job_id: job_id,
            status: 'PENDING'
        }));

        const { error } = await supabase.from('milestones').insert(inserts);
        if (error) throw error;

        // Đổi trạng thái job để báo hiệu Khách hàng cần duyệt Plan
        await supabase.from('jobs').update({ status: 'pending_plan_approval' }).eq('id', job_id);

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Bản kế hoạch dự án đã hoàn tất',
                content: 'Freelancer đã lên xong kế hoạch (Milestones). Vui lòng vào kiểm tra, chốt kế hoạch và Khóa Escrow để bắt đầu.'
            }]);
        }

        res.status(200).json({ message: 'Tạo kế hoạch thành công, chờ Khách duyệt.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.1.1 API: Freelancer hủy/thu hồi Kế hoạch (khi đang ở pending_plan_approval)
router.post('/api/milestones/revoke-plan', async (req, res) => {
    const { job_id } = req.body;
    try {
        // Kiểm tra xem job có đang ở trạng thái pending_plan_approval không
        const { data: job, error: jobErr } = await supabase.from('jobs').select('status').eq('id', job_id).single();
        if (jobErr) throw jobErr;
        
        if (job.status !== 'pending_plan_approval') {
            return res.status(400).json({ error: 'Chỉ có thể thu hồi khi kế hoạch đang chờ duyệt.' });
        }

        // Xóa tất cả milestones PENDING của job này
        const { error: delErr } = await supabase.from('milestones').delete().match({ job_id: job_id, status: 'PENDING' });
        if (delErr) throw delErr;

        // Trả trạng thái job về lại planning
        const { error: updateErr } = await supabase.from('jobs').update({ status: 'planning' }).eq('id', job_id);
        if (updateErr) throw updateErr;

        res.status(200).json({ message: 'Đã thu hồi kế hoạch thành công. Bạn có thể làm lại.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 8. API: Freelancer nộp minh chứng (Submit Milestone)
router.post('/api/milestones/submit', async (req, res) => {
    const { milestone_id, evidence_url } = req.body;
    try {
        const { data, error } = await supabase
            .from('milestones')
            .update({ evidence_url, status: 'pending_review' })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', data[0].job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Có báo cáo công việc mới',
                content: 'Freelancer vừa nộp báo cáo (minh chứng) cho dự án. Hãy vào kiểm tra và nghiệm thu.'
            }]);
        }

        res.status(200).json({ message: 'Nộp bằng chứng thành công!', milestone: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 9. API: Khách hàng xem danh sách Job cần quản lý (Duyệt kế hoạch HOẶC duyệt bài)
router.get('/api/client/:client_id/pending-actions', async (req, res) => {
    const { client_id } = req.params;
    console.log(`\n📋 [API GET /api/client/pending-actions] Lấy danh sách tiến độ cho Client ID: ${client_id}`);
    try {
        const { data: jobs, error: jobsError } = await supabase
            .from('jobs')
            .select('id, title, status, budget, deadline, created_at')
            .eq('client_id', client_id)
            .in('status', ['planning', 'pending_plan_approval', 'in_progress', 'completed'])
            .order('created_at', { ascending: false });
            
        if (jobsError) throw jobsError;
        if (!jobs || jobs.length === 0) return res.status(200).json({ jobs: [] });

        for (let job of jobs) {
            const { data: milestones } = await supabase
                .from('milestones')
                .select('*')
                .eq('job_id', job.id)
                .order('created_at', { ascending: true });
            job.milestones = milestones || [];

            // Lấy thông tin freelancer đã trúng thầu
            const { data: appData } = await supabase
                .from('job_applications')
                .select('freelancer_id, users:freelancer_id(id, full_name, email, avatar_url, phone)')
                .eq('job_id', job.id)
                .eq('status', 'accepted')
                .maybeSingle();
            job.freelancer = appData?.users || null;
            job.freelancer_id = appData?.freelancer_id || null;
        }
            
        console.log(`✅ [API GET /api/client/pending-actions] Trả về ${jobs ? jobs.length : 0} dự án đang xử lý/tiến độ/hoàn thành`);
        res.status(200).json({ jobs });
    } catch (error) {
        console.error(`❌ [API GET /api/client/pending-actions] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 10. API: Nghiệm thu và Giải ngân (Release Escrow)
router.post('/api/escrow/release', async (req, res) => {
    const { client_id, milestone_id, amount } = req.body;
    try {
        // Lấy job_id từ milestone
        const { data: mData, error: mErr } = await supabase.from('milestones').select('job_id').eq('id', milestone_id).single();
        if (mErr) throw new Error('Không tìm thấy milestone');

        // Lấy freelancer_id từ job_applications (chỉ lấy người đã được accepted)
        const { data: appData, error: appErr } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', mData.job_id).eq('status', 'accepted').single();
        if (appErr) throw new Error('Không tìm thấy Freelancer của dự án này');

        const freelancer_id = appData.freelancer_id;

        // Lấy ví
        const { data: clientWallet, error: cwError } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        const { data: freeWallet, error: fwError } = await supabase.from('wallets').select('*').eq('user_id', freelancer_id).single();
        
        if (cwError || fwError || !clientWallet || !freeWallet) throw new Error('Lỗi truy xuất ví');
        if (clientWallet.locked_balance < amount) throw new Error('Không đủ số dư bị khóa để giải ngân');

        // Trừ locked client, cộng balance freelancer
        await supabase.from('wallets').update({ locked_balance: clientWallet.locked_balance - amount }).eq('user_id', client_id);
        await supabase.from('wallets').update({ balance: freeWallet.balance + amount }).eq('user_id', freelancer_id);

        // Đồng bộ lên Blockchain (Chuyển tiền thực tế trên Sổ cái)
        if (blockchain.isConfigured()) {
            try {
                await blockchain.transferBalance(client_id, freelancer_id, amount);
            } catch (err) {
                console.error('Lỗi khi gọi smart contract transfer:', err);
            }
        }

        // Cập nhật milestone thành approved
        await supabase.from('milestones').update({ status: 'approved' }).eq('id', milestone_id);

        // Ghi transaction
        await supabase.from('transactions').insert([{
            user_id: freelancer_id,
            amount: amount,
            type: 'escrow_release',
            status: 'success'
        }]);

        // Gửi thông báo cho Freelancer
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: 'Đã nhận thanh toán!',
            content: `Khách hàng đã nghiệm thu công việc và giải ngân ${amount} Token vào ví của bạn.`
        }]);

        res.status(200).json({ message: 'Giải ngân thành công! Tiền đã được chuyển cho Freelancer.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 11. API: Submit Milestone (Freelancer nộp bài với mảng proof_urls)
router.post('/api/milestones/advanced/submit', async (req, res) => {
    const { milestone_id, proof_urls, report_text } = req.body;
    try {
        const { data, error } = await supabase
            .from('milestones')
            .update({ 
                proof_urls: proof_urls, 
                status: 'PENDING_REVIEW' 
            })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', data[0].job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Có báo cáo công việc mới',
                content: 'Freelancer vừa nộp báo cáo (minh chứng) cho dự án. Hãy vào kiểm tra và nghiệm thu.'
            }]);
        }
        res.status(200).json({ message: 'Nộp bằng chứng thành công!', milestone: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 12. API: Request Revision (Khách hàng yêu cầu sửa lại)
router.post('/api/milestones/advanced/revision', async (req, res) => {
    const { milestone_id, feedback_text, screenshot_urls } = req.body;
    try {
        // Lưu lịch sử yêu cầu sửa
        await supabase.from('milestone_revisions').insert([{
            milestone_id, feedback_text, screenshot_urls
        }]);

        // Cập nhật trạng thái milestone về REVISION
        const { data, error } = await supabase
            .from('milestones')
            .update({ status: 'REVISION' })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Tìm Freelancer để báo tin
        const { data: mData } = await supabase.from('milestones').select('job_id').eq('id', milestone_id).single();
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', mData.job_id).eq('status', 'accepted').single();
        
        await supabase.from('notifications').insert([{
            user_id: appData.freelancer_id,
            title: 'Yêu cầu chỉnh sửa',
            content: 'Khách hàng đã yêu cầu chỉnh sửa báo cáo của bạn. Vui lòng kiểm tra chi tiết.'
        }]);

        res.status(200).json({ message: 'Đã gửi yêu cầu chỉnh sửa cho Freelancer!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 13. API: Approve Milestone - CHUẨN CORE BANKING (ACID + Row-Level Locking)
router.post('/api/milestones/advanced/approve', async (req, res) => {
    const { client_id, milestone_id } = req.body;
    if (!client_id || !milestone_id) {
        return res.status(400).json({ error: 'Thiếu client_id hoặc milestone_id' });
    }

    try {
        // Lấy job_id để tìm freelancer
        const { data: mData, error: mErr } = await supabase
            .from('milestones')
            .select('job_id, status, amount')
            .eq('id', milestone_id)
            .single();
        if (mErr) throw new Error('Không tìm thấy milestone. Hãy kiểm tra milestone_id có đúng không.');

        // Chặn approve trùng ngay ở Node.js trước khi vào DB (tầng bảo vệ thứ nhất)
        if (mData.status === 'PAID') {
            return res.status(409).json({ error: 'Milestone này đã được giải ngân trước đó (status: PAID). Không thể thực hiện lần 2.' });
        }

        const { data: appData, error: appErr } = await supabase
            .from('job_applications')
            .select('freelancer_id')
            .eq('job_id', mData.job_id)
            .eq('status', 'accepted')
            .single();
        if (appErr) throw new Error('Không tìm thấy Freelancer của dự án này');

        const freelancer_id = appData.freelancer_id;

        // KIỂM TRA & TẠO VÍ CHO FREELANCER NẾU CHƯA CÓ
        const { data: fWallet } = await supabase.from('wallets').select('id').eq('user_id', freelancer_id).single();
        if (!fWallet) {
            await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: 0, locked_balance: 0 }]);
        }

        // Tạo Idempotency Key duy nhất cho giao dịch này
        const idempotency_key = `RELEASE_${milestone_id}`;

        // Gọi PostgreSQL Stored Function (tầng bảo vệ thứ hai - ACID + Row-Level Lock)
        const { data: rpcResult, error: rpcError } = await supabase.rpc('fn_release_milestone', {
            p_milestone_id:     milestone_id,
            p_client_id:        client_id,
            p_freelancer_id:    freelancer_id,
            p_idempotency_key:  idempotency_key
        });

        if (rpcError) throw rpcError;

        // Hàm PostgreSQL trả về { success, message/error }
        if (!rpcResult.success) {
            return res.status(400).json({ error: rpcResult.error });
        }

        // ĐỒNG BỘ LÊN BLOCKCHAIN (WEB2.5)
        if (blockchain.isConfigured()) {
            await blockchain.transferBalance(client_id, freelancer_id, mData.amount);
        }

        // Gửi thông báo cho Freelancer sau khi giải ngân thành công
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: '💰 Đã nhận thanh toán!',
            content: `Khách hàng đã nghiệm thu. ${mData.amount} Token đã được chuyển vào ví của bạn (Blockchain Synced).`
        }]);

        // Cập nhật trạng thái job nếu tất cả milestones đã PAID
        const { data: allMilestones, error: checkErr } = await supabase
            .from('milestones')
            .select('status')
            .eq('job_id', mData.job_id);
            
        if (!checkErr && allMilestones) {
            const allPaid = allMilestones.every(m => m.status === 'PAID');
            if (allPaid) {
                await supabase.from('jobs').update({ status: 'completed' }).eq('id', mData.job_id);
            }
        }

        res.status(200).json({ 
            message: 'Nghiệm thu và giải ngân thành công!',
            detail: rpcResult.message
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
