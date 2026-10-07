const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');
const { getDisputes, saveDisputes } = require('../services/disputeStore');
const { logEvent } = require('../services/auditLogger');

// 1. Tạo Khiếu nại (Dispute)
router.post('/api/jobs/dispute', async (req, res) => {
    const { job_id, user_id, reason, evidence_url } = req.body;
    try {
        const { data, error } = await supabase.from('jobs').update({ status: 'disputed' }).eq('id', job_id);
        if (error) throw error;
        
        let disputes = getDisputes();
        disputes[job_id] = { user_id, reason, evidence_url, created_at: new Date().toISOString() };
        saveDisputes(disputes);

        logEvent({
            module: 'DISPUTE',
            action: 'CREATE_DISPUTE',
            actor_id: user_id,
            level: 'CRITICAL',
            details: `Người dùng đã mở đơn khiếu nại dự án #${job_id}. Lý do: ${reason}`,
            metadata: { job_id, user_id, reason, evidence_url }
        });

        res.status(200).json({ message: 'Đã gửi khiếu nại thành công. Hệ thống đã đóng băng dự án.' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 2. Lấy danh sách dự án cho Admin Giám sát & Xử lý Tranh chấp
router.get('/api/admin/projects', async (req, res) => {
    try {
        const { data: jobs, error } = await supabase.from('jobs').select('*, clients:client_id(full_name, email), milestones(*)');
        if (error) throw error;

        // Fetch applications to get freelancers for these jobs
        const { data: apps } = await supabase.from('job_applications').select('job_id, freelancer_id, freelancers:freelancer_id(full_name, email)').eq('status', 'accepted');
        
        const disputes = getDisputes();

        const fullJobs = jobs.map(j => {
            const app = (apps || []).find(a => a.job_id === j.id);
            return {
                ...j,
                freelancer: app ? app.freelancers : null,
                freelancer_id: app ? app.freelancer_id : null,
                dispute: disputes[j.id] || null
            };
        });

        res.status(200).json({ projects: fullJobs });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 3. Admin Phán Quyết Tranh Chấp (Resolve Dispute)
router.post('/api/admin/projects/resolve-dispute', async (req, res) => {
    const { job_id, winner } = req.body; // winner: 'client' | 'freelancer'
    try {
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr) throw jobErr;

        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        if (!appData) throw new Error('Không tìm thấy Freelancer');

        const client_id = job.client_id;
        const freelancer_id = appData.freelancer_id;

        // TÍNH TOÁN SỐ TIỀN THỰC TẾ CÒN BỊ KHÓA CỦA DỰ ÁN NÀY (Tổng các Milestone chưa PAID)
        const { data: pendingMilestones } = await supabase.from('milestones').select('amount').eq('job_id', job_id).neq('status', 'PAID');
        const amount = (pendingMilestones || []).reduce((sum, m) => sum + parseFloat(m.amount || 0), 0);

        const { data: clientWallet } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        const { data: freeWallet } = await supabase.from('wallets').select('*').eq('user_id', freelancer_id).single();

        if (clientWallet.locked_balance < amount) throw new Error(`Số dư đóng băng không khớp! Chỉ còn ${clientWallet.locked_balance} Token trong ví nhưng dự án yêu cầu xử lý ${amount} Token.`);

        if (winner === 'client') {
            // Hoàn tiền Khách Hàng (trả lại những gì chưa giải ngân)
            if (amount > 0) {
                await supabase.from('wallets').update({ 
                    locked_balance: clientWallet.locked_balance - amount,
                    balance: clientWallet.balance + amount 
                }).eq('user_id', client_id);
            }
            await supabase.from('jobs').update({ status: 'cancelled' }).eq('id', job_id);
            
        } else if (winner === 'freelancer') {
            // Ép Giải Ngân Freelancer (trả nốt những gì chưa giải ngân)
            if (amount > 0) {
                await supabase.from('wallets').update({ locked_balance: clientWallet.locked_balance - amount }).eq('user_id', client_id);
                
                // Cập nhật ví Freelancer nếu chưa có
                const currentFreeBalance = freeWallet ? freeWallet.balance : 0;
                if (!freeWallet) {
                    await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: amount, locked_balance: 0 }]);
                } else {
                    await supabase.from('wallets').update({ balance: currentFreeBalance + amount }).eq('user_id', freelancer_id);
                }
                
                // ĐỒNG BỘ BLOCKCHAIN ÉP BUỘC
                if (blockchain.isConfigured()) {
                    await blockchain.transferBalance(client_id, freelancer_id, amount);
                }
                
                // Đánh dấu tất cả milestone còn lại thành PAID
                await supabase.from('milestones').update({ status: 'PAID' }).eq('job_id', job_id).neq('status', 'PAID');
            }
            await supabase.from('jobs').update({ status: 'completed' }).eq('id', job_id);
        }

        // Cleanup dispute record
        let disputes = getDisputes();
        if(disputes[job_id]) {
            delete disputes[job_id];
            saveDisputes(disputes);
        }

        logEvent({
            module: 'DISPUTE',
            action: 'RESOLVE_DISPUTE',
            actor_id: 'ADMIN',
            actor_email: 'admin@htwork.vn',
            target_id: winner === 'client' ? client_id : freelancer_id,
            level: 'CRITICAL',
            details: `Admin đã đưa ra phán quyết Tối Cao: [${winner === 'client' ? 'KHÁCH HÀNG THẮNG (Hoàn Escrow)' : 'FREELANCER THẮNG (Ép giải ngân)'}] cho dự án #${job_id} (Số tiền: ${amount.toLocaleString()} Token)`,
            metadata: { job_id, winner, amount, client_id, freelancer_id }
        });

        res.status(200).json({ message: `Đã phán quyết thành công cho ${winner === 'client' ? 'Khách Hàng' : 'Freelancer'}!` });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;
