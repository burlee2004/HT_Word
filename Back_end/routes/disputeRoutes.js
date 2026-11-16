const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');
const { getDisputes, saveDisputes } = require('../services/disputeStore');
const { logEvent } = require('../services/auditLogger');
const aiModeration = require('../services/aiModeration');

// Helper gửi Notification an toàn
async function sendNotification(userId, title, message, type = 'dispute') {
    try {
        if (supabase && userId) {
            await supabase.from('notifications').insert([{
                user_id: userId,
                title,
                message,
                type,
                is_read: false,
                created_at: new Date().toISOString()
            }]);
        }
    } catch (e) {
        console.warn('[Notification Warning]:', e.message);
    }
}

// 1. Tạo Khiếu nại (Dispute) - Hỗ trợ cả Client & Freelancer mở khiếu nại
router.post('/api/jobs/dispute', async (req, res) => {
    const { job_id, user_id, reason, evidence_url } = req.body;
    try {
        if (!job_id || !user_id || !reason) {
            return res.status(400).json({ error: 'Thiếu thông tin bắt buộc: job_id, user_id hoặc reason.' });
        }

        // Lấy thông tin dự án
        const { data: job, error: jobErr } = await supabase
            .from('jobs')
            .select('*, client:client_id(id, full_name, email)')
            .eq('id', job_id)
            .single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án tương ứng.');

        // Lấy thông tin Freelancer nhận dự án
        const { data: appData } = await supabase
            .from('job_applications')
            .select('freelancer_id, freelancer:freelancer_id(id, full_name, email)')
            .eq('job_id', job_id)
            .eq('status', 'accepted')
            .single();

        const freelancer_id = appData ? appData.freelancer_id : null;
        const freelancer_info = appData ? appData.freelancer : null;

        // Lấy thông tin người nộp đơn
        const { data: filerUser } = await supabase
            .from('users')
            .select('id, full_name, email, role')
            .eq('id', user_id)
            .single();

        const filerName = filerUser ? filerUser.full_name : (user_id === job.client_id ? 'Khách Hàng' : 'Freelancer');
        const filerRole = filerUser ? filerUser.role : (user_id === job.client_id ? 'client' : 'freelancer');
        const filerEmail = filerUser ? filerUser.email : '';

        // Cập nhật trạng thái dự án thành 'disputed'
        await supabase.from('jobs').update({ status: 'disputed' }).eq('id', job_id);

        // Đóng băng các Milestone đang chờ hoặc đang review
        await supabase.from('milestones')
            .update({ status: 'DISPUTED' })
            .eq('job_id', job_id)
            .neq('status', 'PAID');

        // Lưu bản ghi tranh chấp với đầy đủ metadata
        let disputes = getDisputes();
        disputes[job_id] = {
            job_id,
            user_id,
            user_name: filerName,
            user_email: filerEmail,
            user_role: filerRole,
            reason: reason.trim(),
            evidence_url: evidence_url || '',
            status: 'pending',
            created_at: new Date().toISOString()
        };
        saveDisputes(disputes);

        // Gửi Thông Báo Trong Hệ Thống (In-App Notifications)
        // 1. Cho người nộp đơn
        await sendNotification(
            user_id,
            '⚖️ Đã gửi đơn khiếu nại thành công',
            `Bạn đã mở khiếu nại dự án "${job.title}". Toàn bộ tiền ký quỹ Escrow đã được đóng băng an toàn để Ban Quản Trị phán quyết.`
        );

        // 2. Cho đối tác (nếu client khiếu nại -> báo cho freelancer, ngược lại)
        const counterpartId = (user_id === job.client_id) ? freelancer_id : job.client_id;
        if (counterpartId) {
            await sendNotification(
                counterpartId,
                '⚠️ Dự án phát sinh khiếu nại tranh chấp',
                `Dự án "${job.title}" vừa bị đối tác mở khiếu nại tranh chấp: "${reason}". Ban Quản Trị KGS Work đang thụ lý và yêu cầu hai bên hợp tác cung cấp thông tin.`
            );
        }

        // 3. Cho Admin
        await sendNotification(
            '11111111-1111-1111-1111-111111111111',
            '🚨 Khiếu nại tranh chấp dự án mới',
            `[${filerRole.toUpperCase()}] ${filerName} khiếu nại dự án #${job_id.slice(0, 8)}: "${reason}"`
        );

        // Ghi Nhật Ký Kiểm Toán (Audit Log)
        await logEvent({
            module: 'DISPUTE',
            action: 'CREATE_DISPUTE',
            level: 'CRITICAL',
            details: `[${filerRole.toUpperCase()}] ${filerName} (${filerEmail || user_id}) đã mở đơn khiếu nại dự án "${job.title}". Lý do: ${reason}`,
            user_id: user_id,
            user_email: filerEmail,
            user_role: filerRole,
            metadata: {
                job_id,
                job_title: job.title,
                reason,
                evidence_url,
                client_id: job.client_id,
                freelancer_id
            }
        });

        res.status(200).json({
            success: true,
            message: 'Đã gửi khiếu nại thành công. Hệ thống đã đóng băng toàn bộ số tiền Escrow để Ban Quản Trị thụ lý.'
        });
    } catch (err) {
        console.error('[Dispute Create Error]:', err);
        res.status(400).json({ error: err.message });
    }
});

// 2. Lấy danh sách dự án cho Admin Giám sát & Xử lý Tranh chấp
router.get('/api/admin/projects', async (req, res) => {
    try {
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select('*, clients:client_id(full_name, email), milestones(*)')
            .order('created_at', { ascending: false });
        if (error) throw error;

        // Lấy thông tin đơn ứng tuyển đã được duyệt
        const { data: apps } = await supabase
            .from('job_applications')
            .select('job_id, freelancer_id, freelancers:freelancer_id(full_name, email)')
            .eq('status', 'accepted');

        const disputes = getDisputes();

        const allMods = aiModeration.getAllModerations();
        const fullJobs = (jobs || []).map(j => {
            const app = (apps || []).find(a => a.job_id === j.id);
            const mod = allMods[j.id] || {
                is_approved: j.status !== 'pending_review' && j.status !== 'rejected',
                score: j.status === 'open' ? 92 : (j.status === 'rejected' ? 20 : 50),
                reason: j.status === 'open' ? 'Nội dung chuẩn mực (AI Phê Duyệt)' : (j.status === 'rejected' ? 'Bài viết đã bị từ chối' : 'Chờ Quản trị viên hậu kiểm'),
                flagged: j.status === 'pending_review'
            };
            return {
                ...j,
                freelancer: app ? app.freelancers : null,
                freelancer_id: app ? app.freelancer_id : null,
                dispute: disputes[j.id] || null,
                moderation: mod
            };
        });

        res.status(200).json({ projects: fullJobs });
    } catch (err) {
        console.error('[Admin Get Projects Error]:', err);
        res.status(400).json({ error: err.message });
    }
});

// 3. Admin Phán Quyết Tranh Chấp (Resolve Dispute: 'client' | 'freelancer' | 'split_50_50')
router.post('/api/admin/projects/resolve-dispute', async (req, res) => {
    const { job_id, winner, admin_note } = req.body;
    try {
        if (!job_id || !['client', 'freelancer', 'split_50_50'].includes(winner)) {
            return res.status(400).json({ error: 'Phán quyết không hợp lệ. Chọn client, freelancer hoặc split_50_50.' });
        }

        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr || !job) throw new Error('Không tìm thấy dự án tương ứng.');

        const { data: appData } = await supabase
            .from('job_applications')
            .select('freelancer_id')
            .eq('job_id', job_id)
            .eq('status', 'accepted')
            .single();
        if (!appData) throw new Error('Không tìm thấy Freelancer của hợp đồng này.');

        const client_id = job.client_id;
        const freelancer_id = appData.freelancer_id;

        // Tính tổng tiền Escrow còn lại chưa thanh toán
        const { data: pendingMilestones } = await supabase
            .from('milestones')
            .select('amount')
            .eq('job_id', job_id)
            .neq('status', 'PAID');
        const amount = (pendingMilestones || []).reduce((sum, m) => sum + parseFloat(m.amount || 0), 0);

        const { data: clientWallet } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        const { data: freeWallet } = await supabase.from('wallets').select('*').eq('user_id', freelancer_id).single();

        if (clientWallet && clientWallet.locked_balance < amount) {
            throw new Error(`Số dư đóng băng không khớp! Chỉ còn ${clientWallet.locked_balance} Token nhưng yêu cầu xử lý ${amount} Token.`);
        }

        let verdictText = '';
        let clientRefundAmount = 0;
        let freelancerPayoutAmount = 0;

        if (winner === 'client') {
            // Khách hàng thắng: Hoàn 100% tiền chưa thanh toán về ví Khách
            clientRefundAmount = amount;
            verdictText = 'KHÁCH HÀNG THẮNG (Hoàn 100% tiền ký quỹ về ví Khách)';

            if (amount > 0 && clientWallet) {
                await supabase.from('wallets').update({
                    locked_balance: clientWallet.locked_balance - amount,
                    balance: clientWallet.balance + amount
                }).eq('user_id', client_id);

                // Ghi sổ cái Double-Entry Ledger
                await supabase.from('wallet_ledger').insert([{
                    sender_id: '00000000-0000-0000-0000-000000000001',
                    receiver_id: client_id,
                    amount: amount,
                    type: 'DISPUTE_REFUND',
                    idempotency_key: `dispute_refund_${job_id}_${Date.now()}`,
                    note: `Phán quyết tranh chấp dự án "${job.title}": Hoàn ${amount.toLocaleString()} Token về ví Khách`
                }]).catch(() => {});
            }

            await supabase.from('milestones').update({ status: 'CANCELLED' }).eq('job_id', job_id).neq('status', 'PAID');
            await supabase.from('jobs').update({ status: 'cancelled' }).eq('id', job_id);

        } else if (winner === 'freelancer') {
            // Freelancer thắng: Ép giải ngân 100% tiền còn lại cho Freelancer
            freelancerPayoutAmount = amount;
            verdictText = 'FREELANCER THẮNG (Ép giải ngân 100% tiền ký quỹ cho Freelancer)';

            if (amount > 0 && clientWallet) {
                await supabase.from('wallets').update({
                    locked_balance: clientWallet.locked_balance - amount
                }).eq('user_id', client_id);

                const currentFreeBalance = freeWallet ? freeWallet.balance : 0;
                if (!freeWallet) {
                    await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: amount, locked_balance: 0 }]);
                } else {
                    await supabase.from('wallets').update({ balance: currentFreeBalance + amount }).eq('user_id', freelancer_id);
                }

                // Ghi sổ cái Double-Entry Ledger
                await supabase.from('wallet_ledger').insert([{
                    sender_id: client_id,
                    receiver_id: freelancer_id,
                    amount: amount,
                    type: 'DISPUTE_RELEASE',
                    idempotency_key: `dispute_release_${job_id}_${Date.now()}`,
                    note: `Phán quyết tranh chấp dự án "${job.title}": Giải ngân ${amount.toLocaleString()} Token cho Freelancer`
                }]).catch(() => {});

                // Đồng bộ Blockchain Sepolia nếu có cấu hình
                if (blockchain.isConfigured()) {
                    await blockchain.transferBalance(client_id, freelancer_id, amount).catch(() => {});
                }
            }

            await supabase.from('milestones').update({ status: 'PAID' }).eq('job_id', job_id).neq('status', 'PAID');
            await supabase.from('jobs').update({ status: 'completed' }).eq('id', job_id);

        } else if (winner === 'split_50_50') {
            // Phán quyết hòa giải 50/50: Khách nhận 50%, Freelancer nhận 50%
            clientRefundAmount = Math.floor(amount / 2);
            freelancerPayoutAmount = amount - clientRefundAmount;
            verdictText = `HÒA GIẢI 50/50 (Hoàn ${clientRefundAmount.toLocaleString()} Token cho Khách & Giải ngân ${freelancerPayoutAmount.toLocaleString()} Token cho Freelancer)`;

            if (amount > 0 && clientWallet) {
                // Trừ toàn bộ số dư locked của Client
                await supabase.from('wallets').update({
                    locked_balance: clientWallet.locked_balance - amount,
                    balance: clientWallet.balance + clientRefundAmount
                }).eq('user_id', client_id);

                const currentFreeBalance = freeWallet ? freeWallet.balance : 0;
                if (!freeWallet) {
                    await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: freelancerPayoutAmount, locked_balance: 0 }]);
                } else {
                    await supabase.from('wallets').update({ balance: currentFreeBalance + freelancerPayoutAmount }).eq('user_id', freelancer_id);
                }

                // Ghi sổ cái cho Khách
                if (clientRefundAmount > 0) {
                    await supabase.from('wallet_ledger').insert([{
                        sender_id: '00000000-0000-0000-0000-000000000001',
                        receiver_id: client_id,
                        amount: clientRefundAmount,
                        type: 'DISPUTE_SPLIT_REFUND',
                        idempotency_key: `split_refund_${job_id}_${Date.now()}`,
                        note: `Phán quyết hòa giải 50/50: Hoàn ${clientRefundAmount.toLocaleString()} Token cho Khách`
                    }]).catch(() => {});
                }

                // Ghi sổ cái cho Freelancer
                if (freelancerPayoutAmount > 0) {
                    await supabase.from('wallet_ledger').insert([{
                        sender_id: client_id,
                        receiver_id: freelancer_id,
                        amount: freelancerPayoutAmount,
                        type: 'DISPUTE_SPLIT_PAYOUT',
                        idempotency_key: `split_payout_${job_id}_${Date.now()}`,
                        note: `Phán quyết hòa giải 50/50: Giải ngân ${freelancerPayoutAmount.toLocaleString()} Token cho Freelancer`
                    }]).catch(() => {});
                }
            }

            await supabase.from('milestones').update({ status: 'PAID' }).eq('job_id', job_id).neq('status', 'PAID');
            await supabase.from('jobs').update({ status: 'completed' }).eq('id', job_id);
        }

        // Xóa hoặc lưu trạng thái đã giải quyết
        let disputes = getDisputes();
        if (disputes[job_id]) {
            delete disputes[job_id];
            saveDisputes(disputes);
        }

        // Gửi Thông Báo Tới Cả 2 Bên
        await sendNotification(
            client_id,
            '⚖️ Phán quyết cuối cùng của Tòa án KGS Work',
            `Dự án "${job.title}" đã được Admin phán quyết: ${verdictText}. ${clientRefundAmount > 0 ? `Ví bạn được cộng lại +${clientRefundAmount.toLocaleString()} Token.` : ''}`
        );

        await sendNotification(
            freelancer_id,
            '⚖️ Phán quyết cuối cùng của Tòa án KGS Work',
            `Dự án "${job.title}" đã được Admin phán quyết: ${verdictText}. ${freelancerPayoutAmount > 0 ? `Ví bạn nhận được +${freelancerPayoutAmount.toLocaleString()} Token.` : ''}`
        );

        // Ghi Log Kiểm Toán
        await logEvent({
            module: 'DISPUTE',
            action: 'RESOLVE_DISPUTE',
            level: 'CRITICAL',
            details: `Admin đã đưa ra phán quyết: [${verdictText}] cho dự án "${job.title}" (Tổng tiền tranh chấp: ${amount.toLocaleString()} Token)`,
            user_id: '11111111-1111-1111-1111-111111111111',
            user_email: 'admin@kgs work.vn',
            user_role: 'admin',
            metadata: {
                job_id,
                job_title: job.title,
                winner,
                amount,
                clientRefundAmount,
                freelancerPayoutAmount,
                client_id,
                freelancer_id,
                admin_note: admin_note || ''
            }
        });

        res.status(200).json({
            success: true,
            message: `Đã thực thi phán quyết thành công: ${verdictText}!`
        });
    } catch (err) {
        console.error('[Resolve Dispute Error]:', err);
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;
