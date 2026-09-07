const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');
const { logEvent, getAuditLogs } = require('../services/auditLogger');
const { getDisputes } = require('../services/disputeStore');

// 1. API: Thống kê tổng quan KPI cho Admin Dashboard
router.get('/api/admin/stats', async (req, res) => {
    try {
        // Users stats
        const { data: users, error: uErr } = await supabase.from('users').select('id, role');
        const totalUsers = users ? users.length : 0;
        const totalClients = users ? users.filter(u => u.role === 'client').length : 0;
        const totalFreelancers = users ? users.filter(u => u.role === 'freelancer').length : 0;

        // Jobs stats
        const { data: jobs, error: jErr } = await supabase.from('jobs').select('id, status, budget');
        const totalJobs = jobs ? jobs.length : 0;
        const activeJobs = jobs ? jobs.filter(j => ['in_progress', 'planning', 'pending_plan_approval'].includes(j.status)).length : 0;
        const disputedJobs = jobs ? jobs.filter(j => j.status === 'disputed').length : 0;
        const completedJobs = jobs ? jobs.filter(j => j.status === 'completed').length : 0;

        // Wallets & Escrow stats
        const { data: wallets } = await supabase.from('wallets').select('balance, locked_balance');
        let totalBalance = 0;
        let totalLockedEscrow = 0;
        if (wallets) {
            wallets.forEach(w => {
                totalBalance += parseFloat(w.balance || 0);
                totalLockedEscrow += parseFloat(w.locked_balance || 0);
            });
        }

        // Withdraw requests stats
        const { data: withdraws } = await supabase.from('withdraw_requests').select('amount, status');
        const pendingWithdraws = (withdraws || []).filter(w => w.status === 'pending');
        const pendingWithdrawCount = pendingWithdraws.length;
        const pendingWithdrawAmount = pendingWithdraws.reduce((sum, w) => sum + parseFloat(w.amount || 0), 0);

        res.status(200).json({
            success: true,
            stats: {
                total_users: totalUsers,
                total_clients: totalClients,
                total_freelancers: totalFreelancers,
                total_jobs: totalJobs,
                active_jobs: activeJobs,
                disputed_jobs: disputedJobs,
                completed_jobs: completedJobs,
                total_balance: totalBalance,
                total_escrow_locked: totalLockedEscrow,
                pending_withdraw_count: pendingWithdrawCount,
                pending_withdraw_amount: pendingWithdrawAmount
            }
        });
    } catch (error) {
        console.error('Lỗi lấy admin stats:', error);
        res.status(500).json({ error: error.message });
    }
});

// 2. API: Lấy danh sách toàn bộ người dùng kèm số dư ví & trạng thái
router.get('/api/admin/users', async (req, res) => {
    try {
        const { search, role } = req.query;

        let query = supabase.from('users').select(`
            id, full_name, email, role, avatar_url, bank_name, bank_account, bank_owner, phone_number, is_email_verified, kyc_status, created_at,
            wallets (balance, locked_balance)
        `).order('created_at', { ascending: false });

        if (role && role !== 'all') {
            query = query.eq('role', role);
        }

        const { data: users, error } = await query;
        if (error) throw error;

        let formattedUsers = (users || []).map(u => {
            const w = Array.isArray(u.wallets) ? u.wallets[0] : u.wallets;
            return {
                id: u.id,
                full_name: u.full_name || 'Chưa đặt tên',
                email: u.email,
                role: u.role || 'client',
                avatar_url: u.avatar_url,
                phone_number: u.phone_number || '',
                bank_name: u.bank_name || '',
                bank_account: u.bank_account || '',
                bank_owner: u.bank_owner || '',
                balance: w ? parseFloat(w.balance || 0) : 0,
                locked_balance: w ? parseFloat(w.locked_balance || 0) : 0,
                kyc_status: u.kyc_status || (u.bank_account ? 'VERIFIED' : 'UNVERIFIED'),
                is_active: u.kyc_status !== 'BANNED',
                created_at: u.created_at
            };
        });

        if (search && search.trim()) {
            const s = search.trim().toLowerCase();
            formattedUsers = formattedUsers.filter(u => 
                u.full_name.toLowerCase().includes(s) ||
                u.email.toLowerCase().includes(s) ||
                u.phone_number.includes(s)
            );
        }

        res.status(200).json({ success: true, users: formattedUsers });
    } catch (error) {
        console.error('Lỗi lấy danh sách users:', error);
        res.status(500).json({ error: error.message });
    }
});

// 3. API: Khóa / Mở khóa tài khoản người dùng
router.put('/api/admin/users/:id/status', async (req, res) => {
    const { id } = req.params;
    const { is_active, reason, admin_id } = req.body;
    try {
        const newStatus = is_active ? 'VERIFIED' : 'BANNED';
        const { data: updated, error } = await supabase
            .from('users')
            .update({ kyc_status: newStatus })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        // Ghi log kiểm toán
        await logEvent({
            module: 'ADMIN',
            action: is_active ? 'UNBAN_USER' : 'BAN_USER',
            level: is_active ? 'WARN' : 'SECURITY',
            details: `Admin ${admin_id || 'System'} đã ${is_active ? 'mở khóa' : 'khóa'} tài khoản ${updated.email}. Lý do: ${reason || 'Không có'}`,
            user_id: id,
            user_email: updated.email,
            user_role: updated.role,
            metadata: { is_active, reason, admin_id }
        });

        res.status(200).json({ success: true, message: `Đã ${is_active ? 'mở khóa' : 'khóa'} tài khoản thành công!`, user: updated });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. API: Chuyển đổi vai trò người dùng (Client <-> Freelancer <-> Admin)
router.put('/api/admin/users/:id/role', async (req, res) => {
    const { id } = req.params;
    const { role, admin_id } = req.body;
    try {
        if (!['client', 'freelancer', 'admin'].includes(role)) {
            return res.status(400).json({ error: 'Vai trò không hợp lệ' });
        }

        const { data: updated, error } = await supabase
            .from('users')
            .update({ role: role })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        // Ghi log kiểm toán
        await logEvent({
            module: 'ADMIN',
            action: 'CHANGE_USER_ROLE',
            level: 'SECURITY',
            details: `Admin đã chuyển vai trò của người dùng ${updated.email} sang: [${role.toUpperCase()}]`,
            user_id: id,
            user_email: updated.email,
            user_role: role,
            metadata: { new_role: role, admin_id }
        });

        res.status(200).json({ success: true, message: `Đã cập nhật vai trò sang ${role}!`, user: updated });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. API: Điều chỉnh số dư Token trực tiếp (Cấp / Trừ Token hỗ trợ đối soát)
router.post('/api/admin/users/:id/adjust-tokens', async (req, res) => {
    const { id } = req.params;
    const { amount, action_type, reason, admin_id } = req.body; // action_type: 'CREDIT' | 'DEBIT'
    try {
        const adjustAmount = parseFloat(amount);
        if (!adjustAmount || adjustAmount <= 0) {
            return res.status(400).json({ error: 'Số lượng Token phải lớn hơn 0' });
        }

        const { data: wallet, error: wErr } = await supabase.from('wallets').select('*').eq('user_id', id).single();
        if (wErr || !wallet) throw new Error('Không tìm thấy ví người dùng');

        const currentBalance = parseFloat(wallet.balance || 0);
        let newBalance = currentBalance;

        if (action_type === 'CREDIT') {
            newBalance = currentBalance + adjustAmount;
        } else if (action_type === 'DEBIT') {
            if (currentBalance < adjustAmount) {
                return res.status(400).json({ error: `Số dư người dùng chỉ có ${currentBalance} Token, không thể trừ ${adjustAmount} Token` });
            }
            newBalance = currentBalance - adjustAmount;
        } else {
            return res.status(400).json({ error: 'Hành động không hợp lệ' });
        }

        // Cập nhật ví
        await supabase.from('wallets').update({ balance: newBalance }).eq('user_id', id);

        // Ghi sổ cái giao dịch
        await supabase.from('wallet_ledger').insert([{
            sender_id: action_type === 'CREDIT' ? '11111111-1111-1111-1111-111111111111' : id,
            receiver_id: action_type === 'CREDIT' ? id : '11111111-1111-1111-1111-111111111111',
            amount: adjustAmount,
            type: action_type === 'CREDIT' ? 'ADMIN_CREDIT' : 'ADMIN_DEBIT',
            idempotency_key: `ADJUST_${id}_${Date.now()}`,
            note: `[Admin Điều Chỉnh] ${reason || 'Đối soát số dư'}`
        }]);

        // Lấy email user
        const { data: user } = await supabase.from('users').select('email, role').eq('id', id).single();

        // Ghi log kiểm toán
        await logEvent({
            module: 'FINANCE',
            action: action_type === 'CREDIT' ? 'ADMIN_CREDIT_TOKEN' : 'ADMIN_DEBIT_TOKEN',
            level: 'WARN',
            details: `Admin đã ${action_type === 'CREDIT' ? 'cấp thêm' : 'khấu trừ'} ${adjustAmount.toLocaleString()} Token cho ${user?.email || id}. Lý do: ${reason || 'Đối soát số dư'}`,
            user_id: id,
            user_email: user?.email,
            user_role: user?.role,
            metadata: { amount: adjustAmount, action_type, reason, admin_id, old_balance: currentBalance, new_balance: newBalance }
        });

        res.status(200).json({ success: true, message: `Đã ${action_type === 'CREDIT' ? 'cộng' : 'trừ'} ${adjustAmount.toLocaleString()} Token thành công!`, new_balance: newBalance });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 6. API: Lấy danh sách Nhật Ký Kiểm Toán Hệ Thống Toàn Diện (System Audit Logs)
router.get('/api/admin/audit-logs', async (req, res) => {
    try {
        const { module, level, search, limit, offset } = req.query;
        const result = getAuditLogs({
            module: module || 'ALL',
            level: level || 'ALL',
            search: search || '',
            limit: parseInt(limit) || 100,
            offset: parseInt(offset) || 0
        });

        res.status(200).json({
            success: true,
            total: result.total,
            logs: result.logs
        });
    } catch (error) {
        console.error('Lỗi lấy audit logs:', error);
        res.status(500).json({ error: error.message });
    }
});

// 7. API: Trích xuất toàn bộ dữ liệu lưu vết tin nhắn Chat của một dự án (phục vụ phán quyết tranh chấp)
router.get('/api/admin/projects/:id/chat-logs', async (req, res) => {
    const { id } = req.params;
    try {
        const { data: messages, error } = await supabase
            .from('messages')
            .select('*, users:sender_id(id, full_name, email, role, avatar_url)')
            .eq('job_id', id)
            .order('created_at', { ascending: true });

        if (error) throw error;

        // Ghi log việc Admin trích xuất chứng cứ
        await logEvent({
            module: 'DISPUTE',
            action: 'EXTRACT_CHAT_EVIDENCE',
            level: 'INFO',
            details: `Admin đã trích xuất dữ liệu lưu vết chat của dự án ID: ${id} (${messages ? messages.length : 0} tin nhắn)`,
            metadata: { job_id: id, message_count: messages ? messages.length : 0 }
        });

        res.status(200).json({ success: true, messages: messages || [] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
