const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const supportStore = require('../services/supportStore');
const { logEvent } = require('../services/auditLogger');

// 1. Lấy trạng thái Trực tuyến của Admin
router.get('/api/admin/online-status', (req, res) => {
    try {
        const status = supportStore.getAdminOnlineStatus();
        res.status(200).json(status);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Admin Heartbeat (Gửi định kỳ từ trang Admin để duy trì trạng thái Online)
router.post('/api/admin/heartbeat', (req, res) => {
    try {
        const { admin_id, admin_name } = req.body;
        const status = supportStore.recordAdminHeartbeat({ admin_id, admin_name });
        res.status(200).json({ success: true, status });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Người dùng (Freelancer / Client) gửi yêu cầu hỗ trợ (Ticket)
router.post('/api/support/tickets', async (req, res) => {
    const { user_id, category, priority, subject, message, attachments, phone } = req.body;
    
    if (!user_id || !subject || !message) {
        return res.status(400).json({ error: 'Vui lòng nhập đầy đủ tiêu đề và nội dung yêu cầu hỗ trợ!' });
    }

    try {
        // Lấy thông tin user mới nhất từ database
        let userInfo = {
            id: user_id,
            full_name: req.body.user_name || 'Người dùng',
            email: req.body.user_email || '',
            role: req.body.user_role || 'client',
            avatar_url: req.body.user_avatar || '',
            phone_number: phone || ''
        };

        try {
            const { data: dbUser } = await supabase
                .from('users')
                .select('id, full_name, email, role, avatar_url, phone_number')
                .eq('id', user_id)
                .single();
            if (dbUser) {
                userInfo = { ...userInfo, ...dbUser };
            }
        } catch (e) {}

        const ticket = supportStore.createTicket({
            user_id: userInfo.id,
            user_name: userInfo.full_name,
            user_email: userInfo.email,
            user_role: userInfo.role,
            user_avatar: userInfo.avatar_url,
            phone: phone || userInfo.phone_number || '',
            category: category || 'other',
            priority: priority || 'medium',
            subject: subject.trim(),
            message: message.trim(),
            attachments: Array.isArray(attachments) ? attachments : []
        });

        // Ghi log kiểm toán
        logEvent({
            module: 'SUPPORT',
            action: 'CREATE_TICKET',
            level: priority === 'urgent' ? 'CRITICAL' : 'INFO',
            details: `[${userInfo.role.toUpperCase()}] ${userInfo.full_name} đã gửi yêu cầu hỗ trợ ${ticket.ticket_code}: "${subject}"`,
            user_id: userInfo.id,
            user_email: userInfo.email,
            user_role: userInfo.role,
            metadata: { ticket_code: ticket.ticket_code, category, priority }
        });

        res.status(201).json({
            success: true,
            message: `Gửi yêu cầu hỗ trợ thành công! Mã vé của bạn là ${ticket.ticket_code}`,
            ticket
        });
    } catch (err) {
        console.error('[Create Ticket Error]:', err);
        res.status(500).json({ error: 'Không thể tạo yêu cầu hỗ trợ: ' + err.message });
    }
});

// 4. Lấy danh sách Ticket của User hiện tại
router.get('/api/support/my-tickets', (req, res) => {
    const { user_id } = req.query;
    if (!user_id) {
        return res.status(400).json({ error: 'Thiếu user_id' });
    }
    try {
        const tickets = supportStore.getUserTickets(user_id);
        res.status(200).json({ success: true, tickets });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Lấy chi tiết 1 Ticket
router.get('/api/support/tickets/:id', (req, res) => {
    try {
        const ticket = supportStore.getTicketById(req.params.id);
        if (!ticket) return res.status(404).json({ error: 'Không tìm thấy yêu cầu hỗ trợ' });
        res.status(200).json({ success: true, ticket });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Admin: Lấy toàn bộ danh sách Ticket (Có lọc & tìm kiếm)
router.get('/api/admin/support/tickets', (req, res) => {
    try {
        let tickets = supportStore.getTickets();
        const { status, role, category, search } = req.query;

        if (status && status !== 'all') {
            tickets = tickets.filter(t => t.status === status);
        }
        if (role && role !== 'all') {
            tickets = tickets.filter(t => t.user_role === role);
        }
        if (category && category !== 'all') {
            tickets = tickets.filter(t => t.category === category);
        }
        if (search) {
            const q = search.toLowerCase();
            tickets = tickets.filter(t => 
                (t.ticket_code && t.ticket_code.toLowerCase().includes(q)) ||
                (t.subject && t.subject.toLowerCase().includes(q)) ||
                (t.user_name && t.user_name.toLowerCase().includes(q)) ||
                (t.user_email && t.user_email.toLowerCase().includes(q))
            );
        }

        res.status(200).json({ success: true, tickets, total: tickets.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. Admin: Phản hồi & Cập nhật trạng thái Ticket
router.put('/api/admin/support/tickets/:id', async (req, res) => {
    const { id } = req.params;
    const { status, admin_reply, admin_name } = req.body;

    try {
        const existing = supportStore.getTicketById(id);
        if (!existing) {
            return res.status(404).json({ error: 'Không tìm thấy ticket' });
        }

        const updateFields = {};
        if (status) updateFields.status = status;
        if (admin_reply !== undefined) {
            updateFields.admin_reply = admin_reply;
            updateFields.admin_replied_at = new Date().toISOString();
            updateFields.admin_name = admin_name || 'Quản Trị Viên KGS Work';
        }

        const updated = supportStore.updateTicket(id, updateFields);

        // Tự động gửi thông báo chuông cho người dùng
        if (admin_reply && existing.user_id) {
            try {
                await supabase.from('notifications').insert([{
                    user_id: existing.user_id,
                    title: `Admin đã phản hồi yêu cầu ${existing.ticket_code}`,
                    content: `Vấn đề: "${existing.subject}". Phản hồi: ${admin_reply.slice(0, 100)}${admin_reply.length > 100 ? '...' : ''}`,
                    type: 'support_reply',
                    created_at: new Date().toISOString()
                }]);
            } catch (notiErr) {
                console.warn('[Notification Error]:', notiErr.message);
            }
        }

        // Ghi log kiểm toán
        logEvent({
            module: 'SUPPORT',
            action: 'REPLY_TICKET',
            level: 'INFO',
            details: `Admin đã phản hồi yêu cầu ${existing.ticket_code} (Trạng thái: ${updated.status})`,
            actor_id: 'ADMIN',
            target_id: existing.user_id,
            metadata: { ticket_code: existing.ticket_code, status: updated.status }
        });

        res.status(200).json({
            success: true,
            message: 'Đã cập nhật yêu cầu hỗ trợ thành công!',
            ticket: updated
        });
    } catch (err) {
        console.error('[Update Ticket Error]:', err);
        res.status(500).json({ error: 'Không thể cập nhật ticket: ' + err.message });
    }
});

module.exports = router;
