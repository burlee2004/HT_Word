const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const notificationService = require('../services/notificationService');

// 14. API: Lấy thông báo của user
router.get('/api/notifications/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('notifications')
            .select('*')
            .eq('user_id', user_id)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ notifications: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15. API: Xóa thông báo
router.delete('/api/notifications/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { error } = await supabase.from('notifications').delete().eq('id', id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã xóa thông báo' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 16. API: Đánh dấu thông báo đã đọc
router.put('/api/notifications/:id/read', async (req, res) => {
    const { id } = req.params;
    try {
        const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã đánh dấu đã đọc' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 17. API: Đánh dấu TẤT CẢ thông báo đã đọc
router.put('/api/notifications/user/:user_id/read-all', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { error } = await supabase.from('notifications').update({ is_read: true }).eq('user_id', user_id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã đánh dấu tất cả đã đọc' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 18. API: Xóa TẤT CẢ thông báo
router.delete('/api/notifications/user/:user_id/delete-all', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { error } = await supabase.from('notifications').delete().eq('user_id', user_id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã xóa tất cả thông báo' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 19. API: Phát thông báo toàn server (Broadcast tới toàn bộ user hoặc theo role)
router.post('/api/notifications/broadcast', async (req, res) => {
    try {
        const { title, content, role, admin_id } = req.body;
        if (!title || !content) {
            return res.status(400).json({ error: 'Tiêu đề và nội dung thông báo không được để trống.' });
        }

        let result;
        if (role && ['client', 'freelancer'].includes(role.toLowerCase())) {
            result = await notificationService.broadcastToRole(role.toLowerCase(), { title, content, actor_id: admin_id });
        } else {
            result = await notificationService.broadcastToAllUsers({ title, content, actor_id: admin_id });
        }

        res.status(200).json({
            success: true,
            message: `Đã gửi thông báo thành công tới ${result.delivered_count} tài khoản.`,
            ...result
        });
    } catch (error) {
        console.error('Lỗi khi broadcast thông báo:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
