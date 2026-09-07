const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');

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

module.exports = router;
