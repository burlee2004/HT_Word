const express = require('express');
const router = express.Router();
const connectionStore = require('../services/connectionStore');
const { logEvent } = require('../services/auditLogger');
const supabase = require('../config/supabase');

// 1. Gửi lời mời kết bạn / thêm mối ruột
router.post('/api/connections/request', async (req, res) => {
    const { sender_id, receiver_id, note } = req.body;
    try {
        const result = await connectionStore.sendConnectionRequest(sender_id, receiver_id, note);
        
        // Push notification cho người nhận
        try {
            const { data: sender } = await supabase.from('users').select('full_name').eq('id', sender_id).single();
            const senderName = sender ? sender.full_name : 'Một người dùng';
            await supabase.from('notifications').insert([{
                user_id: receiver_id,
                title: '🤝 Lời mời kết bạn mới',
                content: `${senderName} đã gửi cho bạn lời mời kết nối / hợp tác.`
            }]);
        } catch (e) {}

        logEvent({
            module: 'AUTH',
            action: 'SEND_FRIEND_REQUEST',
            actor_id: sender_id,
            target_id: receiver_id,
            level: 'INFO',
            details: `Người dùng ${sender_id} gửi lời mời kết bạn cho ${receiver_id}`,
            metadata: { sender_id, receiver_id, note }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 2. Phản hồi lời mời kết bạn (Chấp nhận / Từ chối / Hủy kết bạn)
router.post('/api/connections/respond', async (req, res) => {
    const { user_id, target_user_id, action } = req.body;
    try {
        const result = await connectionStore.respondConnectionRequest(user_id, target_user_id, action);
        
        if (action === 'accept') {
            try {
                const { data: user } = await supabase.from('users').select('full_name').eq('id', user_id).single();
                const userName = user ? user.full_name : 'Một người dùng';
                await supabase.from('notifications').insert([{
                    user_id: target_user_id,
                    title: '🎉 Lời mời kết bạn được chấp nhận',
                    content: `${userName} đã đồng ý kết bạn! Hai bạn hiện đã có thể giao việc trực tiếp và nhắn tin 1-1 tự do.`
                }]);
            } catch (e) {}
        }

        logEvent({
            module: 'AUTH',
            action: `RESPOND_FRIEND_REQUEST_${action.toUpperCase()}`,
            actor_id: user_id,
            target_id: target_user_id,
            level: 'INFO',
            details: `Người dùng ${user_id} đã ${action} lời mời kết bạn với ${target_user_id}`,
            metadata: { user_id, target_user_id, action }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. Lấy mạng lưới bạn bè / mối ruột & lời mời đang chờ
router.get('/api/connections/:user_id', async (req, res) => {
    const { user_id } = req.params;
    const { search } = req.query;
    try {
        const data = await connectionStore.getUserNetwork(user_id, search);
        res.status(200).json({ success: true, ...data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. Kiểm tra trạng thái quan hệ giữa 2 người dùng
router.get('/api/connections/status/:user_1/:user_2', async (req, res) => {
    const { user_1, user_2 } = req.params;
    try {
        const status = connectionStore.getConnectionStatus(user_1, user_2);
        const isFriend = connectionStore.isFriend(user_1, user_2);
        res.status(200).json({ success: true, ...status, is_friend: isFriend });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
