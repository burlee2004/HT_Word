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

// 3. Thả tim / Bỏ tim Mối Ruột (Toggle Favorite)
router.post('/api/connections/toggle-favorite', async (req, res) => {
    const { user_id, target_user_id } = req.body;
    try {
        const result = await connectionStore.toggleFavorite(user_id, target_user_id);
        
        logEvent({
            module: 'AUTH',
            action: result.is_favorite ? 'ADD_FAVORITE_PARTNER' : 'REMOVE_FAVORITE_PARTNER',
            actor_id: user_id,
            target_id: target_user_id,
            level: 'INFO',
            details: `Người dùng ${user_id} đã ${result.is_favorite ? 'thêm' : 'bỏ'} ${target_user_id} vào danh sách Mối Ruột ❤️`,
            metadata: { user_id, target_user_id, is_favorite: result.is_favorite }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. Hủy kết bạn (Unfriend)
router.post('/api/connections/unfriend', async (req, res) => {
    const { user_id, target_user_id } = req.body;
    try {
        const result = await connectionStore.unfriend(user_id, target_user_id);
        
        logEvent({
            module: 'AUTH',
            action: 'UNFRIEND_USER',
            actor_id: user_id,
            target_id: target_user_id,
            level: 'INFO',
            details: `Người dùng ${user_id} đã hủy kết bạn với ${target_user_id}`,
            metadata: { user_id, target_user_id }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. Chặn người dùng (Block)
router.post('/api/connections/block', async (req, res) => {
    const { user_id, target_user_id } = req.body;
    try {
        const result = await connectionStore.blockUser(user_id, target_user_id);
        
        logEvent({
            module: 'AUTH',
            action: 'BLOCK_USER',
            actor_id: user_id,
            target_id: target_user_id,
            level: 'WARNING',
            details: `Người dùng ${user_id} đã chặn ${target_user_id}`,
            metadata: { user_id, target_user_id }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 6. Bỏ chặn người dùng (Unblock)
router.post('/api/connections/unblock', async (req, res) => {
    const { user_id, target_user_id } = req.body;
    try {
        const result = await connectionStore.unblockUser(user_id, target_user_id);
        
        logEvent({
            module: 'AUTH',
            action: 'UNBLOCK_USER',
            actor_id: user_id,
            target_id: target_user_id,
            level: 'INFO',
            details: `Người dùng ${user_id} đã bỏ chặn ${target_user_id}`,
            metadata: { user_id, target_user_id }
        });

        res.status(200).json({ success: true, ...result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 7. Lấy mạng lưới bạn bè / mối ruột & lời mời đang chờ
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

// 8. Kiểm tra trạng thái quan hệ giữa 2 người dùng
router.get('/api/connections/status/:user_1/:user_2', async (req, res) => {
    const { user_1, user_2 } = req.params;
    try {
        const status = connectionStore.getConnectionStatus(user_1, user_2);
        res.status(200).json({ success: true, ...status });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;

