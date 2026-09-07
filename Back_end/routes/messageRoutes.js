const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const directMessageStore = require('../services/directMessageStore');
const { logEvent } = require('../services/auditLogger');

// ==========================================
// 1. CHAT TRONG DỰ ÁN (PROJECT CHAT)
// ==========================================

// Lấy tin nhắn Chat theo Job ID
router.get('/api/jobs/:job_id/messages', async (req, res) => {
    const { job_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('messages')
            .select('*, users(full_name, role, avatar_url)')
            .eq('job_id', job_id)
            .order('created_at', { ascending: true });
        if (error) throw error;
        res.status(200).json({ messages: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Gửi tin nhắn Chat trong Job
router.post('/api/jobs/:job_id/messages', async (req, res) => {
    const { job_id } = req.params;
    const { sender_id, milestone_id, content, file_url, file_type, file_name } = req.body;
    try {
        const { data, error } = await supabase.from('messages').insert([{
            job_id, sender_id, milestone_id, content, file_url, file_type
        }]).select('*, users(full_name, role, avatar_url)');
        if (error) throw error;

        // Lấy thông tin user để push thông báo
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', job_id).single();
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        
        if (jobData && appData) {
            const recipient_id = (sender_id === jobData.client_id) ? appData.freelancer_id : jobData.client_id;
            await supabase.from('notifications').insert([{
                user_id: recipient_id,
                title: 'Tin nhắn mới trong dự án',
                content: `Bạn có tin nhắn hoặc tệp đính kèm mới trong dự án. Hãy vào phòng chat kiểm tra!`
            }]);
        }

        logEvent({
            module: 'CHAT',
            action: 'SEND_PROJECT_MESSAGE',
            actor_id: sender_id,
            level: 'INFO',
            details: `Gửi tin nhắn trong dự án #${job_id}`,
            metadata: { job_id, sender_id, has_file: !!file_url }
        });

        res.status(201).json({ message: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// 2. CHAT 1-1 TRỰC TIẾP (DIRECT 1-ON-1 MESSAGING)
// ==========================================

// Lấy lịch sử chat 1-1 giữa 2 người dùng (hỗ trợ tìm kiếm theo từ khóa)
router.get('/api/messages/direct/:user_1/:user_2', async (req, res) => {
    const { user_1, user_2 } = req.params;
    const { search } = req.query;
    try {
        const messages = await directMessageStore.getDirectMessages(user_1, user_2, search);
        res.status(200).json({ success: true, messages });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Gửi tin nhắn chat 1-1
router.post('/api/messages/direct', async (req, res) => {
    const { sender_id, receiver_id, content, file_url, file_name, file_type } = req.body;
    try {
        const msg = await directMessageStore.sendDirectMessage({
            sender_id,
            receiver_id,
            content,
            file_url,
            file_name,
            file_type
        });

        logEvent({
            module: 'CHAT',
            action: 'SEND_DIRECT_MESSAGE',
            actor_id: sender_id,
            target_id: receiver_id,
            level: 'INFO',
            details: `Gửi tin nhắn 1-1 từ ${sender_id} tới ${receiver_id}`,
            metadata: { sender_id, receiver_id, has_file: !!file_url }
        });

        res.status(201).json({ success: true, message: msg });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Lấy danh sách các cuộc hội thoại 1-1 gần nhất (Inbox list)
router.get('/api/messages/conversations/:user_id', async (req, res) => {
    const { user_id } = req.params;
    const { search } = req.query;
    try {
        const conversations = await directMessageStore.getConversationsList(user_id, search);
        res.status(200).json({ success: true, conversations });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
