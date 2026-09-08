const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const directMessageStore = require('../services/directMessageStore');
const chatModeration = require('../services/chatModerationService');
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
        // Kiểm duyệt nội dung tin nhắn
        const modResult = chatModeration.moderateMessage(content);
        if (modResult.is_flagged) {
            logEvent({
                module: 'CHAT',
                action: 'CHAT_POLICY_VIOLATION',
                user_id: sender_id,
                level: 'SECURITY',
                details: `[VI PHẠM CHAT DỰ ÁN #${job_id}] Từ khóa: "${modResult.matched_summary}". Hành động: ${modResult.action}.`,
                metadata: { job_id, sender_id, raw_content: content, violations: modResult.violations }
            });

            if (modResult.action === 'BLOCK') {
                return res.status(400).json({
                    error: modResult.warning_message || 'Nội dung tin nhắn vi phạm quy tắc trao đổi dự án!',
                    is_moderated: true,
                    action: 'BLOCK',
                    violations: modResult.violations
                });
            }
        }

        const finalContent = (modResult.action === 'MASK') ? modResult.sanitized_content : content;

        const { data, error } = await supabase.from('messages').insert([{
            job_id, sender_id, milestone_id, content: finalContent, file_url, file_type
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
        // 0. Kiểm tra xem tài khoản người gửi có đang bị TẠM KHÓA 30 NGÀY do vi phạm 5 lần không
        const userStatus = chatModeration.getUserViolationStatus(sender_id);
        if (userStatus.is_locked) {
            const unlockDateStr = userStatus.locked_until ? new Date(userStatus.locked_until).toLocaleDateString('vi-VN') : '30 ngày';
            return res.status(403).json({
                success: false,
                code: 'ACCOUNT_LOCKED_30_DAYS',
                is_locked: true,
                locked_until: userStatus.locked_until,
                violation_count: userStatus.violation_count,
                error: `🚨 TÀI KHOẢN CỦA BẠN ĐANG BỊ TẠM KHÓA ĐẾN NGÀY ${unlockDateStr} do vi phạm chính sách kiểm duyệt 5 lần liên tiếp! Vui lòng liên hệ Admin.`
            });
        }

        // 0.1 Kiểm duyệt nội dung theo bộ quy tắc sàn (Anti-Bypass, Profanity & Gambling Filter)
        const modResult = chatModeration.moderateMessage(content);
        if (modResult.is_flagged) {
            // Ghi nhận lần vi phạm
            const strikeInfo = chatModeration.recordUserViolation(sender_id, {
                reason: modResult.matched_summary,
                violations: modResult.violations,
                raw_content: content
            });

            // Ghi log kiểm toán sự kiện vi phạm chính sách
            logEvent({
                module: 'CHAT',
                action: strikeInfo.is_locked ? 'USER_AUTO_BANNED_5_VIOLATIONS' : 'CHAT_POLICY_VIOLATION',
                user_id: sender_id,
                level: strikeInfo.is_locked ? 'CRITICAL' : 'SECURITY',
                details: `[VI PHẠM QUY TẮC CHAT] Lần ${strikeInfo.violation_count}/5. Từ khóa: "${modResult.matched_summary}". Hành động: ${modResult.action}.`,
                metadata: {
                    sender_id,
                    receiver_id,
                    raw_content: content,
                    violations: modResult.violations,
                    action_taken: modResult.action,
                    matched_summary: modResult.matched_summary,
                    violation_count: strikeInfo.violation_count,
                    is_locked: strikeInfo.is_locked
                }
            });

            if (strikeInfo.is_locked) {
                return res.status(403).json({
                    success: false,
                    is_moderated: true,
                    code: 'ACCOUNT_LOCKED_30_DAYS',
                    is_locked: true,
                    violation_count: strikeInfo.violation_count,
                    locked_until: strikeInfo.locked_until,
                    error: `🚨 TÀI KHOẢN ĐÃ BỊ TẠM KHÓA 30 NGÀY do bạn đã vi phạm chính sách kiểm duyệt 5 lần! Vui lòng liên hệ Quản trị viên để được hỗ trợ.`
                });
            }

            if (modResult.action === 'BLOCK') {
                return res.status(400).json({
                    success: false,
                    is_moderated: true,
                    code: 'POLICY_VIOLATION',
                    action: 'BLOCK',
                    violation_count: strikeInfo.violation_count,
                    max_violations: strikeInfo.max_violations,
                    strikes_remaining: strikeInfo.strikes_remaining,
                    warning_banner: `⚠️ CẢNH BÁO VI PHẠM (Lần ${strikeInfo.violation_count}/5): Bạn còn ${strikeInfo.strikes_remaining} lần trước khi tài khoản bị KHÓA 30 NGÀY!`,
                    error: modResult.warning_message || 'Nội dung tin nhắn vi phạm chính sách trao đổi của nền tảng!',
                    violations: modResult.violations,
                    matched_summary: modResult.matched_summary
                });
            }
        }

        // 0.2 Kiểm duyệt tệp đính kèm & hình ảnh (File & Media Moderation)
        if (file_name || file_url) {
            const mediaMod = chatModeration.moderateMediaFile({
                file_name,
                file_url,
                file_type,
                caption: content
            });

            if (mediaMod.is_flagged) {
                const strikeInfo = chatModeration.recordUserViolation(sender_id, {
                    reason: mediaMod.matched_summary,
                    violations: mediaMod.violations,
                    raw_content: file_name
                });

                logEvent({
                    module: 'CHAT',
                    action: strikeInfo.is_locked ? 'USER_AUTO_BANNED_5_VIOLATIONS' : 'MEDIA_POLICY_VIOLATION',
                    user_id: sender_id,
                    level: strikeInfo.is_locked ? 'CRITICAL' : 'SECURITY',
                    details: `[VI PHẠM TỆP TIN / HÌNH ẢNH] Lần ${strikeInfo.violation_count}/5. File: "${file_name}". Lý do: ${mediaMod.matched_summary}`,
                    metadata: {
                        sender_id,
                        receiver_id,
                        file_name,
                        file_url,
                        file_type,
                        violations: mediaMod.violations,
                        action_taken: mediaMod.action,
                        violation_count: strikeInfo.violation_count,
                        is_locked: strikeInfo.is_locked
                    }
                });

                if (strikeInfo.is_locked) {
                    return res.status(403).json({
                        success: false,
                        is_moderated: true,
                        code: 'ACCOUNT_LOCKED_30_DAYS',
                        is_locked: true,
                        violation_count: strikeInfo.violation_count,
                        locked_until: strikeInfo.locked_until,
                        error: `🚨 TÀI KHOẢN ĐÃ BỊ TẠM KHÓA 30 NGÀY do bạn đã gửi tệp vi phạm chính sách 5 lần!`
                    });
                }

                if (mediaMod.action === 'BLOCK') {
                    return res.status(400).json({
                        success: false,
                        is_moderated: true,
                        code: 'MEDIA_POLICY_VIOLATION',
                        action: 'BLOCK',
                        violation_count: strikeInfo.violation_count,
                        max_violations: strikeInfo.max_violations,
                        strikes_remaining: strikeInfo.strikes_remaining,
                        warning_banner: `⚠️ CẢNH BÁO VI PHẠM (Lần ${strikeInfo.violation_count}/5): Bạn còn ${strikeInfo.strikes_remaining} lần trước khi tài khoản bị KHÓA 30 NGÀY!`,
                        error: mediaMod.warning_message || 'Tệp tin hoặc hình ảnh vi phạm tiêu chuẩn an toàn nội dung của HT Work!',
                        violations: mediaMod.violations,
                        matched_summary: mediaMod.matched_summary
                    });
                }
            }
        }

        const finalContent = (modResult.action === 'MASK') ? modResult.sanitized_content : (content || '');

        const msg = await directMessageStore.sendDirectMessage({
            sender_id,
            receiver_id,
            content: finalContent,
            file_url,
            file_name,
            file_type
        });

        // Lấy thông tin email & tên để ghi log điều tra rõ ràng
        let senderEmail = null;
        let senderName = sender_id;
        let receiverName = receiver_id;
        try {
            const { data: users } = await supabase.from('users').select('id, full_name, email').in('id', [sender_id, receiver_id]);
            if (users) {
                const s = users.find(u => String(u.id) === String(sender_id));
                const r = users.find(u => String(u.id) === String(receiver_id));
                if (s) { senderEmail = s.email; senderName = s.full_name || s.email; }
                if (r) { receiverName = r.full_name || r.email; }
            }
        } catch (e) {}

        const detailsText = file_name 
            ? `[CHAT 1-1] [${senderName} ➔ ${receiverName}]: "${finalContent}" | 📎 Tệp đính kèm: "${file_name}" (${file_url})`
            : `[CHAT 1-1] [${senderName} ➔ ${receiverName}]: "${finalContent}"`;

        logEvent({
            module: 'CHAT',
            action: 'SEND_DIRECT_MESSAGE',
            user_id: sender_id,
            user_email: senderEmail,
            actor_id: sender_id,
            target_id: receiver_id,
            level: 'INFO',
            details: detailsText,
            metadata: {
                message_id: msg.id,
                sender_id,
                sender_name: senderName,
                sender_email: senderEmail,
                receiver_id,
                receiver_name: receiverName,
                content: msg.content,
                file_url: msg.file_url,
                file_name: msg.file_name,
                file_type: msg.file_type,
                created_at: msg.created_at,
                is_moderated: modResult.is_flagged
            }
        });

        res.status(201).json({ 
            success: true, 
            message: msg,
            is_moderated: modResult.is_flagged,
            moderation_warning: modResult.is_flagged ? modResult.warning_message : null
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Đánh dấu đã đọc tin nhắn trong cuộc hội thoại
router.post('/api/messages/mark-read', async (req, res) => {
    const { user_id, partner_id } = req.body;
    try {
        const result = await directMessageStore.markMessagesAsRead(user_id, partner_id);
        res.status(200).json({ success: true, ...result });
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

// Chỉnh sửa tin nhắn 1-1
router.post('/api/messages/direct/edit', async (req, res) => {
    const { message_id, user_id, new_content } = req.body;
    try {
        // Kiểm duyệt nội dung chỉnh sửa
        const modResult = chatModeration.moderateMessage(new_content);
        if (modResult.is_flagged && modResult.action === 'BLOCK') {
            return res.status(400).json({
                success: false,
                is_moderated: true,
                action: 'BLOCK',
                error: modResult.warning_message || 'Nội dung chỉnh sửa vi phạm quy tắc sàn!',
                violations: modResult.violations
            });
        }

        const finalContent = (modResult.action === 'MASK') ? modResult.sanitized_content : new_content;
        const updatedMsg = await directMessageStore.editDirectMessage({ message_id, user_id, new_content: finalContent });

        let userEmail = null;
        try {
            const { data: u } = await supabase.from('users').select('email, full_name').eq('id', user_id).single();
            if (u) userEmail = u.email;
        } catch(e){}

        logEvent({
            module: 'CHAT',
            action: 'EDIT_DIRECT_MESSAGE',
            user_id: user_id,
            user_email: userEmail,
            actor_id: user_id,
            level: 'INFO',
            details: `[SỬA TIN NHẮN #${message_id}]: "${finalContent}"`,
            metadata: { 
                message_id, 
                user_id, 
                user_email: userEmail,
                new_content: finalContent,
                edited_at: updatedMsg.edited_at
            }
        });

        res.status(200).json({ success: true, message: updatedMsg });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Thu hồi tin nhắn 1-1 (chuẩn Zalo)
router.post('/api/messages/direct/recall', async (req, res) => {
    const { message_id, user_id } = req.body;
    try {
        const recalledMsg = await directMessageStore.recallDirectMessage({ message_id, user_id });

        res.status(200).json({ success: true, message: recalledMsg });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Thả cảm xúc / reaction (thả tim, like, haha...) vào tin nhắn 1-1
router.post('/api/messages/direct/react', async (req, res) => {
    const { message_id, user_id, emoji } = req.body;
    try {
        const updatedMsg = await directMessageStore.reactToDirectMessage({ message_id, user_id, emoji });

        let userEmail = null;
        try {
            const { data: u } = await supabase.from('users').select('email, full_name').eq('id', user_id).single();
            if (u) userEmail = u.email;
        } catch(e){}

        logEvent({
            module: 'CHAT',
            action: 'REACT_DIRECT_MESSAGE',
            user_id: user_id,
            user_email: userEmail,
            actor_id: user_id,
            level: 'INFO',
            details: `[CẢM XÚC TIN NHẮN] Thả emoji "${emoji}" vào tin nhắn #${message_id}`,
            metadata: { 
                message_id, 
                user_id, 
                user_email: userEmail,
                emoji,
                reactions: updatedMsg.reactions
            }
        });

        res.status(200).json({ success: true, message: updatedMsg, reactions: updatedMsg.reactions });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// ==========================================
// 3. QUẢN TRỊ BỘ QUY TẮC KIỂM DUYỆT CHAT (ADMIN CHAT RULES)
// ==========================================

// Lấy toàn bộ cấu hình quy tắc
router.get('/api/admin/chat-rules', (req, res) => {
    try {
        const config = chatModeration.getModerationConfig();
        res.status(200).json({ success: true, config });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Cập nhật cấu hình chung (is_enabled, default_action, mask_character)
router.post('/api/admin/chat-rules', (req, res) => {
    try {
        const updated = chatModeration.updateModerationConfig(req.body);
        logEvent({
            module: 'ADMIN',
            action: 'UPDATE_CHAT_RULES',
            level: 'INFO',
            details: `Cập nhật cấu hình bộ quy tắc kiểm duyệt chat (Trạng thái: ${updated.is_enabled ? 'BẬT' : 'TẮT'}, Chế độ: ${updated.default_action})`,
            metadata: req.body
        });
        res.status(200).json({ success: true, config: updated });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Thêm từ khóa vào danh mục
router.post('/api/admin/chat-rules/keyword', (req, res) => {
    const { category_id, keyword } = req.body;
    try {
        const updated = chatModeration.addKeywordToCategory(category_id, keyword);
        if (!updated) return res.status(400).json({ success: false, error: 'Danh mục hoặc từ khóa không hợp lệ' });
        
        logEvent({
            module: 'ADMIN',
            action: 'ADD_CHAT_KEYWORD',
            level: 'INFO',
            details: `Thêm từ khóa cấm "${keyword}" vào danh mục [${category_id}]`,
            metadata: { category_id, keyword }
        });
        res.status(200).json({ success: true, config: updated });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Xóa từ khóa khỏi danh mục
router.delete('/api/admin/chat-rules/keyword', (req, res) => {
    const category_id = (req.body && req.body.category_id) || req.query.category_id;
    const keyword = (req.body && req.body.keyword) || req.query.keyword;
    try {
        const updated = chatModeration.removeKeywordFromCategory(category_id, keyword);
        if (!updated) return res.status(400).json({ success: false, error: 'Danh mục hoặc từ khóa không hợp lệ' });

        logEvent({
            module: 'ADMIN',
            action: 'REMOVE_CHAT_KEYWORD',
            level: 'INFO',
            details: `Xóa từ khóa cấm "${keyword}" khỏi danh mục [${category_id}]`,
            metadata: { category_id, keyword }
        });
        res.status(200).json({ success: true, config: updated });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Thêm mục danh sách trắng (whitelist)
router.post('/api/admin/chat-rules/whitelist', (req, res) => {
    const { item } = req.body || {};
    try {
        const updated = chatModeration.addWhitelistItem(item);
        res.status(200).json({ success: true, config: updated });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Xóa mục danh sách trắng
router.delete('/api/admin/chat-rules/whitelist', (req, res) => {
    const item = (req.body && req.body.item) || req.query.item;
    try {
        const updated = chatModeration.removeWhitelistItem(item);
        res.status(200).json({ success: true, config: updated });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Thử nghiệm kiểm duyệt nội dung trực tiếp (Live Tester)
router.post('/api/admin/chat-rules/test', (req, res) => {
    const { content } = req.body;
    try {
        const result = chatModeration.moderateMessage(content);
        res.status(200).json({ success: true, result });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Lấy danh sách tệp tin & hình ảnh trong chat để Admin kiểm duyệt
router.get('/api/admin/chat-media', async (req, res) => {
    try {
        const mediaList = await directMessageStore.getRecentMediaMessages(100);
        
        // Enrich với thông tin tên người gửi/nhận
        const userIds = new Set();
        mediaList.forEach(m => {
            if (m.sender_id) userIds.add(m.sender_id);
            if (m.receiver_id) userIds.add(m.receiver_id);
        });

        let userMap = {};
        if (userIds.size > 0) {
            try {
                const { data: users } = await supabase.from('users').select('id, full_name, email, avatar_url').in('id', Array.from(userIds));
                if (users) {
                    users.forEach(u => userMap[String(u.id)] = u);
                }
            } catch (e) {}
        }

        const enriched = mediaList.map(m => {
            const sUser = userMap[String(m.sender_id)] || {};
            const rUser = userMap[String(m.receiver_id)] || {};
            
            // Check nếu file có dấu hiệu vi phạm
            const check = chatModeration.moderateMediaFile({
                file_name: m.file_name,
                file_url: m.file_url,
                file_type: m.file_type,
                caption: m.content
            });

            return {
                ...m,
                sender_name: sUser.full_name || sUser.email || m.sender_id,
                sender_email: sUser.email || '',
                receiver_name: rUser.full_name || rUser.email || m.receiver_id,
                receiver_email: rUser.email || '',
                is_flagged: check.is_flagged,
                violation_details: check.is_flagged ? check.matched_summary : null
            };
        });

        res.status(200).json({ success: true, media: enriched });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Xóa/Cách ly tệp tin hoặc hình ảnh nhạy cảm bởi Admin
router.delete('/api/admin/chat-media/:message_id', async (req, res) => {
    const { message_id } = req.params;
    try {
        const ok = await directMessageStore.deleteMediaMessage(message_id);
        if (!ok) return res.status(404).json({ success: false, error: 'Không tìm thấy tệp tin cần xóa' });

        logEvent({
            module: 'ADMIN',
            action: 'DELETE_CHAT_MEDIA',
            level: 'WARNING',
            details: `Admin đã cách ly & xóa tệp tin vi phạm trong tin nhắn #${message_id}`,
            metadata: { message_id }
        });

        res.status(200).json({ success: true, message: 'Đã xóa và cách ly tệp tin thành công' });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Lấy trạng thái vi phạm và cảnh báo của người dùng (User Violation Status)
router.get('/api/messages/violation-status/:userId', (req, res) => {
    const { userId } = req.params;
    try {
        const status = chatModeration.getUserViolationStatus(userId);
        res.status(200).json({ success: true, ...status });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Admin lấy danh sách vi phạm của tất cả người dùng
router.get('/api/admin/violations', (req, res) => {
    try {
        const violations = chatModeration.getAllViolations();
        res.status(200).json({ success: true, violations });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Admin reset/mở khóa vi phạm cho người dùng
router.post('/api/admin/violations/reset', (req, res) => {
    const { user_id } = req.body;
    try {
        const ok = chatModeration.resetUserViolations(user_id);
        logEvent({
            module: 'ADMIN',
            action: 'RESET_USER_VIOLATIONS',
            level: 'INFO',
            details: `Admin đã reset số lần vi phạm & mở khóa tài khoản #${user_id}`,
            metadata: { user_id }
        });
        res.status(200).json({ success: true, message: 'Đã mở khóa và xóa điểm vi phạm thành công' });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

module.exports = router;


