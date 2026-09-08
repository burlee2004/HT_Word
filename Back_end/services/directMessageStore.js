const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');
const connectionStore = require('./connectionStore');

const DATA_DIR = path.join(__dirname, '..', 'node_modules', '.cache', 'htwork_data');
const DM_FILE = path.join(DATA_DIR, 'direct_messages.json');
const LEGACY_DM_FILE = path.join(__dirname, '..', 'data', 'direct_messages.json');

if (!fs.existsSync(DATA_DIR)) {
    try { 
        fs.mkdirSync(DATA_DIR, { recursive: true }); 
        if (fs.existsSync(LEGACY_DM_FILE)) {
            fs.copyFileSync(LEGACY_DM_FILE, DM_FILE);
        }
    } catch (e) {}
}

function readLocalMessages() {
    try {
        if (fs.existsSync(DM_FILE)) {
            const raw = fs.readFileSync(DM_FILE, 'utf8');
            return JSON.parse(raw);
        } else if (fs.existsSync(LEGACY_DM_FILE)) {
            const raw = fs.readFileSync(LEGACY_DM_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Lỗi đọc direct_messages.json:', e.message);
    }
    return [];
}

function saveLocalMessages(messages) {
    try {
        fs.writeFileSync(DM_FILE, JSON.stringify(messages, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu direct_messages.json:', e.message);
    }
}

/**
 * Gửi tin nhắn trực tiếp 1-1
 */
async function sendDirectMessage(data) {
    const { sender_id, receiver_id, content, file_url, file_name, file_type } = data;

    if (!sender_id || !receiver_id) {
        throw new Error('Thiếu thông tin người gửi hoặc người nhận');
    }
    if (!content && !file_url) {
        throw new Error('Nội dung tin nhắn hoặc tệp đính kèm không được để trống');
    }

    const blockStatus = connectionStore.getBlockStatus(sender_id, receiver_id);
    if (blockStatus.is_blocked) {
        throw new Error('Không thể gửi tin nhắn (bạn đã chặn người này hoặc đã bị đối phương chặn).');
    }

    const newMsg = {
        id: `dm_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
        sender_id,
        receiver_id,
        content: content || '',
        file_url: file_url || null,
        file_name: file_name || null,
        file_type: file_type || 'text',
        is_read: false,
        created_at: new Date().toISOString()
    };

    const messages = readLocalMessages();
    messages.push(newMsg);
    saveLocalMessages(messages);

    // Đồng bộ Supabase nếu có bảng
    try {
        await supabase.from('direct_messages').insert([newMsg]);
    } catch (e) {}

    // Lấy thông tin sender để push notification
    try {
        const { data: sender } = await supabase.from('users').select('full_name, email').eq('id', sender_id).single();
        const senderName = sender ? sender.full_name : 'Một người dùng';
        
        await supabase.from('notifications').insert([{
            user_id: receiver_id,
            title: `💬 Tin nhắn từ ${senderName}`,
            content: content ? (content.length > 50 ? content.slice(0, 50) + '...' : content) : 'Đã gửi cho bạn một tệp đính kèm.'
        }]);
    } catch (e) {}

    return newMsg;
}

/**
 * Lấy toàn bộ lịch sử tin nhắn 1-1 giữa 2 người dùng (có hỗ trợ tìm kiếm từ khóa)
 */
async function getDirectMessages(userA, userB, search = '') {
    const all = readLocalMessages();
    let thread = all.filter(m => 
        (String(m.sender_id) === String(userA) && String(m.receiver_id) === String(userB)) ||
        (String(m.sender_id) === String(userB) && String(m.receiver_id) === String(userA))
    );

    thread.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    if (search && search.trim()) {
        const s = search.trim().toLowerCase();
        thread = thread.filter(m => (m.content || '').toLowerCase().includes(s) || (m.file_name || '').toLowerCase().includes(s));
    }

    // Đánh dấu đã đọc cho tin nhắn gửi đến userA
    let updated = false;
    thread.forEach(m => {
        if (String(m.receiver_id) === String(userA) && !m.is_read) {
            m.is_read = true;
            updated = true;
        }
    });
    if (updated) {
        saveLocalMessages(all);
    }

    // Trích xuất các ID hoặc tiêu đề dự án xuất hiện trong tin nhắn hợp đồng
    const jobIds = [];
    const jobTitles = [];

    thread.forEach(m => {
        const idMatch = (m.content || '').match(/(?:Mã dự án:\s*#?|ID:\s*#?)([a-zA-Z0-9\-_]+)/i);
        if (idMatch) {
            jobIds.push(idMatch[1]);
        } else {
            const titleMatch = (m.content || '').match(/dự án\s*["“]([^"”]+)["”]/i);
            if (titleMatch) {
                jobTitles.push(titleMatch[1].trim());
            }
        }
    });

    let jobsMap = {};
    if (jobIds.length > 0 || jobTitles.length > 0) {
        try {
            if (jobIds.length > 0) {
                const { data: jobsById } = await supabase
                    .from('jobs')
                    .select('id, title, status, budget, client_id')
                    .in('id', Array.from(new Set(jobIds)));
                if (jobsById) {
                    jobsById.forEach(j => {
                        jobsMap[j.id] = j;
                        if (j.title) jobsMap[j.title.trim()] = j;
                    });
                }
            }
            if (jobTitles.length > 0) {
                const { data: jobsByTitle } = await supabase
                    .from('jobs')
                    .select('id, title, status, budget, client_id')
                    .in('title', Array.from(new Set(jobTitles)));
                if (jobsByTitle) {
                    jobsByTitle.forEach(j => {
                        jobsMap[j.id] = j;
                        if (j.title) jobsMap[j.title.trim()] = j;
                    });
                }
            }

            const queriedJobIds = Array.from(new Set(Object.values(jobsMap).map(j => j.id)));
            if (queriedJobIds.length > 0) {
                const { data: apps } = await supabase
                    .from('job_applications')
                    .select('job_id, freelancer_id, status')
                    .in('job_id', queriedJobIds);
                if (apps) {
                    apps.forEach(app => {
                        if (jobsMap[app.job_id]) {
                            jobsMap[app.job_id].app_status = app.status;
                            if (app.status === 'revoked') {
                                jobsMap[app.job_id].is_revoked = true;
                            }
                        }
                    });
                }
            }
        } catch (e) {
            console.error('Lỗi truy vấn job status cho chat 1-1:', e.message);
        }
    }

    // Gắn thông tin job_status, job_budget & is_revoked vào tin nhắn
    const enrichedThread = thread.map(m => {
        const isDirectHire = m.content && (
            m.content.includes('[GIAO VIỆC TRỰC TIẾP]') || 
            m.content.includes('[ĐỀ XUẤT HỢP ĐỒNG]') || 
            m.content.includes('[CHỐT GIÁ & KHÓA ESCROW]') || 
            m.content.includes('[THU HỒI DỰ ÁN]') ||
            m.content.includes('[CẬP NHẬT GIÁ]')
        );
        if (!isDirectHire) return m;

        let matchedJob = null;
        const idMatch = m.content.match(/(?:Mã dự án:\s*#?|ID:\s*#?)([a-zA-Z0-9\-_]+)/i);
        if (idMatch && jobsMap[idMatch[1]]) {
            matchedJob = jobsMap[idMatch[1]];
        } else {
            const titleMatch = m.content.match(/dự án\s*["“]([^"”]+)["”]/i);
            if (titleMatch && jobsMap[titleMatch[1].trim()]) {
                matchedJob = jobsMap[titleMatch[1].trim()];
            }
        }

        if (matchedJob) {
            const isRevoked = matchedJob.status === 'cancelled' || matchedJob.status === 'revoked' || matchedJob.app_status === 'revoked' || matchedJob.is_revoked === true;
            return {
                ...m,
                job_id: matchedJob.id,
                job_title: matchedJob.title,
                job_status: matchedJob.status,
                job_budget: matchedJob.budget,
                app_status: matchedJob.app_status,
                is_revoked: isRevoked
            };
        }
        return m;
    });

    return enrichedThread;
}

/**
 * Đánh dấu đã đọc tất cả tin nhắn giữa 2 người dùng
 */
async function markMessagesAsRead(user_id, partner_id) {
    const all = readLocalMessages();
    let updated = false;
    all.forEach(m => {
        if (m.sender_id === partner_id && m.receiver_id === user_id && !m.is_read) {
            m.is_read = true;
            updated = true;
        }
    });
    if (updated) {
        saveLocalMessages(all);
    }
    return { success: true, updated };
}

/**
 * Lấy danh sách các cuộc hội thoại gần nhất của người dùng
 */
async function getConversationsList(user_id, search = '') {
    const all = readLocalMessages();
    const myMessages = all.filter(m => m.sender_id === user_id || m.receiver_id === user_id);

    // Gom nhóm theo đối tác (partner)
    const partnersMap = {};

    myMessages.forEach(m => {
        const partnerId = m.sender_id === user_id ? m.receiver_id : m.sender_id;
        if (!partnersMap[partnerId]) {
            partnersMap[partnerId] = {
                partner_id: partnerId,
                last_message: m,
                unread_count: 0,
                has_replied: false,
                sent_by_me_count: 0
            };
        } else {
            if (new Date(m.created_at) > new Date(partnersMap[partnerId].last_message.created_at)) {
                partnersMap[partnerId].last_message = m;
            }
        }

        if (m.sender_id === user_id) {
            partnersMap[partnerId].has_replied = true;
            partnersMap[partnerId].sent_by_me_count++;
        }

        if (m.receiver_id === user_id && !m.is_read) {
            partnersMap[partnerId].unread_count++;
        }
    });

    const partnerIds = Object.keys(partnersMap);
    if (partnerIds.length === 0) return [];

    // Lấy thông tin user từ Supabase
    let usersInfoMap = {};
    try {
        const { data: users } = await supabase
            .from('users')
            .select('id, full_name, email, role, avatar_url, kyc_status')
            .in('id', partnerIds);

        if (users) {
            users.forEach(u => usersInfoMap[u.id] = u);
        }
    } catch (e) {}

    let conversations = partnerIds.map(pid => {
        const partner = usersInfoMap[pid] || { id: pid, full_name: 'Người dùng', email: '', role: 'client' };
        const isFriend = connectionStore.isFriend(user_id, pid);
        const isFav = connectionStore.isFavorite(user_id, pid);
        const blockStatus = connectionStore.getBlockStatus(user_id, pid);
        const hasReplied = !!partnersMap[pid].has_replied;
        const isStranger = !isFriend && !hasReplied;

        return {
            partner_id: pid,
            partner: partner,
            last_message: partnersMap[pid].last_message,
            unread_count: partnersMap[pid].unread_count,
            last_activity: partnersMap[pid].last_message.created_at,
            is_friend: isFriend,
            is_favorite: isFav,
            is_blocked: blockStatus.is_blocked,
            blocked_by_me: blockStatus.blocked_by_me,
            blocked_by_partner: blockStatus.blocked_by_partner,
            has_replied: hasReplied,
            is_stranger: isStranger
        };
    });


    // Sắp xếp cuộc trò chuyện gần nhất lên đầu
    conversations.sort((a, b) => new Date(b.last_activity) - new Date(a.last_activity));

    if (search && search.trim()) {
        const s = search.trim().toLowerCase();
        conversations = conversations.filter(c => 
            (c.partner.full_name || '').toLowerCase().includes(s) ||
            (c.partner.email || '').toLowerCase().includes(s) ||
            (c.last_message.content || '').toLowerCase().includes(s)
        );
    }

    return conversations;
}

/**
 * Chỉnh sửa tin nhắn 1-1 (chỉ người gửi mới có quyền sửa)
 */
async function editDirectMessage({ message_id, user_id, new_content }) {
    if (!message_id || !user_id) {
        throw new Error('Thiếu thông tin message_id hoặc user_id');
    }
    if (!new_content || !new_content.trim()) {
        throw new Error('Nội dung chỉnh sửa không được để trống');
    }

    const messages = readLocalMessages();
    const msg = messages.find(m => m.id === message_id);
    if (!msg) {
        throw new Error('Tin nhắn không tồn tại');
    }
    if (msg.sender_id !== user_id) {
        throw new Error('Bạn không có quyền chỉnh sửa tin nhắn này');
    }
    if (msg.is_recalled) {
        throw new Error('Không thể chỉnh sửa tin nhắn đã bị thu hồi');
    }

    msg.content = new_content.trim();
    msg.is_edited = true;
    msg.edited_at = new Date().toISOString();

    saveLocalMessages(messages);

    // Đồng bộ Supabase nếu có
    try {
        await supabase
            .from('direct_messages')
            .update({ content: msg.content, is_edited: true, edited_at: msg.edited_at })
            .eq('id', message_id);
    } catch (e) {}

    return msg;
}

const AUDIT_RECALLED_FILE = path.join(DATA_DIR, 'recalled_messages_audit.json');

function saveRecalledMessageAudit(auditRecord) {
    try {
        let list = [];
        if (fs.existsSync(AUDIT_RECALLED_FILE)) {
            try {
                list = JSON.parse(fs.readFileSync(AUDIT_RECALLED_FILE, 'utf8'));
                if (!Array.isArray(list)) list = [];
            } catch (e) {
                list = [];
            }
        }
        list.unshift(auditRecord);
        if (list.length > 2000) list = list.slice(0, 2000);
        fs.writeFileSync(AUDIT_RECALLED_FILE, JSON.stringify(list, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu audit tin nhắn đã thu hồi:', e.message);
    }
}

/**
 * Thu hồi tin nhắn 1-1 (chuẩn Zalo: người gửi có quyền thu hồi cho cả 2 bên)
 * Lưu trữ nguyên vẹn dữ liệu gốc vào Audit Log để phục vụ đối soát, điều tra xét xử của Admin
 */
async function recallDirectMessage({ message_id, user_id }) {
    if (!message_id || !user_id) {
        throw new Error('Thiếu thông tin message_id hoặc user_id');
    }

    const messages = readLocalMessages();
    const msg = messages.find(m => String(m.id) === String(message_id));
    if (!msg) {
        throw new Error('Tin nhắn không tồn tại');
    }
    if (String(msg.sender_id) !== String(user_id)) {
        throw new Error('Bạn không có quyền thu hồi tin nhắn này');
    }
    if (msg.is_recalled) {
        return msg; // Đã thu hồi rồi
    }

    const recalledAt = new Date().toISOString();

    // 1. Sao lưu toàn diện bằng chứng nguyên gốc phục vụ điều tra xét xử của Admin
    const auditRecord = {
        audit_id: 'audit_recall_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
        message_id: msg.id,
        sender_id: msg.sender_id,
        receiver_id: msg.receiver_id,
        original_content: msg.content || '',
        original_file_url: msg.file_url || null,
        original_file_name: msg.file_name || null,
        original_file_type: msg.file_type || null,
        original_reactions: msg.reactions || {},
        original_created_at: msg.created_at,
        recalled_at: recalledAt,
        recalled_by: user_id,
        reason: 'Lưu trữ bằng chứng xét xử tranh chấp / điều tra admin'
    };

    saveRecalledMessageAudit(auditRecord);

    // 2. Ghi sự kiện Audit Log bảo mật vào hệ thống
    try {
        const { logEvent } = require('./auditLogger');
        logEvent({
            module: 'CHAT',
            action: 'RECALL_DIRECT_MESSAGE_AUDIT',
            level: 'SECURITY',
            user_id: user_id,
            details: `[LƯU BẰNG CHỨNG ĐIỀU TRA] Thu hồi tin nhắn #${msg.id}. Nội dung gốc: "${msg.content || ''}" | Tệp: "${msg.file_name || 'Không có'}" (${msg.file_url || 'N/A'})`,
            metadata: auditRecord
        });
    } catch (e) {
        console.error('Lỗi ghi audit log thu hồi tin nhắn:', e);
    }

    // 3. Đánh dấu đã thu hồi cho người dùng thông thường
    msg.is_recalled = true;
    msg.recalled_at = recalledAt;
    msg.file_url = null;
    msg.file_name = null;
    msg.file_type = null;
    msg.reactions = {};

    saveLocalMessages(messages);

    // Đồng bộ Supabase nếu có
    try {
        await supabase
            .from('direct_messages')
            .update({ 
                is_recalled: true, 
                recalled_at: msg.recalled_at, 
                file_url: null, 
                file_name: null,
                file_type: null,
                reactions: {}
            })
            .eq('id', message_id);
    } catch (e) {}

    return msg;
}

/**
 * Thả cảm xúc / reaction (thả tim, like, haha...) vào tin nhắn 1-1
 */
async function reactToDirectMessage({ message_id, user_id, emoji }) {
    if (!message_id || !user_id || !emoji) {
        throw new Error('Thiếu thông tin message_id, user_id hoặc emoji');
    }

    const messages = readLocalMessages();
    const msg = messages.find(m => String(m.id) === String(message_id));
    if (!msg) {
        throw new Error('Tin nhắn không tồn tại');
    }
    if (msg.is_recalled) {
        throw new Error('Không thể thả cảm xúc vào tin nhắn đã bị thu hồi');
    }

    if (!msg.reactions || typeof msg.reactions !== 'object' || Array.isArray(msg.reactions)) {
        msg.reactions = {};
    }

    // Khởi tạo mảng user_id cho emoji nếu chưa có
    if (!Array.isArray(msg.reactions[emoji])) {
        msg.reactions[emoji] = [];
    }

    const strUserId = String(user_id);
    const userIdx = msg.reactions[emoji].findIndex(uid => String(uid) === strUserId);
    if (userIdx > -1) {
        // Người dùng đã thả emoji này -> Hủy thả (toggle off)
        msg.reactions[emoji].splice(userIdx, 1);
        if (msg.reactions[emoji].length === 0) {
            delete msg.reactions[emoji];
        }
    } else {
        // Thêm reaction mới của user
        msg.reactions[emoji].push(user_id);
    }

    saveLocalMessages(messages);

    // Đồng bộ Supabase nếu có
    try {
        await supabase
            .from('direct_messages')
            .update({ reactions: msg.reactions })
            .eq('id', message_id);
    } catch (e) {}

    return msg;
}

/**
 * Lấy danh sách các tệp tin & hình ảnh gần nhất để Admin kiểm duyệt
 */
async function getRecentMediaMessages(limit = 100) {
    const messages = readLocalMessages();
    const mediaList = messages
        .filter(m => m.file_url || (m.content && (m.content.startsWith('http') || m.content.match(/\.(jpg|jpeg|png|gif|webp|pdf|docx?|zip|rar)/i))))
        .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
        .slice(0, limit);

    return mediaList;
}

/**
 * Xóa/Cách ly tệp tin độc hại theo message_id bởi Admin
 */
async function deleteMediaMessage(message_id) {
    const messages = readLocalMessages();
    const idx = messages.findIndex(m => String(m.id) === String(message_id));
    if (idx === -1) return false;

    // Thay thế file_url và content thành [Đã bị Admin cách ly do vi phạm]
    messages[idx].file_url = null;
    messages[idx].file_name = `[ĐÃ XÓA: ${messages[idx].file_name || 'Tệp tin'}]`;
    messages[idx].content = '🚫 [Tệp tin / Hình ảnh này đã bị Quản trị viên xóa do vi phạm quy tắc an toàn nội dung]';
    messages[idx].is_quarantined = true;

    saveLocalMessages(messages);
    return true;
}

module.exports = {
    sendDirectMessage,
    getDirectMessages,
    markMessagesAsRead,
    getConversationsList,
    editDirectMessage,
    recallDirectMessage,
    reactToDirectMessage,
    getRecentMediaMessages,
    deleteMediaMessage
};
