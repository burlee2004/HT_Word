const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

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
        (m.sender_id === userA && m.receiver_id === userB) ||
        (m.sender_id === userB && m.receiver_id === userA)
    );

    thread.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    if (search && search.trim()) {
        const s = search.trim().toLowerCase();
        thread = thread.filter(m => (m.content || '').toLowerCase().includes(s) || (m.file_name || '').toLowerCase().includes(s));
    }

    // Đánh dấu đã đọc cho tin nhắn gửi đến userA
    let updated = false;
    thread.forEach(m => {
        if (m.receiver_id === userA && !m.is_read) {
            m.is_read = true;
            updated = true;
        }
    });
    if (updated) {
        saveLocalMessages(all);
    }

    return thread;
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
                unread_count: 0
            };
        } else {
            if (new Date(m.created_at) > new Date(partnersMap[partnerId].last_message.created_at)) {
                partnersMap[partnerId].last_message = m;
            }
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
        return {
            partner_id: pid,
            partner: partner,
            last_message: partnersMap[pid].last_message,
            unread_count: partnersMap[pid].unread_count,
            last_activity: partnersMap[pid].last_message.created_at
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

module.exports = {
    sendDirectMessage,
    getDirectMessages,
    getConversationsList
};
