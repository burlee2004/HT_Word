const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CACHE_DIR = path.join(__dirname, '..', 'node_modules', '.cache', 'kgs work_data');
const TICKETS_FILE = path.join(DATA_DIR, 'support_tickets.json');
const CACHE_TICKETS_FILE = path.join(CACHE_DIR, 'support_tickets.json');

// Đảm bảo thư mục tồn tại
function ensureStorage() {
    try {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
        if (!fs.existsSync(TICKETS_FILE)) {
            if (fs.existsSync(CACHE_TICKETS_FILE)) {
                fs.copyFileSync(CACHE_TICKETS_FILE, TICKETS_FILE);
            } else {
                fs.writeFileSync(TICKETS_FILE, JSON.stringify([], null, 2), 'utf8');
            }
        }
    } catch (e) {
        console.error('[SupportStore] Lỗi khởi tạo thư mục lưu trữ:', e.message);
    }
}

ensureStorage();

// Đọc danh sách tickets
function getTickets() {
    try {
        if (fs.existsSync(TICKETS_FILE)) {
            const raw = fs.readFileSync(TICKETS_FILE, 'utf8');
            return JSON.parse(raw);
        } else if (fs.existsSync(CACHE_TICKETS_FILE)) {
            const raw = fs.readFileSync(CACHE_TICKETS_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('[SupportStore] Lỗi đọc support_tickets.json:', e.message);
    }
    return [];
}

// Lưu danh sách tickets
function saveTickets(tickets) {
    try {
        const jsonStr = JSON.stringify(tickets, null, 2);
        fs.writeFileSync(TICKETS_FILE, jsonStr, 'utf8');
        try { fs.writeFileSync(CACHE_TICKETS_FILE, jsonStr, 'utf8'); } catch (e) {}
        return true;
    } catch (e) {
        console.error('[SupportStore] Lỗi lưu support_tickets.json:', e.message);
        return false;
    }
}

// Tạo Ticket mới
function createTicket(data) {
    const tickets = getTickets();
    const timestamp = Date.now();
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const ticketCode = `#TK-${randomSuffix}`;

    const newTicket = {
        id: `ticket_${timestamp}_${randomSuffix}`,
        ticket_code: ticketCode,
        user_id: data.user_id,
        user_name: data.user_name || 'Người dùng',
        user_email: data.user_email || '',
        user_role: data.user_role || 'user',
        user_avatar: data.user_avatar || '',
        phone: data.phone || '',
        category: data.category || 'other',
        category_label: data.category_label || getCategoryLabel(data.category),
        priority: data.priority || 'medium', // low, medium, high, urgent
        subject: data.subject || 'Yêu cầu hỗ trợ',
        message: data.message || '',
        attachments: Array.isArray(data.attachments) ? data.attachments : [],
        status: 'pending', // pending, in_progress, resolved, closed
        admin_reply: '',
        admin_replied_at: null,
        admin_name: '',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };

    tickets.unshift(newTicket);
    saveTickets(tickets);
    return newTicket;
}

// Cập nhật Ticket (Admin trả lời hoặc đổi trạng thái)
function updateTicket(ticketId, updateFields) {
    const tickets = getTickets();
    const idx = tickets.findIndex(t => t.id === ticketId || t.ticket_code === ticketId);
    if (idx === -1) return null;

    tickets[idx] = {
        ...tickets[idx],
        ...updateFields,
        updated_at: new Date().toISOString()
    };

    saveTickets(tickets);
    return tickets[idx];
}

function getTicketById(ticketId) {
    const tickets = getTickets();
    return tickets.find(t => t.id === ticketId || t.ticket_code === ticketId) || null;
}

function getUserTickets(userId) {
    const tickets = getTickets();
    return tickets.filter(t => t.user_id === userId);
}

// Helper nhãn danh mục
function getCategoryLabel(catKey) {
    const map = {
        'payment': 'Thanh toán & Nạp/Rút Token',
        'job_dispute': 'Tranh chấp Hợp đồng & Tiến độ',
        'fraud_report': 'Báo cáo Gian lận / Lừa đảo',
        'tech_bug': 'Lỗi Kỹ thuật & Giao diện',
        'kyc_account': 'Tài khoản & Xác thực KYC / SĐT',
        'other': 'Yêu cầu hỗ trợ khác'
    };
    return map[catKey] || 'Hỗ trợ chung';
}

// ==========================================
// THEO DÕI TRẠNG THÁI ONLINE CỦA ADMIN (PRESENCE)
// ==========================================
let lastAdminHeartbeat = {
    admin_id: '11111111-1111-1111-1111-111111111111',
    admin_name: 'Quản Trị Viên KGS Work',
    timestamp: 0 // epoch ms
};

function recordAdminHeartbeat(adminInfo = {}) {
    lastAdminHeartbeat = {
        admin_id: adminInfo.admin_id || '11111111-1111-1111-1111-111111111111',
        admin_name: adminInfo.admin_name || 'Quản Trị Viên KGS Work',
        timestamp: Date.now()
    };
    return lastAdminHeartbeat;
}

function getAdminOnlineStatus() {
    const now = Date.now();
    // Coi là Online nếu có heartbeat trong vòng 150 giây (2.5 phút)
    const isOnline = (now - lastAdminHeartbeat.timestamp) < 150000;
    return {
        online: isOnline,
        admin_id: lastAdminHeartbeat.admin_id,
        admin_name: lastAdminHeartbeat.admin_name,
        last_active: lastAdminHeartbeat.timestamp ? new Date(lastAdminHeartbeat.timestamp).toISOString() : null
    };
}

module.exports = {
    getTickets,
    saveTickets,
    createTicket,
    updateTicket,
    getTicketById,
    getUserTickets,
    getCategoryLabel,
    recordAdminHeartbeat,
    getAdminOnlineStatus
};
