const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

const DATA_DIR = path.join(__dirname, '..', 'node_modules', '.cache', 'htwork_data');
const CONNECTIONS_FILE = path.join(DATA_DIR, 'connections.json');
const LEGACY_FILE = path.join(__dirname, '..', 'data', 'connections.json');

if (!fs.existsSync(DATA_DIR)) {
    try { 
        fs.mkdirSync(DATA_DIR, { recursive: true }); 
        if (fs.existsSync(LEGACY_FILE)) {
            fs.copyFileSync(LEGACY_FILE, CONNECTIONS_FILE);
        }
    } catch (e) {}
}

function readLocalConnections() {
    try {
        if (fs.existsSync(CONNECTIONS_FILE)) {
            const raw = fs.readFileSync(CONNECTIONS_FILE, 'utf8');
            return JSON.parse(raw);
        } else if (fs.existsSync(LEGACY_FILE)) {
            const raw = fs.readFileSync(LEGACY_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Lỗi đọc connections.json:', e.message);
    }
    return [];
}

function saveLocalConnections(connections) {
    try {
        fs.writeFileSync(CONNECTIONS_FILE, JSON.stringify(connections, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu connections.json:', e.message);
    }
}

// Chuẩn hóa cặp User ID để luôn có user_id_1 < user_id_2
function getNormalizedPair(uidA, uidB) {
    return uidA < uidB ? [uidA, uidB] : [uidB, uidA];
}

/**
 * Gửi yêu cầu kết bạn
 */
async function sendConnectionRequest(sender_id, receiver_id, note = '') {
    if (!sender_id || !receiver_id || sender_id === receiver_id) {
        throw new Error('ID người dùng không hợp lệ');
    }

    const [u1, u2] = getNormalizedPair(sender_id, receiver_id);
    const local = readLocalConnections();

    // Kiểm tra xem đã có quan hệ kết bạn chưa
    let existing = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);

    if (existing) {
        if (existing.status === 'accepted') {
            return { alreadyFriends: true, connection: existing, message: 'Hai bạn đã là bạn bè/mối ruột của nhau!' };
        }
        if (existing.status === 'pending') {
            if (existing.sender_id === sender_id) {
                return { pending: true, connection: existing, message: 'Lời mời kết bạn đang chờ đối phương phản hồi.' };
            } else {
                // Người kia đã gửi trước đó -> Tự động chấp nhận luôn
                existing.status = 'accepted';
                existing.updated_at = new Date().toISOString();
                saveLocalConnections(local);
                return { acceptedNow: true, connection: existing, message: 'Đã chấp nhận kết bạn thành công!' };
            }
        }
        // Nếu trước đó rejected -> Reset lại thành pending
        existing.status = 'pending';
        existing.sender_id = sender_id;
        existing.note = note || '';
        existing.updated_at = new Date().toISOString();
        saveLocalConnections(local);
        return { connection: existing, message: 'Đã gửi lại lời mời kết bạn thành công!' };
    }

    const newConnection = {
        id: `conn_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
        user_id_1: u1,
        user_id_2: u2,
        sender_id: sender_id,
        receiver_id: receiver_id,
        status: 'pending',
        note: note || '',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };

    local.unshift(newConnection);
    saveLocalConnections(local);

    // Đồng bộ Supabase nếu có bảng
    try {
        await supabase.from('friendships').upsert([{
            id: newConnection.id,
            user_id_1: u1,
            user_id_2: u2,
            sender_id: sender_id,
            status: 'pending',
            note: note
        }]);
    } catch (e) {}

    return { connection: newConnection, message: 'Đã gửi lời mời kết bạn thành công!' };
}

/**
 * Phản hồi yêu cầu kết bạn (Chấp nhận / Từ chối / Hủy kết bạn)
 */
async function respondConnectionRequest(user_id, target_user_id, action) {
    if (!['accept', 'reject', 'unfriend'].includes(action)) {
        throw new Error('Hành động không hợp lệ');
    }

    const [u1, u2] = getNormalizedPair(user_id, target_user_id);
    const local = readLocalConnections();
    const index = local.findIndex(c => c.user_id_1 === u1 && c.user_id_2 === u2);

    if (index === -1) {
        throw new Error('Không tìm thấy quan hệ kết bạn');
    }

    const conn = local[index];

    if (action === 'accept') {
        conn.status = 'accepted';
        conn.updated_at = new Date().toISOString();
    } else if (action === 'reject') {
        conn.status = 'rejected';
        conn.updated_at = new Date().toISOString();
    } else if (action === 'unfriend') {
        local.splice(index, 1);
    }

    saveLocalConnections(local);

    try {
        if (action === 'unfriend') {
            await supabase.from('friendships').delete().match({ user_id_1: u1, user_id_2: u2 });
        } else {
            await supabase.from('friendships').update({ status: conn.status }).match({ user_id_1: u1, user_id_2: u2 });
        }
    } catch (e) {}

    return { success: true, status: conn ? conn.status : 'none' };
}

/**
 * Lấy trạng thái kết bạn giữa 2 user
 */
function getConnectionStatus(uidA, uidB) {
    if (!uidA || !uidB || uidA === uidB) return { status: 'self' };
    const [u1, u2] = getNormalizedPair(uidA, uidB);
    const local = readLocalConnections();
    const conn = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);

    if (!conn) return { status: 'none' };
    return {
        status: conn.status, // 'pending', 'accepted', 'rejected'
        isSender: conn.sender_id === uidA,
        connection: conn
    };
}

/**
 * Kiểm tra xem 2 user đã là Bạn Bè / Mối Ruột (accepted) hay chưa
 */
function isFriend(uidA, uidB) {
    if (!uidA || !uidB || uidA === uidB) return false;
    const [u1, u2] = getNormalizedPair(uidA, uidB);
    const local = readLocalConnections();
    const conn = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);
    return conn && conn.status === 'accepted';
}

/**
 * Lấy danh sách bạn bè và lời mời của một người dùng
 */
async function getUserNetwork(user_id, search = '') {
    const local = readLocalConnections();
    const myConns = local.filter(c => (c.user_id_1 === user_id || c.user_id_2 === user_id));

    // Lấy thông tin user từ Supabase
    const otherUserIds = myConns.map(c => c.user_id_1 === user_id ? c.user_id_2 : c.user_id_1);
    
    let usersMap = {};
    if (otherUserIds.length > 0) {
        try {
            const { data: users } = await supabase
                .from('users')
                .select('id, full_name, email, role, avatar_url, kyc_status, phone_number')
                .in('id', otherUserIds);

            if (users) {
                users.forEach(u => usersMap[u.id] = u);
            }
        } catch (e) {}
    }

    const friends = [];
    const pendingSent = [];
    const pendingReceived = [];

    myConns.forEach(c => {
        const partnerId = c.user_id_1 === user_id ? c.user_id_2 : c.user_id_1;
        const partner = usersMap[partnerId] || { id: partnerId, full_name: 'Người dùng', email: '' };

        const item = {
            connection_id: c.id,
            partner_id: partnerId,
            partner: partner,
            status: c.status,
            sender_id: c.sender_id,
            created_at: c.created_at,
            updated_at: c.updated_at,
            note: c.note
        };

        if (c.status === 'accepted') {
            friends.push(item);
        } else if (c.status === 'pending') {
            if (c.sender_id === user_id) {
                pendingSent.push(item);
            } else {
                pendingReceived.push(item);
            }
        }
    });

    // Filter search nếu có
    const s = (search || '').toLowerCase().trim();
    const filterFn = (item) => {
        if (!s) return true;
        const p = item.partner;
        return (p.full_name || '').toLowerCase().includes(s) ||
               (p.email || '').toLowerCase().includes(s) ||
               (p.role || '').toLowerCase().includes(s);
    };

    return {
        friends: friends.filter(filterFn),
        pending_sent: pendingSent.filter(filterFn),
        pending_received: pendingReceived.filter(filterFn),
        total_friends: friends.length,
        total_pending_received: pendingReceived.length
    };
}

module.exports = {
    sendConnectionRequest,
    respondConnectionRequest,
    getConnectionStatus,
    isFriend,
    getUserNetwork
};
