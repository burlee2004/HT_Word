const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

const DATA_DIR = path.join(__dirname, '..', 'node_modules', '.cache', 'htwork_data');
const CONNECTIONS_FILE = path.join(DATA_DIR, 'connections.json');
const FAVORITES_FILE = path.join(DATA_DIR, 'favorites.json');
const BLOCKS_FILE = path.join(DATA_DIR, 'blocks.json');
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

function readLocalFavorites() {
    try {
        if (fs.existsSync(FAVORITES_FILE)) {
            const raw = fs.readFileSync(FAVORITES_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Lỗi đọc favorites.json:', e.message);
    }
    return [];
}

function saveLocalFavorites(favorites) {
    try {
        fs.writeFileSync(FAVORITES_FILE, JSON.stringify(favorites, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu favorites.json:', e.message);
    }
}

function readLocalBlocks() {
    try {
        if (fs.existsSync(BLOCKS_FILE)) {
            const raw = fs.readFileSync(BLOCKS_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Lỗi đọc blocks.json:', e.message);
    }
    return [];
}

function saveLocalBlocks(blocks) {
    try {
        fs.writeFileSync(BLOCKS_FILE, JSON.stringify(blocks, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu blocks.json:', e.message);
    }
}

// Chuẩn hóa cặp User ID để luôn có user_id_1 < user_id_2
function getNormalizedPair(uidA, uidB) {
    return uidA < uidB ? [uidA, uidB] : [uidB, uidA];
}

/**
 * Kiểm tra trạng thái Chặn giữa 2 User
 */
function getBlockStatus(uidA, uidB) {
    if (!uidA || !uidB || uidA === uidB) {
        return { is_blocked: false, blocked_by_me: false, blocked_by_partner: false };
    }
    const blocks = readLocalBlocks();
    const blocked_by_me = blocks.some(b => b.user_id === uidA && b.blocked_id === uidB);
    const blocked_by_partner = blocks.some(b => b.user_id === uidB && b.blocked_id === uidA);
    return {
        is_blocked: blocked_by_me || blocked_by_partner,
        blocked_by_me,
        blocked_by_partner
    };
}

/**
 * Chặn người dùng (Block)
 */
async function blockUser(user_id, target_user_id) {
    if (!user_id || !target_user_id || user_id === target_user_id) {
        throw new Error('ID người dùng không hợp lệ để chặn');
    }

    const blocks = readLocalBlocks();
    const exists = blocks.some(b => b.user_id === user_id && b.blocked_id === target_user_id);
    if (!exists) {
        blocks.push({
            id: `blk_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
            user_id: user_id,
            blocked_id: target_user_id,
            created_at: new Date().toISOString()
        });
        saveLocalBlocks(blocks);
    }

    // Tự động hủy kết bạn / lời mời nếu có
    const [u1, u2] = getNormalizedPair(user_id, target_user_id);
    const localConns = readLocalConnections();
    const cIdx = localConns.findIndex(c => c.user_id_1 === u1 && c.user_id_2 === u2);
    if (cIdx !== -1) {
        localConns.splice(cIdx, 1);
        saveLocalConnections(localConns);
        try {
            await supabase.from('friendships').delete().match({ user_id_1: u1, user_id_2: u2 });
        } catch (e) {}
    }

    // Tự động xóa khỏi danh sách Mối Ruột của cả 2
    const favs = readLocalFavorites();
    const filteredFavs = favs.filter(f => 
        !(f.user_id === user_id && f.favorite_id === target_user_id) &&
        !(f.user_id === target_user_id && f.favorite_id === user_id)
    );
    if (filteredFavs.length !== favs.length) {
        saveLocalFavorites(filteredFavs);
    }

    return { success: true, message: 'Đã chặn người dùng thành công' };
}

/**
 * Bỏ chặn người dùng (Unblock)
 */
async function unblockUser(user_id, target_user_id) {
    if (!user_id || !target_user_id) {
        throw new Error('ID người dùng không hợp lệ');
    }

    const blocks = readLocalBlocks();
    const newBlocks = blocks.filter(b => !(b.user_id === user_id && b.blocked_id === target_user_id));
    saveLocalBlocks(newBlocks);

    return { success: true, message: 'Đã bỏ chặn người dùng thành công' };
}

/**
 * Kiểm tra xem target_user_id có phải là Mối Ruột (favorite) của user_id không
 */
function isFavorite(user_id, target_user_id) {
    if (!user_id || !target_user_id) return false;
    if (!isFriend(user_id, target_user_id)) return false;
    const favs = readLocalFavorites();
    return favs.some(f => f.user_id === user_id && f.favorite_id === target_user_id);
}

/**
 * Thả Tim / Bỏ Tim Mối Ruột (Toggle Favorite)
 */
async function toggleFavorite(user_id, target_user_id) {
    if (!user_id || !target_user_id || user_id === target_user_id) {
        throw new Error('ID người dùng không hợp lệ');
    }

    // Phải là Bạn Bè (accepted) mới được thả tim Mối Ruột
    if (!isFriend(user_id, target_user_id)) {
        throw new Error('Chỉ có thể thêm vào danh sách Mối Ruột khi hai bên đã là bạn bè!');
    }

    const favs = readLocalFavorites();
    const index = favs.findIndex(f => f.user_id === user_id && f.favorite_id === target_user_id);

    let isFav = false;
    let message = '';

    if (index !== -1) {
        // Đã là mối ruột -> Bỏ tim
        favs.splice(index, 1);
        saveLocalFavorites(favs);
        isFav = false;
        message = 'Đã bỏ khỏi danh sách Mối Ruột';
    } else {
        // Thêm vào mối ruột
        favs.push({
            id: `fav_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
            user_id: user_id,
            favorite_id: target_user_id,
            created_at: new Date().toISOString()
        });
        saveLocalFavorites(favs);
        isFav = true;
        message = 'Đã thêm vào danh sách Mối Ruột ❤️';
    }

    return { success: true, is_favorite: isFav, message };
}

/**
 * Hủy kết bạn (Unfriend)
 */
async function unfriend(user_id, target_user_id) {
    const result = await respondConnectionRequest(user_id, target_user_id, 'unfriend');
    
    // Xóa khỏi danh sách Mối Ruột của cả 2 bên
    const favs = readLocalFavorites();
    const filteredFavs = favs.filter(f => 
        !(f.user_id === user_id && f.favorite_id === target_user_id) &&
        !(f.user_id === target_user_id && f.favorite_id === user_id)
    );
    if (filteredFavs.length !== favs.length) {
        saveLocalFavorites(filteredFavs);
    }

    return { success: true, message: 'Đã hủy kết bạn thành công' };
}

/**
 * Gửi yêu cầu kết bạn
 */
async function sendConnectionRequest(sender_id, receiver_id, note = '') {
    if (!sender_id || !receiver_id || sender_id === receiver_id) {
        throw new Error('ID người dùng không hợp lệ');
    }

    const blockStatus = getBlockStatus(sender_id, receiver_id);
    if (blockStatus.is_blocked) {
        throw new Error('Không thể gửi lời mời kết bạn (người dùng đã bị chặn hoặc bạn đã chặn người này)');
    }

    const [u1, u2] = getNormalizedPair(sender_id, receiver_id);
    const local = readLocalConnections();

    // Kiểm tra xem đã có quan hệ kết bạn chưa
    let existing = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);

    if (existing) {
        if (existing.status === 'accepted') {
            return { alreadyFriends: true, connection: existing, message: 'Hai bạn đã là bạn bè của nhau!' };
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
        if (action === 'unfriend') {
            return { success: true, status: 'none' };
        }
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
        // Đồng thời xóa khỏi danh sách Mối Ruột
        const favs = readLocalFavorites();
        const filteredFavs = favs.filter(f => 
            !(f.user_id === user_id && f.favorite_id === target_user_id) &&
            !(f.user_id === target_user_id && f.favorite_id === user_id)
        );
        if (filteredFavs.length !== favs.length) {
            saveLocalFavorites(filteredFavs);
        }
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
    if (!uidA || !uidB || uidA === uidB) return { status: 'self', is_friend: false, is_favorite: false, is_blocked: false };
    const [u1, u2] = getNormalizedPair(uidA, uidB);
    const local = readLocalConnections();
    const conn = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);
    const blockStatus = getBlockStatus(uidA, uidB);
    const is_fav = isFavorite(uidA, uidB);

    if (!conn) {
        return { 
            status: 'none', 
            is_friend: false,
            is_favorite: false,
            ...blockStatus
        };
    }

    return {
        status: conn.status, // 'pending', 'accepted', 'rejected'
        isSender: conn.sender_id === uidA,
        is_friend: conn.status === 'accepted',
        is_favorite: is_fav,
        connection: conn,
        ...blockStatus
    };
}

/**
 * Kiểm tra xem 2 user đã là Bạn Bè (accepted) hay chưa
 */
function isFriend(uidA, uidB) {
    if (!uidA || !uidB || uidA === uidB) return false;
    const [u1, u2] = getNormalizedPair(uidA, uidB);
    const local = readLocalConnections();
    const conn = local.find(c => c.user_id_1 === u1 && c.user_id_2 === u2);
    return conn && conn.status === 'accepted';
}

/**
 * Lấy danh sách bạn bè, mối ruột và lời mời của một người dùng
 */
async function getUserNetwork(user_id, search = '') {
    const local = readLocalConnections();
    const myConns = local.filter(c => (c.user_id_1 === user_id || c.user_id_2 === user_id));
    const blocks = readLocalBlocks();
    const myBlockedIds = blocks.filter(b => b.user_id === user_id).map(b => b.blocked_id);

    // Lấy thông tin user từ Supabase
    const otherUserIds = Array.from(new Set([
        ...myConns.map(c => c.user_id_1 === user_id ? c.user_id_2 : c.user_id_1),
        ...myBlockedIds
    ]));
    
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
    const favorites = [];
    const pendingSent = [];
    const pendingReceived = [];
    const blockedUsers = [];

    myConns.forEach(c => {
        const partnerId = c.user_id_1 === user_id ? c.user_id_2 : c.user_id_1;
        const partner = usersMap[partnerId] || { id: partnerId, full_name: 'Người dùng', email: '' };
        const isFav = isFavorite(user_id, partnerId);

        const item = {
            connection_id: c.id,
            partner_id: partnerId,
            partner: partner,
            status: c.status,
            sender_id: c.sender_id,
            created_at: c.created_at,
            updated_at: c.updated_at,
            note: c.note,
            is_favorite: isFav
        };

        if (c.status === 'accepted') {
            friends.push(item);
            if (isFav) {
                favorites.push(item);
            }
        } else if (c.status === 'pending') {
            if (c.sender_id === user_id) {
                pendingSent.push(item);
            } else {
                pendingReceived.push(item);
            }
        }
    });

    myBlockedIds.forEach(bId => {
        const partner = usersMap[bId] || { id: bId, full_name: 'Người dùng', email: '' };
        blockedUsers.push({
            partner_id: bId,
            partner: partner
        });
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
        favorites: favorites.filter(filterFn),
        pending_sent: pendingSent.filter(filterFn),
        pending_received: pendingReceived.filter(filterFn),
        blocked_users: blockedUsers.filter(filterFn),
        total_friends: friends.length,
        total_favorites: favorites.length,
        total_pending_received: pendingReceived.length,
        total_blocked: blockedUsers.length
    };
}

module.exports = {
    sendConnectionRequest,
    respondConnectionRequest,
    getConnectionStatus,
    isFriend,
    isFavorite,
    toggleFavorite,
    unfriend,
    blockUser,
    unblockUser,
    getBlockStatus,
    getUserNetwork
};

