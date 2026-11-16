const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');
const settingsStore = require('./settingsStore');

const logFilePath = path.join(__dirname, '..', 'node_modules', '.cache', 'kgs work_data', 'audit_logs.json');
const legacyLogFilePath = path.join(__dirname, '..', 'data', 'audit_logs.json');

function ensureDir(p) {
    try {
        const d = path.dirname(p);
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    } catch(e) {}
}

// Đảm bảo file log json tồn tại ở cả 2 nơi để bảo đảm tính bền vững (Persistence)
function ensureLogFile() {
    try {
        ensureDir(logFilePath);
        ensureDir(legacyLogFilePath);

        if (!fs.existsSync(logFilePath) && fs.existsSync(legacyLogFilePath)) {
            fs.copyFileSync(legacyLogFilePath, logFilePath);
        } else if (fs.existsSync(logFilePath) && !fs.existsSync(legacyLogFilePath)) {
            fs.copyFileSync(logFilePath, legacyLogFilePath);
        } else if (!fs.existsSync(logFilePath) && !fs.existsSync(legacyLogFilePath)) {
            fs.writeFileSync(logFilePath, JSON.stringify([], null, 2), 'utf-8');
            fs.writeFileSync(legacyLogFilePath, JSON.stringify([], null, 2), 'utf-8');
        }
    } catch (e) {
        console.error('Lỗi khởi tạo audit_logs.json:', e.message);
    }
}

ensureLogFile();

/**
 * Gửi dữ liệu log bất đồng bộ lên Firebase Realtime Database
 */
async function forwardToFirebase(logEntry, customFirebaseUrl = null) {
    const firebaseUrl = customFirebaseUrl || settingsStore.getFirebaseDbUrl();
    if (!firebaseUrl || !firebaseUrl.startsWith('http')) return;

    try {
        const base = firebaseUrl.replace(/\/+$/, '');
        const targetUrl = `${base}/audit_logs/${logEntry.id}.json`;

        if (typeof fetch === 'function') {
            fetch(targetUrl, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(logEntry),
                signal: AbortSignal.timeout(5000)
            }).catch(err => {
                console.warn('[AuditLogger -> Firebase Sync Warning]:', err.message);
            });
        }
    } catch (e) {
        // Silent catch
    }
}

/**
 * Gửi dữ liệu log bất đồng bộ lên Google Sheets Webhook
 */
async function forwardToGoogleSheets(logEntry, customWebhook = null) {
    const webhookUrl = customWebhook || settingsStore.getGoogleSheetWebhook();
    if (!webhookUrl || !webhookUrl.startsWith('http')) return;

    try {
        const payload = {
            id: logEntry.id,
            timestamp: logEntry.timestamp,
            level: logEntry.level,
            module: logEntry.module,
            action: logEntry.action,
            actor: logEntry.user_email || logEntry.user_id || 'System',
            role: logEntry.user_role || 'system',
            ip: logEntry.ip || '127.0.0.1',
            details: logEntry.details,
            metadata: typeof logEntry.metadata === 'object' ? JSON.stringify(logEntry.metadata) : String(logEntry.metadata || '')
        };

        if (typeof fetch === 'function') {
            fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(5000)
            }).catch(err => {
                console.warn('[AuditLogger -> Google Sheets Sync Warning]:', err.message);
            });
        }
    } catch (e) {
        // Silent catch
    }
}

/**
 * Ghi log kiểm toán hệ thống toàn diện từ A-Z
 */
async function logEvent({
    module = 'SYSTEM',
    action = 'UNKNOWN_ACTION',
    level = 'INFO',
    details = '',
    user_id = null,
    actor_id = null,
    user_email = null,
    actor_email = null,
    user_role = null,
    ip = '127.0.0.1',
    metadata = {}
}) {
    const timestamp = new Date().toISOString();
    const logId = 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);

    const actualUserId = user_id || actor_id || null;
    const actualEmail = user_email || actor_email || (actualUserId ? `User:${String(actualUserId).substring(0, 8)}` : 'System');
    const actualRole = user_role || (actualUserId === 'ADMIN' ? 'admin' : 'system');

    const logEntry = {
        id: logId,
        timestamp,
        module: String(module).toUpperCase(),
        action: String(action).toUpperCase(),
        level: String(level).toUpperCase(),
        details,
        user_id: actualUserId,
        user_email: actualEmail,
        user_role: actualRole,
        ip,
        metadata: metadata || {}
    };

    console.log(`📝 [AUDIT LOG] [${logEntry.level}] [${logEntry.module}] [${logEntry.action}]: ${details}`);

    // 1. Lưu vào file JSON cục bộ an toàn (ghi đồng thời cả 2 nơi để không bị mất khi deploy)
    try {
        ensureLogFile();
        let logs = [];
        try {
            const raw = fs.readFileSync(logFilePath, 'utf-8');
            logs = JSON.parse(raw);
            if (!Array.isArray(logs)) logs = [];
        } catch (e) {
            logs = [];
        }

        logs.unshift(logEntry); // Sự kiện mới nhất lên đầu
        if (logs.length > 5000) logs = logs.slice(0, 5000); // Giới hạn 5000 logs

        const jsonStr = JSON.stringify(logs, null, 2);
        fs.writeFileSync(logFilePath, jsonStr, 'utf-8');
        try { fs.writeFileSync(legacyLogFilePath, jsonStr, 'utf-8'); } catch(e) {}
    } catch (fsErr) {
        console.warn('⚠️ [AUDIT LOG] Lỗi lưu vào audit_logs.json:', fsErr.message);
    }

    // 2. Thử lưu vào Supabase table system_audit_logs nếu có
    try {
        if (supabase) {
            await supabase.from('system_audit_logs').insert([{
                id: logId,
                module: logEntry.module,
                action: logEntry.action,
                level: logEntry.level,
                details: logEntry.details,
                user_id: actualUserId || null,
                user_email: logEntry.user_email,
                metadata: logEntry.metadata,
                created_at: timestamp
            }]);
        }
    } catch (dbErr) {
        // Silent catch
    }

    // 3. Tự động đồng bộ lên Firebase Realtime Database nếu được cấu hình
    forwardToFirebase(logEntry);

    // 4. Tự động đồng bộ lên Google Sheets Webhook nếu được cấu hình
    forwardToGoogleSheets(logEntry);

    return logEntry;
}

/**
 * Đọc log từ file JSON cục bộ
 */
function readLocalLogs() {
    ensureLogFile();
    let logs = [];
    for (const p of [logFilePath, legacyLogFilePath]) {
        if (fs.existsSync(p)) {
            try {
                const raw = fs.readFileSync(p, 'utf-8');
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed) && parsed.length > logs.length) {
                    logs = parsed;
                }
            } catch(e) {}
        }
    }
    return logs;
}

/**
 * Lấy danh sách audit logs với bộ lọc và tìm kiếm (Phiên bản Bất đồng bộ, kết hợp Firebase & Supabase & Local)
 */
async function getAuditLogsAsync({ module, level, search, limit = 500, offset = 0 } = {}) {
    let firebaseLogs = [];
    let supabaseLogs = [];
    const localLogs = readLocalLogs();

    // 1. Thử tải dữ liệu từ Firebase Realtime Database (nếu có cấu hình)
    const firebaseUrl = settingsStore.getFirebaseDbUrl();
    if (firebaseUrl && firebaseUrl.startsWith('http')) {
        try {
            const base = firebaseUrl.replace(/\/+$/, '');
            const targetUrl = `${base}/audit_logs.json`;
            const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(4000) });
            if (resp.ok) {
                const data = await resp.json();
                if (data && typeof data === 'object') {
                    firebaseLogs = Object.values(data);
                }
            }
        } catch (e) {
            console.warn('[AuditLogger] Không thể lấy log từ Firebase:', e.message);
        }
    }

    // 2. Thử tải dữ liệu từ Supabase nếu có bảng
    try {
        if (supabase) {
            const { data, error } = await supabase
                .from('system_audit_logs')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(limit || 500);
            if (!error && Array.isArray(data)) {
                supabaseLogs = data.map(d => ({
                    id: d.id,
                    timestamp: d.created_at || d.timestamp,
                    module: d.module,
                    action: d.action,
                    level: d.level,
                    details: d.details,
                    user_id: d.user_id,
                    user_email: d.user_email,
                    user_role: d.user_role || 'system',
                    ip: d.ip || '127.0.0.1',
                    metadata: d.metadata || {}
                }));
            }
        }
    } catch(e) {}

    // 3. Hợp nhất (Deduplicate) theo log ID
    const map = new Map();
    for (const l of [...localLogs, ...supabaseLogs, ...firebaseLogs]) {
        if (!l) continue;
        const key = l.id || `${l.timestamp}_${l.action}`;
        const normalized = {
            id: l.id || key,
            timestamp: l.timestamp || l.created_at || new Date().toISOString(),
            module: String(l.module || 'SYSTEM').toUpperCase(),
            action: String(l.action || 'UNKNOWN').toUpperCase(),
            level: String(l.level || 'INFO').toUpperCase(),
            details: l.details || '',
            user_id: l.user_id || l.actor_id || null,
            user_email: l.user_email || l.actor_email || (l.user_id ? `User:${String(l.user_id).substring(0, 8)}` : 'System'),
            user_role: l.user_role || 'system',
            ip: l.ip || '127.0.0.1',
            metadata: l.metadata || {}
        };
        map.set(key, normalized);
    }

    let logs = Array.from(map.values());

    // Sắp xếp thời gian mới nhất lên đầu
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Bộ lọc Module
    if (module && module !== 'ALL') {
        logs = logs.filter(l => l.module === module.toUpperCase());
    }

    // Bộ lọc Level
    if (level && level !== 'ALL') {
        logs = logs.filter(l => l.level === level.toUpperCase());
    }

    // Tìm kiếm tự do
    if (search && search.trim()) {
        const s = search.trim().toLowerCase();
        logs = logs.filter(l => 
            (l.details || '').toLowerCase().includes(s) ||
            (l.action || '').toLowerCase().includes(s) ||
            (l.user_email || '').toLowerCase().includes(s) ||
            (l.user_id || '').toLowerCase().includes(s) ||
            (l.module || '').toLowerCase().includes(s)
        );
    }

    const total = logs.length;
    const paginated = logs.slice(offset, offset + limit);

    return { 
        total, 
        logs: paginated,
        firebaseConnected: Boolean(firebaseUrl),
        firebaseCount: firebaseLogs.length
    };
}

/**
 * Lấy danh sách audit logs đồng bộ (Đọc local file)
 */
function getAuditLogs({ module, level, search, limit = 500, offset = 0 } = {}) {
    let logs = readLocalLogs();

    if (module && module !== 'ALL') {
        logs = logs.filter(l => l.module === module.toUpperCase());
    }

    if (level && level !== 'ALL') {
        logs = logs.filter(l => l.level === level.toUpperCase());
    }

    if (search && search.trim()) {
        const s = search.trim().toLowerCase();
        logs = logs.filter(l => 
            (l.details || '').toLowerCase().includes(s) ||
            (l.action || '').toLowerCase().includes(s) ||
            (l.user_email || '').toLowerCase().includes(s) ||
            (l.user_id || '').toLowerCase().includes(s) ||
            (l.module || '').toLowerCase().includes(s)
        );
    }

    const total = logs.length;
    const paginated = logs.slice(offset, offset + limit);

    return { total, logs: paginated };
}

/**
 * Đồng bộ hàng loạt (Batch Sync) toàn bộ log hiện có lên Google Sheets
 */
async function batchSyncToGoogleSheets(webhookUrl, maxRows = 300) {
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
        throw new Error('Địa chỉ Webhook Google Sheets không hợp lệ!');
    }

    const { logs } = await getAuditLogsAsync({ limit: maxRows });
    if (!logs || logs.length === 0) {
        return { success: true, count: 0, message: 'Chưa có bản ghi log nào để đồng bộ.' };
    }

    const rows = logs.map(l => ({
        id: l.id,
        timestamp: l.timestamp,
        level: l.level,
        module: l.module,
        action: l.action,
        actor: l.user_email || l.user_id || 'System',
        role: l.user_role || 'system',
        ip: l.ip || '127.0.0.1',
        details: l.details,
        metadata: typeof l.metadata === 'object' ? JSON.stringify(l.metadata) : String(l.metadata || '')
    }));

    if (typeof fetch === 'function') {
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rows)
        });
        if (!response.ok) {
            throw new Error(`Google Sheets Webhook trả về mã lỗi: ${response.status}`);
        }
    }

    return { success: true, count: rows.length };
}

/**
 * Đồng bộ hàng loạt (Batch Sync) toàn bộ log hiện có lên Firebase Realtime Database
 */
async function batchSyncToFirebase(customUrl = null, maxRows = 500) {
    const firebaseUrl = customUrl || settingsStore.getFirebaseDbUrl();
    if (!firebaseUrl || !firebaseUrl.startsWith('http')) {
        throw new Error('Địa chỉ Firebase Realtime Database URL không hợp lệ!');
    }

    const localLogs = readLocalLogs();
    if (!localLogs || localLogs.length === 0) {
        return { success: true, count: 0, message: 'Chưa có log cục bộ nào để đồng bộ.' };
    }

    const base = firebaseUrl.replace(/\/+$/, '');
    const targetUrl = `${base}/audit_logs.json`;

    // Tạo batch object { [logId]: log } để đẩy bằng PATCH chỉ với 1 HTTP request duy nhất
    const batchData = {};
    const limitLogs = localLogs.slice(0, maxRows);
    for (const l of limitLogs) {
        if (l.id) {
            batchData[l.id] = l;
        }
    }

    const resp = await fetch(targetUrl, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batchData),
        signal: AbortSignal.timeout(10000)
    });

    if (!resp.ok) {
        throw new Error(`Firebase Database trả về mã phản hồi: ${resp.status}`);
    }

    return { success: true, count: Object.keys(batchData).length };
}

module.exports = {
    logEvent,
    getAuditLogs,
    getAuditLogsAsync,
    batchSyncToGoogleSheets,
    batchSyncToFirebase
};
