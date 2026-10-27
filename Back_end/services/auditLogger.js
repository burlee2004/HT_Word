const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

const logFilePath = path.join(__dirname, '..', 'node_modules', '.cache', 'htwork_data', 'audit_logs.json');
const legacyLogFilePath = path.join(__dirname, '..', 'data', 'audit_logs.json');

// Đảm bảo file log json tồn tại
function ensureLogFile() {
    try {
        const dir = path.dirname(logFilePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        if (!fs.existsSync(logFilePath)) {
            if (fs.existsSync(legacyLogFilePath)) {
                fs.copyFileSync(legacyLogFilePath, logFilePath);
            } else {
                fs.writeFileSync(logFilePath, JSON.stringify([], null, 2), 'utf-8');
            }
        }
    } catch (e) {
        console.error('Lỗi khởi tạo audit_logs.json:', e.message);
    }
}

ensureLogFile();

/**
 * Ghi log kiểm toán hệ thống toàn diện từ A-Z
 * @param {Object} param
 * @param {string} param.module - AUTH | JOB | MILESTONE | WALLET | CHAT | DISPUTE | ADMIN | SYSTEM
 * @param {string} param.action - Tên hành động (vd: REGISTER, LOGIN, CREATE_JOB, SUBMIT_EVIDENCE, RELEASE_ESCROW, CREATE_WITHDRAW, RESOLVE_DISPUTE...)
 * @param {string} param.level - INFO | WARN | SECURITY | CRITICAL
 * @param {string} param.details - Mô tả chi tiết hành động
 * @param {string} [param.user_id] - ID người thực hiện
 * @param {string} [param.user_email] - Email người thực hiện
 * @param {string} [param.user_role] - client | freelancer | admin
 * @param {string} [param.ip] - IP client
 * @param {Object} [param.metadata] - Dữ liệu JSON chi tiết (payload, job_id, milestone_id, amount...)
 */
async function logEvent({
    module = 'SYSTEM',
    action = 'UNKNOWN_ACTION',
    level = 'INFO',
    details = '',
    user_id = null,
    user_email = null,
    user_role = null,
    ip = '127.0.0.1',
    metadata = {}
}) {
    const timestamp = new Date().toISOString();
    const logId = 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);

    const logEntry = {
        id: logId,
        timestamp,
        module: module.toUpperCase(),
        action: action.toUpperCase(),
        level: level.toUpperCase(),
        details,
        user_id,
        user_email: user_email || (user_id ? `User:${user_id.substring(0, 8)}` : 'System'),
        user_role: user_role || 'system',
        ip,
        metadata: metadata || {}
    };

    console.log(`📝 [AUDIT LOG] [${logEntry.level}] [${logEntry.module}] [${logEntry.action}]: ${details}`);

    // 1. Lưu vào file JSON cục bộ an toàn
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

        logs.unshift(logEntry); // Đưa sự kiện mới nhất lên đầu
        if (logs.length > 5000) logs = logs.slice(0, 5000); // Giới hạn 5000 log gần nhất

        fs.writeFileSync(logFilePath, JSON.stringify(logs, null, 2), 'utf-8');
    } catch (fsErr) {
        console.warn('⚠️ [AUDIT LOG] Lỗi lưu vào audit_logs.json:', fsErr.message);
    }

    // 2. Thử lưu vào Supabase nếu có bảng
    try {
        if (supabase) {
            await supabase.from('system_audit_logs').insert([{
                id: logId,
                module: logEntry.module,
                action: logEntry.action,
                level: logEntry.level,
                details: logEntry.details,
                user_id: user_id || null,
                user_email: logEntry.user_email,
                metadata: logEntry.metadata,
                created_at: timestamp
            }]).catch(() => {}); // Không throw error nếu chưa tạo bảng
        }
    } catch (dbErr) {
        // Silent catch for DB log
    }

    return logEntry;
}

/**
 * Lấy danh sách audit logs với bộ lọc và tìm kiếm
 */
function getAuditLogs({ module, level, search, limit = 100, offset = 0 } = {}) {
    ensureLogFile();
    try {
        const raw = fs.readFileSync(logFilePath, 'utf-8');
        let logs = JSON.parse(raw);
        if (!Array.isArray(logs)) logs = [];

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
                (l.module || '').toLowerCase().includes(s)
            );
        }

        const total = logs.length;
        const paginated = logs.slice(offset, offset + limit);

        return { total, logs: paginated };
    } catch (e) {
        console.error('Lỗi đọc audit logs:', e.message);
        return { total: 0, logs: [] };
    }
}

module.exports = {
    logEvent,
    getAuditLogs
};
