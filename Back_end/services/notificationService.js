const supabase = require('../config/supabase');
const { logEvent } = require('./auditLogger');

/**
 * Service quản lý và phát thông báo diện rộng toàn hệ thống
 */
class NotificationService {
    /**
     * Phát thông báo tới TẤT CẢ người dùng trong toàn server (Client, Freelancer, Admin)
     * @param {Object} options
     * @param {string} options.title - Tiêu đề thông báo
     * @param {string} options.content - Nội dung thông báo
     * @param {string} [options.actor_id] - ID người phát (Admin hoặc SYSTEM)
     */
    async broadcastToAllUsers({ title, content, actor_id = 'SYSTEM' }) {
        if (!title || !content) {
            throw new Error('Tiêu đề và nội dung thông báo không được để trống.');
        }

        console.log(`📢 [Broadcast] Đang lấy danh sách người dùng để gửi thông báo: "${title}"...`);
        const { data: users, error: fetchErr } = await supabase
            .from('users')
            .select('id, email, full_name');

        if (fetchErr) {
            console.error('❌ [Broadcast] Lỗi lấy danh sách users:', fetchErr);
            throw fetchErr;
        }

        if (!users || users.length === 0) {
            console.warn('⚠️ [Broadcast] Không tìm thấy người dùng nào trong cơ sở dữ liệu.');
            return { success: true, total_users: 0, delivered_count: 0 };
        }

        const notifications = users.map(u => ({
            user_id: u.id,
            title: title.trim(),
            content: content.trim(),
            is_read: false
        }));

        // Chia nhỏ theo batch (100 thông báo / batch) để tránh tràn payload của DB
        const BATCH_SIZE = 100;
        let deliveredCount = 0;

        for (let i = 0; i < notifications.length; i += BATCH_SIZE) {
            const batch = notifications.slice(i, i + BATCH_SIZE);
            const { error: insErr } = await supabase.from('notifications').insert(batch);
            if (insErr) {
                console.error(`❌ [Broadcast] Lỗi insert batch ${i} - ${i + batch.length}:`, insErr);
            } else {
                deliveredCount += batch.length;
            }
        }

        console.log(`✅ [Broadcast] Đã phát thông báo thành công tới ${deliveredCount}/${users.length} tài khoản.`);

        try {
            await logEvent({
                module: 'NOTIFICATION',
                action: 'BROADCAST_ALL',
                actor_id: actor_id,
                level: 'INFO',
                details: `Phát thông báo toàn server: "${title}" tới ${deliveredCount} người dùng.`,
                metadata: { title, content, total_users: users.length, delivered: deliveredCount }
            });
        } catch (e) {
            console.warn('Lỗi ghi audit log broadcast:', e.message);
        }

        return {
            success: true,
            total_users: users.length,
            delivered_count: deliveredCount
        };
    }

    /**
     * Phát thông báo theo nhóm vai trò (vd: 'freelancer' hoặc 'client')
     */
    async broadcastToRole(role, { title, content, actor_id = 'SYSTEM' }) {
        if (!role || !title || !content) {
            throw new Error('Vai trò, tiêu đề và nội dung không được để trống.');
        }

        const { data: users, error: fetchErr } = await supabase
            .from('users')
            .select('id')
            .eq('role', role);

        if (fetchErr) throw fetchErr;
        if (!users || users.length === 0) return { success: true, count: 0 };

        const rows = users.map(u => ({
            user_id: u.id,
            title: title.trim(),
            content: content.trim(),
            is_read: false
        }));

        const BATCH_SIZE = 100;
        let count = 0;
        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);
            const { error: insErr } = await supabase.from('notifications').insert(batch);
            if (!insErr) count += batch.length;
        }

        return { success: true, total_users: users.length, delivered_count: count };
    }

    /**
     * Gửi thông báo cho 1 người dùng cụ thể
     */
    async notifyUser(userId, { title, content }) {
        if (!userId || !title || !content) return false;
        const { error } = await supabase.from('notifications').insert([{
            user_id: userId,
            title: title.trim(),
            content: content.trim(),
            is_read: false
        }]);
        return !error;
    }
}

module.exports = new NotificationService();
