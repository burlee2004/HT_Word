require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('Lỗi: Không tìm thấy SUPABASE_URL hoặc SUPABASE_KEY trong file .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { autoRefreshToken: false, persistSession: false }
});

const tablesToWipe = [
    'notifications',
    'system_audit_logs',
    'wallet_ledger',
    'transactions',
    'deposit_requests',
    'withdraw_requests',
    'wallets',
    'milestone_revisions',
    'milestones',
    'job_applications',
    'direct_messages',
    'friendships',
    'jobs',
    'freelancer_profiles',
    'otp_verifications',
    'users'
];

async function wipeDatabase() {
    console.log('⚠️ BẮT ĐẦU XÓA TOÀN BỘ DỮ LIỆU TRÊN SUPABASE ⚠️');
    console.log('Đang kết nối tới:', supabaseUrl);

    for (const table of tablesToWipe) {
        try {
            // Lấy id để xóa (Supabase yêu cầu điều kiện khi delete nhiều)
            const { data, error: selectErr } = await supabase.from(table).select('id').limit(9999);
            
            if (selectErr) {
                // Có thể bảng không có cột id, thử xóa trắng
                const { error: delErr } = await supabase.from(table).delete().neq('id', 'non-existent-id');
                if (delErr) {
                    console.error(`❌ Lỗi khi xóa bảng ${table}:`, delErr.message);
                } else {
                    console.log(`✅ Đã xóa toàn bộ dữ liệu bảng: ${table}`);
                }
                continue;
            }

            if (!data || data.length === 0) {
                console.log(`ℹ️ Bảng ${table} đã trống.`);
                continue;
            }

            const ids = data.map(r => r.id);
            // Xóa theo batch 1000
            for (let i = 0; i < ids.length; i += 1000) {
                const batchIds = ids.slice(i, i + 1000);
                const { error } = await supabase.from(table).delete().in('id', batchIds);
                if (error) throw error;
            }
            console.log(`✅ Đã xóa ${ids.length} dòng từ bảng: ${table}`);
        } catch (err) {
            console.error(`❌ Lỗi khi dọn dẹp bảng ${table}:`, err.message);
        }
    }
    
    console.log('🎉 ĐÃ HOÀN TẤT VIỆC XÓA DỮ LIỆU TRÊN CLOUD! 🎉');
    console.log('Lưu ý: Để web hoạt động bình thường, hãy tải lại trang và tạo lại tài khoản từ đầu.');
}

wipeDatabase();
