-- =========================================================
-- SCRIPT RESET DỮ LIỆU & TẠO ADMIN (BẢO VỆ CHỐNG XÓA)
-- =========================================================

-- 1. Dọn dẹp sạch sẽ toàn bộ dữ liệu giao dịch cũ (Dùng CASCADE để tự động xóa khóa ngoại)
TRUNCATE TABLE 
    notifications, 
    messages, 
    transactions, 
    deposit_requests, 
    wallet_ledger,
    milestone_revisions,
    milestones, 
    job_applications, 
    jobs,
    project_requirements,
    freelancer_profiles,
    wallets,
    users
RESTART IDENTITY CASCADE;

-- 2. Tạo tài khoản Admin mới
-- Email: admin@htwork.com
-- Mật khẩu: admin123 (Mã băm bcrypt chuẩn của hệ thống)
INSERT INTO users (id, email, password, full_name, role, is_email_verified, kyc_status)
VALUES (
    '11111111-1111-1111-1111-111111111111', 
    'admin@htwork.com', 
    '$2b$10$QlS.v61DN6e6tSQjWt1WveVPvHy9aGFQPazPYSU4qpnsCwyvmn.pa', 
    'Quản Trị Viên HT Work', 
    'admin',
    true,
    'verified'
);

-- 3. Tạo ví tiền mặc định cho Admin
INSERT INTO wallets (user_id, balance, locked_balance)
VALUES ('11111111-1111-1111-1111-111111111111', 0, 0);

-- 4. Tạo Logic bảo vệ (Trigger) KHÓA CỨNG không cho xóa Admin
CREATE OR REPLACE FUNCTION prevent_admin_deletion()
RETURNS TRIGGER AS $$
BEGIN
    -- Nếu cố tình xóa user có role là 'admin' hoặc email là admin, sẽ bị chặn lại ngay lập tức
    IF OLD.role = 'admin' OR OLD.email = 'admin@htwork.com' THEN
        RAISE EXCEPTION 'BẢO MẬT: Không được phép xóa tài khoản Admin hệ thống!';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Xóa trigger cũ nếu đã tồn tại để cập nhật bản mới
DROP TRIGGER IF EXISTS trg_prevent_admin_deletion ON users;

-- Gắn khóa bảo vệ vào bảng users
CREATE TRIGGER trg_prevent_admin_deletion
BEFORE DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION prevent_admin_deletion();
