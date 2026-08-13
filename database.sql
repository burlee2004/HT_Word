-- =================================================================================
-- HT Work - Database Schema (Phase 1 MVP)
-- Chạy đoạn mã này trong mục "SQL Editor" của Supabase.
-- =================================================================================

-- 1. Bảng Ví người dùng (Wallets)
-- Lưu trữ số dư Token khả dụng và số dư Token đang bị khóa (Escrow)
CREATE TABLE IF NOT EXISTS public.wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    balance DECIMAL(12,2) DEFAULT 0,          -- Token khả dụng
    locked_balance DECIMAL(12,2) DEFAULT 0,   -- Token đang bị khóa (Escrow)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Bảng Công việc (Jobs)
-- Do Khách hàng (Client) đăng tải
CREATE TABLE IF NOT EXISTS public.jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    budget DECIMAL(12,2) NOT NULL,
    status VARCHAR(50) DEFAULT 'open', -- 'open' (Đang tuyển), 'in_progress' (Đang làm), 'completed' (Hoàn thành)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Bảng Ứng tuyển (Job Applications)
-- Do Freelancer gửi báo giá cho Job
CREATE TABLE IF NOT EXISTS public.job_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES public.jobs(id) ON DELETE CASCADE,
    freelancer_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    cover_letter TEXT,
    bid_amount DECIMAL(12,2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- 'pending' (Chờ duyệt), 'accepted' (Đã nhận), 'rejected' (Bị từ chối)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Bảng Lịch sử Giao dịch (Transactions)
-- Để theo dõi lịch sử nạp tiền, khóa tiền
CREATE TABLE IF NOT EXISTS public.transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    amount DECIMAL(12,2) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'deposit', 'withdraw', 'escrow_lock', 'escrow_release'
    status VARCHAR(50) DEFAULT 'success',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
