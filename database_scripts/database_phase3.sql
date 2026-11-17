-- =================================================================================
-- HT Work - Database Schema (Phase 3)
-- Chạy đoạn mã này trong mục "SQL Editor" của Supabase.
-- =================================================================================

-- Bảng Lệnh Nạp Token (Deposit Requests)
CREATE TABLE IF NOT EXISTS public.deposit_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    amount DECIMAL(12,2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- 'pending' (Chờ duyệt), 'approved' (Đã duyệt), 'rejected' (Bị từ chối)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Bảng Thông báo (Notifications)
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
