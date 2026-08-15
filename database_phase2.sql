-- =================================================================================
-- HT Work - Database Schema (Phase 2)
-- Chạy đoạn mã này trong mục "SQL Editor" của Supabase.
-- =================================================================================

-- Bảng Milestones (Quản lý tiến độ và bàn giao)
CREATE TABLE IF NOT EXISTS public.milestones (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES public.jobs(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    amount DECIMAL(12,2) NOT NULL,
    evidence_url TEXT, -- Link file tải lên S3 hoặc Cloudinary
    status VARCHAR(50) DEFAULT 'pending', -- 'pending' (Đang làm), 'pending_review' (Chờ duyệt), 'approved' (Đã nghiệm thu), 'rejected' (Từ chối)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
