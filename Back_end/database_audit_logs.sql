-- ============================================================
-- KGS WORK - BẢNG LƯU TRỮ NHẬT KÝ KIỂM TOÁN HỆ THỐNG VĨNH VIỄN
-- Chạy script này trong Supabase SQL Editor để lưu log trực tiếp trên Supabase
-- ============================================================

CREATE TABLE IF NOT EXISTS public.system_audit_logs (
    id text PRIMARY KEY,
    timestamp timestamptz DEFAULT now(),
    module text NOT NULL,
    action text NOT NULL,
    level text NOT NULL DEFAULT 'INFO',
    details text,
    user_id text,
    user_email text,
    user_role text,
    ip text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

-- Tạo Index tối ưu truy vấn
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.system_audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_module ON public.system_audit_logs(module);
CREATE INDEX IF NOT EXISTS idx_audit_logs_level ON public.system_audit_logs(level);
