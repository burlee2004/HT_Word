-- ==========================================
-- Cập nhật Database cho tích hợp PayOS
-- Chạy đoạn mã này trong Supabase SQL Editor
-- ==========================================

-- Thêm cột payos_order_code để map với mã order của PayOS (kiểu BIGINT để chứa số ngẫu nhiên tối đa 53-bit)
ALTER TABLE public.deposit_requests 
ADD COLUMN IF NOT EXISTS payos_order_code BIGINT;

-- Đánh index để truy vấn nhanh khi Webhook từ PayOS gọi về
CREATE INDEX IF NOT EXISTS idx_deposit_requests_payos_order_code 
ON public.deposit_requests(payos_order_code);
