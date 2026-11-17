-- =================================================================================
-- HT Work - Nâng Cấp Schema (Quản lý Milestone Nâng Cao & ACID Transaction)
-- Chạy đoạn mã này trong mục "SQL Editor" của Supabase.
-- =================================================================================

-- 1. Bảng Project_Requirements (Đặc tả yêu cầu)
CREATE TABLE IF NOT EXISTS public.project_requirements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES public.jobs(id) ON DELETE CASCADE,
    requirement_file_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Bảng Milestone Revisions (Lịch sử yêu cầu sửa đổi)
CREATE TABLE IF NOT EXISTS public.milestone_revisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    milestone_id UUID REFERENCES public.milestones(id) ON DELETE CASCADE,
    feedback_text TEXT NOT NULL,
    screenshot_urls JSONB, -- Mảng lưu các link ảnh lỗi
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Cập nhật bảng Milestones hiện tại để hỗ trợ luồng mới
ALTER TABLE public.milestones 
ADD COLUMN IF NOT EXISTS expected_deliverables TEXT,
ADD COLUMN IF NOT EXISTS payment_mode VARCHAR(50) DEFAULT 'PAY_PER_MILESTONE',
ADD COLUMN IF NOT EXISTS proof_urls JSONB; -- Mảng link minh chứng

-- 4. FUNCTION PostgreSQL đảm bảo nguyên tắc ACID khi Approve Milestone
-- Hàm này gom tất cả các lệnh Update (Milestone, Wallet, Transaction) vào 1 block duy nhất.
-- Nếu bất kỳ lệnh nào lỗi, toàn bộ quá trình sẽ bị Rollback.
CREATE OR REPLACE FUNCTION approve_milestone_transaction(
    p_milestone_id UUID,
    p_client_id UUID,
    p_freelancer_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_payment_mode VARCHAR(50);
    v_amount DECIMAL(12,2);
    v_job_id UUID;
    v_total_milestones INT;
    v_approved_milestones INT;
    v_total_amount DECIMAL(12,2);
BEGIN
    -- Lấy thông tin Milestone và Khóa dòng (FOR UPDATE) để ngăn chặn Race Condition
    SELECT payment_mode, amount, job_id INTO v_payment_mode, v_amount, v_job_id
    FROM public.milestones WHERE id = p_milestone_id FOR UPDATE;

    -- 1. Cập nhật trạng thái Milestone
    UPDATE public.milestones SET status = 'APPROVED' WHERE id = p_milestone_id;

    -- 2. Xử lý dòng tiền dựa trên Payment Mode
    IF v_payment_mode = 'PAY_PER_MILESTONE' THEN
        -- Trừ Locked Balance của Client
        UPDATE public.wallets SET locked_balance = locked_balance - v_amount WHERE user_id = p_client_id;
        -- Cộng Balance cho Freelancer
        UPDATE public.wallets SET balance = balance + v_amount WHERE user_id = p_freelancer_id;
        
        -- Ghi log Transaction
        INSERT INTO public.transactions (user_id, amount, type, status) 
        VALUES (p_freelancer_id, v_amount, 'escrow_release_milestone', 'success');
        
    ELSIF v_payment_mode = 'PAY_AT_END' THEN
        -- Kiểm tra xem đây có phải Milestone cuối cùng không?
        SELECT COUNT(*) INTO v_total_milestones FROM public.milestones WHERE job_id = v_job_id;
        SELECT COUNT(*) INTO v_approved_milestones FROM public.milestones WHERE job_id = v_job_id AND status = 'APPROVED';
        
        -- Nếu TẤT CẢ milestone đều đã Approved -> Giải ngân 1 cục
        IF v_total_milestones = v_approved_milestones THEN
            SELECT SUM(amount) INTO v_total_amount FROM public.milestones WHERE job_id = v_job_id;
            
            UPDATE public.wallets SET locked_balance = locked_balance - v_total_amount WHERE user_id = p_client_id;
            UPDATE public.wallets SET balance = balance + v_total_amount WHERE user_id = p_freelancer_id;
            
            INSERT INTO public.transactions (user_id, amount, type, status) 
            VALUES (p_freelancer_id, v_total_amount, 'escrow_release_all', 'success');
        END IF;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
