-- ===================================================
-- CẬP NHẬT HÀM DUYỆT NẠP TIỀN (FIX LỖI CONSTRAINT)
-- ===================================================

CREATE OR REPLACE FUNCTION public.fn_approve_deposit(
    p_request_id uuid,
    p_admin_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_request record;
    v_wallet record;
BEGIN
    -- ROW-LEVEL LOCK trên Yêu cầu nạp tiền (deposit_requests)
    SELECT * INTO v_request 
    FROM public.deposit_requests 
    WHERE id = p_request_id 
    FOR UPDATE;

    IF v_request IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Không tìm thấy yêu cầu nạp tiền này.');
    END IF;

    -- Kiểm tra trạng thái chống duyệt đúp (Idempotency)
    IF v_request.status = 'approved' THEN
        RETURN jsonb_build_object('success', false, 'error', 'Yêu cầu này đã được duyệt trước đó. Không thể duyệt 2 lần.');
    END IF;

    IF v_request.status = 'rejected' THEN
        RETURN jsonb_build_object('success', false, 'error', 'Yêu cầu này đã bị từ chối.');
    END IF;

    -- Kiểm tra ví (Tạo nếu chưa có)
    SELECT * INTO v_wallet FROM public.wallets WHERE user_id = v_request.user_id FOR UPDATE;
    IF v_wallet IS NULL THEN
        INSERT INTO public.wallets (user_id, balance, locked_balance) VALUES (v_request.user_id, 0, 0);
    ELSE
        -- Khóa ROW ví
        PERFORM 1 FROM public.wallets WHERE user_id = v_request.user_id FOR UPDATE;
    END IF;

    -- Cộng tiền vào Ví
    UPDATE public.wallets
    SET balance = balance + v_request.amount
    WHERE user_id = v_request.user_id;

    -- Ghi Sổ cái Bất biến (wallet_ledger)
    -- FIX LỖI: Sử dụng p_admin_id làm sender_id thay vì NULL để tránh lỗi NOT NULL constraint
    INSERT INTO public.wallet_ledger (sender_id, receiver_id, amount, type, idempotency_key, note)
    VALUES (
        p_admin_id, 
        v_request.user_id, 
        v_request.amount, 
        'DEPOSIT', 
        'DEPOSIT_' || p_request_id, 
        'Admin duyệt nạp tiền qua VietQR'
    );

    -- Cập nhật trạng thái Request
    UPDATE public.deposit_requests
    SET status = 'approved'
    WHERE id = p_request_id;

    RETURN jsonb_build_object('success', true, 'message', 'Đã duyệt nạp ' || v_request.amount || ' Token thành công!');
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;
