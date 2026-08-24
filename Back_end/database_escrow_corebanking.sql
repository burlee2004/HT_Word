-- ============================================================
-- HTWORK - CORE BANKING ESCROW SCHEMA MIGRATION
-- Chay toan bo script nay trong Supabase SQL Editor
-- ============================================================

-- BUOC 1: Tao bang wallets (neu chua co)
CREATE TABLE IF NOT EXISTS public.wallets (
    id             uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id        uuid UNIQUE NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    balance        numeric(18, 2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
    locked_balance numeric(18, 2) NOT NULL DEFAULT 0 CHECK (locked_balance >= 0),
    created_at     timestamptz DEFAULT now()
);

-- BUOC 2: Tao bang wallet_ledger (SO CAI BAT BIEN - Double-Entry)
CREATE TABLE IF NOT EXISTS public.wallet_ledger (
    id                uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    sender_id         uuid NOT NULL REFERENCES public.users(id),
    receiver_id       uuid NOT NULL REFERENCES public.users(id),
    amount            numeric(18, 2) NOT NULL CHECK (amount > 0),
    type              text NOT NULL,
    milestone_id      uuid REFERENCES public.milestones(id),
    idempotency_key   text UNIQUE,
    note              text,
    created_at        timestamptz DEFAULT now()
);

-- BUOC 3: Them cot paid_at vao milestones
ALTER TABLE public.milestones ADD COLUMN IF NOT EXISTS paid_at timestamptz;

-- BUOC 4: Ham KHOA TIEN VAO ESCROW (fn_escrow_milestone)
CREATE OR REPLACE FUNCTION public.fn_escrow_milestone(
    p_milestone_id    uuid,
    p_client_id       uuid,
    p_amount          numeric,
    p_idempotency_key text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_system_escrow_id uuid := '00000000-0000-0000-0000-000000000001';
    v_client_wallet    record;
BEGIN
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM 1 FROM public.wallet_ledger WHERE idempotency_key = p_idempotency_key;
        IF FOUND THEN
            RETURN jsonb_build_object('success', false, 'error', 'Duplicate Request - Giao dich da duoc xu ly.');
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM public.milestones WHERE id = p_milestone_id AND status = 'FUNDED') THEN
        RETURN jsonb_build_object('success', false, 'error', 'Milestone nay da duoc ky quy truoc do.');
    END IF;

    SELECT * INTO v_client_wallet FROM public.wallets WHERE user_id = p_client_id FOR UPDATE;

    IF v_client_wallet.balance < p_amount THEN
        RETURN jsonb_build_object('success', false, 'error', 'So du khong du de ky quy.');
    END IF;

    UPDATE public.wallets SET balance = balance - p_amount, locked_balance = locked_balance + p_amount WHERE user_id = p_client_id;

    INSERT INTO public.wallet_ledger (sender_id, receiver_id, amount, type, milestone_id, idempotency_key, note)
    VALUES (p_client_id, v_system_escrow_id, p_amount, 'ESCROW_LOCK', p_milestone_id, p_idempotency_key, 'Ky quy Milestone');

    UPDATE public.milestones SET status = 'FUNDED' WHERE id = p_milestone_id;

    RETURN jsonb_build_object('success', true, 'message', 'Ky quy thanh cong!');
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

-- BUOC 5: Ham GIAI NGAN CHO FREELANCER (fn_release_milestone)
CREATE OR REPLACE FUNCTION public.fn_release_milestone(
    p_milestone_id    uuid,
    p_client_id       uuid,
    p_freelancer_id   uuid,
    p_idempotency_key text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_system_escrow_id  uuid := '00000000-0000-0000-0000-000000000001';
    v_milestone         record;
    v_client_wallet     record;
BEGIN
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM 1 FROM public.wallet_ledger WHERE idempotency_key = p_idempotency_key;
        IF FOUND THEN
            RETURN jsonb_build_object('success', false, 'error', 'Duplicate Request - Giao dich nay da duoc xu ly, khong the giai ngan lan 2.');
        END IF;
    END IF;

    SELECT * INTO v_milestone FROM public.milestones WHERE id = p_milestone_id FOR UPDATE;

    IF v_milestone.status = 'PAID' THEN
        RETURN jsonb_build_object('success', false, 'error', 'Milestone nay da duoc giai ngan truoc do (status: PAID).');
    END IF;

    SELECT * INTO v_client_wallet FROM public.wallets WHERE user_id = p_client_id FOR UPDATE;

    IF v_client_wallet.locked_balance < v_milestone.price THEN
        RETURN jsonb_build_object('success', false, 'error', 'So du bi khoa khong du de giai ngan.');
    END IF;

    UPDATE public.wallets SET locked_balance = locked_balance - v_milestone.price WHERE user_id = p_client_id;
    UPDATE public.wallets SET balance = balance + v_milestone.price WHERE user_id = p_freelancer_id;

    INSERT INTO public.wallet_ledger (sender_id, receiver_id, amount, type, milestone_id, idempotency_key, note)
    VALUES (v_system_escrow_id, p_freelancer_id, v_milestone.price, 'ESCROW_RELEASE', p_milestone_id, p_idempotency_key, 'Giai ngan Milestone');

    UPDATE public.milestones SET status = 'PAID', paid_at = now() WHERE id = p_milestone_id;

    RETURN jsonb_build_object('success', true, 'message', 'Giai ngan thanh cong! Token da vao vi Freelancer.');
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;
