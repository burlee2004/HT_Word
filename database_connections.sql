-- Bảng lưu trữ kết nối bạn bè / Mối ruột giữa Client và Freelancer
CREATE TABLE IF NOT EXISTS public.friendships (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    user_id_1 uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    user_id_2 uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    sender_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    status varchar(20) NOT NULL DEFAULT 'pending', -- 'pending', 'accepted', 'rejected', 'blocked'
    note text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT friendships_pkey PRIMARY KEY (id),
    CONSTRAINT unique_friendship UNIQUE (user_id_1, user_id_2)
);

-- Bảng lưu trữ tin nhắn chat 1-1 trực tiếp
CREATE TABLE IF NOT EXISTS public.direct_messages (
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    sender_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    receiver_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    content text,
    file_url text,
    file_name text,
    file_type varchar(50) DEFAULT 'text',
    is_read boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT direct_messages_pkey PRIMARY KEY (id)
);

-- Index tối ưu tìm kiếm hội thoại
CREATE INDEX IF NOT EXISTS idx_dm_users ON public.direct_messages (sender_id, receiver_id);
CREATE INDEX IF NOT EXISTS idx_friendships_users ON public.friendships (user_id_1, user_id_2);
