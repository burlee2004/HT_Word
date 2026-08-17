-- Bảng lưu trữ tin nhắn giữa Khách hàng và Freelancer trong 1 dự án
CREATE TABLE public.messages (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  job_id uuid NOT NULL,
  milestone_id uuid, -- Nếu chat gắn liền với 1 mốc cụ thể
  sender_id uuid NOT NULL, -- Người gửi tin nhắn (Client hoặc Freelancer)
  content text,
  file_url text, -- Link file/ảnh đã upload
  file_type character varying DEFAULT 'text'::character varying, -- 'text', 'image', 'video', 'document'
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT messages_pkey PRIMARY KEY (id),
  CONSTRAINT messages_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.jobs(id),
  CONSTRAINT messages_milestone_id_fkey FOREIGN KEY (milestone_id) REFERENCES public.milestones(id),
  CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id)
);
