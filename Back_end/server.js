require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const blockchain = require('./blockchain');

// Import cấu hình Upload
const uploadImage = require('./config/cloudinary');
const uploadFile = require('./config/s3');

// Khởi tạo PayOS
const payosModule = require('@payos/node');
const PayOS = payosModule.PayOS || payosModule; // Xử lý cả 2 trường hợp version
const payos = new PayOS(
    process.env.PAYOS_CLIENT_ID,
    process.env.PAYOS_API_KEY,
    process.env.PAYOS_CHECKSUM_KEY
);


// 1. Khởi tạo Express app & Cấu hình
const app = express();
app.use(cors()); // Cho phép Frontend gọi API
app.use(express.json()); // Hỗ trợ đọc dữ liệu JSON từ request body

// 2. Kết nối Supabase (Chỉ khai báo 1 lần duy nhất)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

// Kiểm tra xem biến môi trường có đọc được không (Dành cho Debug)
if (!supabaseUrl || !supabaseKey) {
    console.log("❌ LỖI: Không tìm thấy SUPABASE_URL hoặc SUPABASE_KEY. Kiểm tra file .env!");
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Route Test xem Server có chạy không
app.get('/', (req, res) => {
    res.send('HT Work Backend is running!');
});

// Route Đăng ký (Register)
app.post('/register', async (req, res) => {
    const { email, password, full_name, role, main_category, skills } = req.body;

    try {
        // 1. Mã hóa mật khẩu (Giả sử bạn đã dùng bcrypt)
        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Tạo User trong bảng public.users
        const { data: newUser, error: userError } = await supabase
            .from('users')
            .insert([{ email, password: hashedPassword, full_name, role }])
            .select()
            .single();

        if (userError) throw userError;

        // 3. Nếu là Freelancer, tạo thêm Profile
        if (role === 'freelancer') {
            const { error: profileError } = await supabase
                .from('freelancer_profiles')
                .insert([{
                    user_id: newUser.id,
                    main_category: main_category || 'Other',
                    skills: skills || [] // Mảng JSON chứa tối đa 5 skills
                }]);

            if (profileError) {
                // Rollback: Xóa user nếu tạo profile thất bại để tránh rác dữ liệu
                await supabase.from('users').delete().eq('id', newUser.id);
                throw profileError;
            }
        }

        res.status(201).json({ message: 'Đăng ký thành công!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Route Đăng nhập (Login)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Lấy thông tin user (bao gồm cả role)
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) throw new Error('Email không tồn tại!');

        // Kiểm tra mật khẩu (Sử dụng bcrypt)
        const match = await bcrypt.compare(password, user.password);
        if (!match) throw new Error('Mật khẩu không đúng!');

        // Trả về thông tin user (để Frontend biết đường điều hướng)
        res.status(200).json({ 
            message: 'Đăng nhập thành công', 
            user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role } 
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Route Upload Ảnh (Cloudinary)
app.post('/upload-image', uploadImage.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Không có file ảnh' });
    
    res.status(200).json({
        message: 'Upload ảnh thành công!',
        imageUrl: req.file.path // Đường dẫn ảnh trên Cloudinary
    });
});

// Route Upload File/Video (AWS S3)
app.post('/upload-file', uploadFile.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Không có file' });
    
    res.status(200).json({
        message: 'Upload file thành công!',
        fileUrl: req.file.location // Đường dẫn file trên S3
    });
});

// ==========================================
// API DÀNH CHO NGƯỜI DÙNG (PROFILE & BIO)
// ==========================================

// 1. Xem Hồ sơ cá nhân (Profile)
app.get('/api/users/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, full_name, email, role, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner, created_at')
            .eq('id', req.params.id)
            .single();
        if (error) throw error;
        res.status(200).json(data);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 2. Cập nhật Hồ sơ cá nhân
app.put('/api/users/:id', async (req, res) => {
    const { full_name, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner } = req.body;
    try {
        const { data, error } = await supabase
            .from('users')
            .update({ full_name, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner })
            .eq('id', req.params.id)
            .select('id, full_name, email, role, avatar_url, cover_url, bio, skills, bank_name, bank_account, bank_owner, created_at')
            .single();
        if (error) throw error;
        res.status(200).json({ message: 'Cập nhật thành công', user: data });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// ==========================================
// CÁC API VỀ CÔNG VIỆC (JOB)
// ==========================================

// 1. API: Khách hàng đăng Job mới
app.post('/api/jobs', async (req, res) => {
    const { client_id, title, description, budget } = req.body;
    try {
        // KIỂM TRA SỐ DƯ VÍ TRƯỚC KHI CHO ĐĂNG DỰ ÁN
        const { data: wallet, error: walletErr } = await supabase.from('wallets').select('balance').eq('user_id', client_id).single();
        if (walletErr || !wallet) throw new Error('Không tìm thấy ví của bạn.');
        if (wallet.balance < budget) throw new Error(`Số dư ví không đủ! Dự án yêu cầu ${budget} Token, nhưng ví bạn chỉ có ${wallet.balance} Token. Vui lòng nạp thêm.`);

        const { data, error } = await supabase
            .from('jobs')
            .insert([{ client_id, title, description, budget, status: 'open' }])
            .select();
        

        if (error) throw error;

        // Gửi thông báo cho Client
        await supabase.from('notifications').insert([{
            user_id: client_id,
            title: 'Tạo Yêu cầu thành công',
            content: `Bạn đã đăng thành công yêu cầu: "${title}". Hãy chờ Freelancer ứng tuyển nhé.`
        }]);

        res.status(201).json({ message: 'Đăng dự án thành công!', job: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 2. API: Freelancer xem danh sách Job đang Open
app.get('/api/jobs', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('jobs')
            .select(`*, users (full_name)`) // Lấy thêm tên người đăng
            .eq('status', 'open')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.status(200).json({ jobs: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. API: Freelancer ứng tuyển (Báo giá)
app.post('/api/jobs/apply', async (req, res) => {
    const { job_id, freelancer_id, cover_letter, bid_amount } = req.body;
    try {
        const { data, error } = await supabase
            .from('job_applications')
            .insert([{ job_id, freelancer_id, cover_letter, bid_amount, status: 'pending' }])
            .select();
        
        if (error) throw error;
        res.status(201).json({ message: 'Ứng tuyển thành công!', application: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. API: Khách hàng Chấp nhận Freelancer (Bước khởi tạo - KHÔNG KHÓA TIỀN)
app.post('/api/jobs/accept-freelancer', async (req, res) => {
    const { client_id, application_id } = req.body;
    try {
        // Cập nhật trạng thái Application thành 'accepted'
        const { data: updatedApp, error: appErr } = await supabase
            .from('job_applications')
            .update({ status: 'accepted' })
            .eq('id', application_id)
            .select()
            .single();
            
        if (appErr) throw appErr;

        // Đổi trạng thái Job sang 'planning' và cập nhật Ngân sách dự án thành Giá thỏa thuận của Freelancer
        await supabase.from('jobs').update({ status: 'planning', budget: updatedApp.bid_amount }).eq('id', updatedApp.job_id);

        // Gửi thông báo cho Freelancer yêu cầu lập kế hoạch
        await supabase.from('notifications').insert([{
            user_id: updatedApp.freelancer_id,
            title: 'Trúng thầu dự án!',
            content: 'Khách hàng đã chọn bạn. Hãy vào mục Dự án đang làm để Lập Kế Hoạch (Milestones) và gửi cho Khách hàng duyệt.'
        }]);

        res.status(200).json({ message: 'Đã chọn Freelancer. Chờ Freelancer lập kế hoạch.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.1. API: Freelancer tạo Kế hoạch (Tạo nhiều Milestones)
app.post('/api/milestones/create-plan', async (req, res) => {
    const { job_id, milestones } = req.body; 
    // milestones là mảng: [{ title, description, expected_deliverables, amount, payment_mode }]
    try {
        // Gắn job_id và status mặc định vào từng milestone
        const inserts = milestones.map(m => ({
            ...m,
            job_id: job_id,
            status: 'PENDING'
        }));

        const { error } = await supabase.from('milestones').insert(inserts);
        if (error) throw error;

        // Đổi trạng thái job để báo hiệu Khách hàng cần duyệt Plan
        await supabase.from('jobs').update({ status: 'pending_plan_approval' }).eq('id', job_id);

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Bản kế hoạch dự án đã hoàn tất',
                content: 'Freelancer đã lên xong kế hoạch (Milestones). Vui lòng vào kiểm tra, chốt kế hoạch và Khóa Escrow để bắt đầu.'
            }]);
        }

        res.status(200).json({ message: 'Tạo kế hoạch thành công, chờ Khách duyệt.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.1.1 API: Freelancer hủy/thu hồi Kế hoạch (khi đang ở pending_plan_approval)
app.post('/api/milestones/revoke-plan', async (req, res) => {
    const { job_id } = req.body;
    try {
        // Kiểm tra xem job có đang ở trạng thái pending_plan_approval không
        const { data: job, error: jobErr } = await supabase.from('jobs').select('status').eq('id', job_id).single();
        if (jobErr) throw jobErr;
        
        if (job.status !== 'pending_plan_approval') {
            return res.status(400).json({ error: 'Chỉ có thể thu hồi khi kế hoạch đang chờ duyệt.' });
        }

        // Xóa tất cả milestones PENDING của job này
        const { error: delErr } = await supabase.from('milestones').delete().match({ job_id: job_id, status: 'PENDING' });
        if (delErr) throw delErr;

        // Trả trạng thái job về lại planning
        const { error: updateErr } = await supabase.from('jobs').update({ status: 'planning' }).eq('id', job_id);
        if (updateErr) throw updateErr;

        res.status(200).json({ message: 'Đã thu hồi kế hoạch thành công. Bạn có thể làm lại.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4.2. API: Khách hàng Duyệt Kế hoạch & Chính thức Khóa Tiền Escrow
app.post('/api/jobs/start-project', async (req, res) => {
    const { client_id, job_id } = req.body;
    try {
        // Tính tổng tiền các milestones
        const { data: milestones, error: mErr } = await supabase.from('milestones').select('amount').eq('job_id', job_id);
        if (mErr || !milestones || milestones.length === 0) throw new Error('Không có kế hoạch nào để duyệt');
        
        const totalAmount = milestones.reduce((sum, m) => sum + parseFloat(m.amount), 0);

        // Lấy ví của Client
        const { data: wallet, error: walletError } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        if (walletError || !wallet || wallet.balance < totalAmount) {
            return res.status(400).json({ error: `Ví không đủ tiền! Cần ${totalAmount} Token.` });
        }

        // Cập nhật số dư Ví: Trừ Balance, cộng Locked Balance
        await supabase.from('wallets').update({ 
            balance: wallet.balance - totalAmount,
            locked_balance: wallet.locked_balance + totalAmount 
        }).eq('user_id', client_id);

        // Đổi trạng thái Job sang in_progress
        await supabase.from('jobs').update({ status: 'in_progress' }).eq('id', job_id);

        // Chuyển status của Milestone đầu tiên sang IN_PROGRESS
        const sortedMilestones = await supabase.from('milestones').select('id').eq('job_id', job_id).order('created_at', { ascending: true }).limit(1);
        if (sortedMilestones.data.length > 0) {
            await supabase.from('milestones').update({ status: 'IN_PROGRESS' }).eq('id', sortedMilestones.data[0].id);
        }

        // Ghi transaction
        await supabase.from('transactions').insert([{
            user_id: client_id,
            amount: totalAmount,
            type: 'escrow_lock',
            status: 'success'
        }]);

        // Thông báo Freelancer
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        await supabase.from('notifications').insert([{
            user_id: appData.freelancer_id,
            title: 'Dự án chính thức bắt đầu!',
            content: `Khách hàng đã chốt kế hoạch và Khóa ${totalAmount} Token. Bắt tay vào làm việc ngay!`
        }]);

        res.status(200).json({ message: 'Đã khóa Escrow và bắt đầu dự án thành công!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. API: Khách hàng xem danh sách Freelancer ứng tuyển
app.get('/api/client/:client_id/applications', async (req, res) => {
    const { client_id } = req.params;
    try {
        // 1. Tìm các job do client này đăng
        const { data: jobs, error: jobsError } = await supabase
            .from('jobs')
            .select('id, title')
            .eq('client_id', client_id);
            
        if (jobsError) throw jobsError;
        if (!jobs || jobs.length === 0) return res.status(200).json({ applications: [] });

        const jobIds = jobs.map(j => j.id);

        // 2. Tìm các ứng tuyển thuộc về các job này
        // Lưu ý: dùng thư viện Supabase JS để join bảng users lấy tên Freelancer
        const { data: apps, error: appsError } = await supabase
            .from('job_applications')
            .select(`
                *,
                jobs (title),
                users!job_applications_freelancer_id_fkey (full_name, email)
            `)
            .in('job_id', jobIds)
            .eq('status', 'pending');

        if (appsError) throw appsError;
        
        res.status(200).json({ applications: apps });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 6. API: Admin xem toàn bộ Sổ cái (Ledger)
app.get('/api/admin/transactions', async (req, res) => {
    try {
        // Lấy từ Sổ cái (wallet_ledger) thay vì transactions cũ
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('*, sender:sender_id(full_name, email), receiver:receiver_id(full_name, email)')
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.status(200).json({ transactions: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 6.5. API: Khách hàng xem danh sách các Yêu cầu (Job) mình đã tạo
app.get('/api/client/:client_id/my-jobs', async (req, res) => {
    const { client_id } = req.params;
    try {
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select('*')
            .eq('client_id', client_id)
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.status(200).json({ jobs });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO PHASE 2 (THỰC THI & NGHIỆM THU)
// ==========================================

// 7. API: Lấy danh sách job Freelancer đang làm (kể cả PLANNING)
app.get('/api/freelancer/:id/active-jobs', async (req, res) => {
    const { id } = req.params;
    try {
        const { data: apps, error } = await supabase
            .from('job_applications')
            .select(`
                job_id,
                jobs (id, title, description, budget, client_id, status)
            `)
            .eq('freelancer_id', id)
            .eq('status', 'accepted');
            
        if (error) throw error;
        if (!apps || apps.length === 0) return res.status(200).json({ jobs: [] });
        
        const jobs = apps.map(app => app.jobs);
        
        // Lấy thêm milestone và revision cho từng job
        for (let job of jobs) {
            const { data: milestones } = await supabase
                .from('milestones')
                .select('*, milestone_revisions(feedback_text, screenshot_urls, created_at)')
                .eq('job_id', job.id)
                .order('created_at', { ascending: true });
            job.milestones = milestones || [];
        }

        res.status(200).json({ jobs });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 8. API: Freelancer nộp minh chứng (Submit Milestone)
app.post('/api/milestones/submit', async (req, res) => {
    const { milestone_id, evidence_url } = req.body;
    try {
        const { data, error } = await supabase
            .from('milestones')
            .update({ evidence_url, status: 'pending_review' })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', data[0].job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Có báo cáo công việc mới',
                content: 'Freelancer vừa nộp báo cáo (minh chứng) cho dự án. Hãy vào kiểm tra và nghiệm thu.'
            }]);
        }

        res.status(200).json({ message: 'Nộp bằng chứng thành công!', milestone: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 9. API: Khách hàng xem danh sách Job cần quản lý (Duyệt kế hoạch HOẶC duyệt bài)
app.get('/api/client/:client_id/pending-actions', async (req, res) => {
    const { client_id } = req.params;
    try {
        const { data: jobs, error: jobsError } = await supabase
            .from('jobs')
            .select('id, title, status')
            .eq('client_id', client_id)
            .in('status', ['pending_plan_approval', 'in_progress']); // Chỉ lấy job chờ duyệt plan hoặc đang chạy
            
        if (jobsError) throw jobsError;
        if (!jobs || jobs.length === 0) return res.status(200).json({ jobs: [] });

        for (let job of jobs) {
            const { data: milestones } = await supabase
                .from('milestones')
                .select('*')
                .eq('job_id', job.id)
                .order('created_at', { ascending: true });
            job.milestones = milestones || [];
        }
            
        res.status(200).json({ jobs });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 10. API: Nghiệm thu và Giải ngân (Release Escrow)
app.post('/api/escrow/release', async (req, res) => {
    const { client_id, milestone_id, amount } = req.body;
    try {
        // Lấy job_id từ milestone
        const { data: mData, error: mErr } = await supabase.from('milestones').select('job_id').eq('id', milestone_id).single();
        if (mErr) throw new Error('Không tìm thấy milestone');

        // Lấy freelancer_id từ job_applications (chỉ lấy người đã được accepted)
        const { data: appData, error: appErr } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', mData.job_id).eq('status', 'accepted').single();
        if (appErr) throw new Error('Không tìm thấy Freelancer của dự án này');

        const freelancer_id = appData.freelancer_id;

        // Lấy ví
        const { data: clientWallet, error: cwError } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        const { data: freeWallet, error: fwError } = await supabase.from('wallets').select('*').eq('user_id', freelancer_id).single();
        
        if (cwError || fwError || !clientWallet || !freeWallet) throw new Error('Lỗi truy xuất ví');
        if (clientWallet.locked_balance < amount) throw new Error('Không đủ số dư bị khóa để giải ngân');

        // Trừ locked client, cộng balance freelancer
        await supabase.from('wallets').update({ locked_balance: clientWallet.locked_balance - amount }).eq('user_id', client_id);
        await supabase.from('wallets').update({ balance: freeWallet.balance + amount }).eq('user_id', freelancer_id);

        // Đồng bộ lên Blockchain (Chuyển tiền thực tế trên Sổ cái)
        if (blockchain.isConfigured()) {
            try {
                await blockchain.transferBalance(client_id, freelancer_id, amount);
            } catch (err) {
                console.error('Lỗi khi gọi smart contract transfer:', err);
                // Bạn có thể rollback nếu cần ở môi trường thật
            }
        }

        // Cập nhật milestone thành approved
        await supabase.from('milestones').update({ status: 'approved' }).eq('id', milestone_id);

        // Ghi transaction
        await supabase.from('transactions').insert([{
            user_id: freelancer_id,
            amount: amount,
            type: 'escrow_release',
            status: 'success'
        }]);

        // Gửi thông báo cho Freelancer
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: 'Đã nhận thanh toán!',
            content: `Khách hàng đã nghiệm thu công việc và giải ngân ${amount} Token vào ví của bạn.`
        }]);

        res.status(200).json({ message: 'Giải ngân thành công! Tiền đã được chuyển cho Freelancer.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO LUỒNG ADVANCED MILESTONE (YÊU CẦU MỚI)
// ==========================================

// 11. API: Submit Milestone (Freelancer nộp bài với mảng proof_urls)
app.post('/api/milestones/advanced/submit', async (req, res) => {
    const { milestone_id, proof_urls, report_text } = req.body;
    try {
        const { data, error } = await supabase
            .from('milestones')
            .update({ 
                proof_urls: proof_urls, 
                status: 'PENDING_REVIEW' 
            })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Gửi thông báo cho Client
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', data[0].job_id).single();
        if (jobData) {
            await supabase.from('notifications').insert([{
                user_id: jobData.client_id,
                title: 'Có báo cáo công việc mới',
                content: 'Freelancer vừa nộp báo cáo (minh chứng) cho dự án. Hãy vào kiểm tra và nghiệm thu.'
            }]);
        }
        res.status(200).json({ message: 'Nộp bằng chứng thành công!', milestone: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 12. API: Request Revision (Khách hàng yêu cầu sửa lại)
app.post('/api/milestones/advanced/revision', async (req, res) => {
    const { milestone_id, feedback_text, screenshot_urls } = req.body;
    try {
        // Lưu lịch sử yêu cầu sửa
        await supabase.from('milestone_revisions').insert([{
            milestone_id, feedback_text, screenshot_urls
        }]);

        // Cập nhật trạng thái milestone về REVISION
        const { data, error } = await supabase
            .from('milestones')
            .update({ status: 'REVISION' })
            .eq('id', milestone_id)
            .select();
            
        if (error) throw error;

        // Tìm Freelancer để báo tin
        const { data: mData } = await supabase.from('milestones').select('job_id').eq('id', milestone_id).single();
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', mData.job_id).eq('status', 'accepted').single();
        
        await supabase.from('notifications').insert([{
            user_id: appData.freelancer_id,
            title: 'Yêu cầu chỉnh sửa',
            content: 'Khách hàng đã yêu cầu chỉnh sửa báo cáo của bạn. Vui lòng kiểm tra chi tiết.'
        }]);

        res.status(200).json({ message: 'Đã gửi yêu cầu chỉnh sửa cho Freelancer!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 13. API: Approve Milestone - CHUẨN CORE BANKING (ACID + Row-Level Locking)
// Sử dụng PostgreSQL Stored Function fn_release_milestone
// Chống spam bằng Idempotency Key (milestone_id là key duy nhất, không thể approve 2 lần)
app.post('/api/milestones/advanced/approve', async (req, res) => {
    const { client_id, milestone_id } = req.body;
    if (!client_id || !milestone_id) {
        return res.status(400).json({ error: 'Thiếu client_id hoặc milestone_id' });
    }

    try {
        // Lấy job_id để tìm freelancer
        const { data: mData, error: mErr } = await supabase
            .from('milestones')
            .select('job_id, status, amount')
            .eq('id', milestone_id)
            .single();
        if (mErr) throw new Error('Không tìm thấy milestone. Hãy kiểm tra milestone_id có đúng không.');

        // Chặn approve trùng ngay ở Node.js trước khi vào DB (tầng bảo vệ thứ nhất)
        if (mData.status === 'PAID') {
            return res.status(409).json({ error: 'Milestone này đã được giải ngân trước đó (status: PAID). Không thể thực hiện lần 2.' });
        }

        const { data: appData, error: appErr } = await supabase
            .from('job_applications')
            .select('freelancer_id')
            .eq('job_id', mData.job_id)
            .eq('status', 'accepted')
            .single();
        if (appErr) throw new Error('Không tìm thấy Freelancer của dự án này');

        const freelancer_id = appData.freelancer_id;

        // KIỂM TRA & TẠO VÍ CHO FREELANCER NẾU CHƯA CÓ
        // Sửa lỗi: Nếu Freelancer chưa có ví, lệnh UPDATE trong fn_release_milestone sẽ update 0 dòng (tiền biến mất)
        const { data: fWallet } = await supabase.from('wallets').select('id').eq('user_id', freelancer_id).single();
        if (!fWallet) {
            await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: 0, locked_balance: 0 }]);
        }


        // Tạo Idempotency Key duy nhất cho giao dịch này
        const idempotency_key = `RELEASE_${milestone_id}`;

        // Gọi PostgreSQL Stored Function (tầng bảo vệ thứ hai - ACID + Row-Level Lock)
        const { data: rpcResult, error: rpcError } = await supabase.rpc('fn_release_milestone', {
            p_milestone_id:     milestone_id,
            p_client_id:        client_id,
            p_freelancer_id:    freelancer_id,
            p_idempotency_key:  idempotency_key
        });

        if (rpcError) throw rpcError;

        // Hàm PostgreSQL trả về { success, message/error }
        if (!rpcResult.success) {
            return res.status(400).json({ error: rpcResult.error });
        }

        // ĐỒNG BỘ LÊN BLOCKCHAIN (WEB2.5)
        if (blockchain.isConfigured()) {
            await blockchain.transferBalance(client_id, freelancer_id, mData.amount);
        }

        // Gửi thông báo cho Freelancer sau khi giải ngân thành công
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: '💰 Đã nhận thanh toán!',
            content: `Khách hàng đã nghiệm thu. ${mData.amount} Token đã được chuyển vào ví của bạn (Blockchain Synced).`
        }]);

        // Cập nhật trạng thái job nếu tất cả milestones đã PAID
        const { data: allMilestones, error: checkErr } = await supabase
            .from('milestones')
            .select('status')
            .eq('job_id', mData.job_id);
            
        if (!checkErr && allMilestones) {
            const allPaid = allMilestones.every(m => m.status === 'PAID');
            if (allPaid) {
                await supabase.from('jobs').update({ status: 'completed' }).eq('id', mData.job_id);
            }
        }

        res.status(200).json({ 
            message: 'Nghiệm thu và giải ngân thành công!',
            detail: rpcResult.message
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO PHASE 3 (NẠP TOKEN & THÔNG BÁO & PAYOS)
// ==========================================

// API PayOS: Tạo Link Thanh Toán
app.post('/api/payment/create-payment-link', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        const orderCode = Number(String(Date.now()).slice(-6) + Math.floor(Math.random() * 1000));
        
        // Lưu vào bảng deposit_requests với payos_order_code
        const { data, error } = await supabase.from('deposit_requests').insert([{
            user_id,
            amount,
            status: 'pending',
            payos_order_code: orderCode
        }]).select('id').single();
        if (error) throw error;

        // Tạo body cho PayOS
        const requestData = {
            orderCode: orderCode,
            amount: Number(amount),
            description: `Nap Token ${orderCode}`,
            cancelUrl: `http://127.0.0.1:5500/Front_end/user/wallet.html?status=cancel`,
            returnUrl: `http://127.0.0.1:5500/Front_end/user/wallet.html?status=success`
        };

        const paymentLink = await payos.createPaymentLink(requestData);
        res.json({ checkoutUrl: paymentLink.checkoutUrl });
    } catch (error) {
        console.error('Lỗi PayOS:', error);
        res.status(500).json({ error: 'Không thể tạo link thanh toán PayOS' });
    }
});

// API PayOS: Webhook nhận tín hiệu thanh toán thành công
app.post('/api/payment/payos-webhook', async (req, res) => {
    try {
        // PayOS gửi dạng JSON body. Xác thực signature
        const webhookData = payos.verifyPaymentWebhookData(req.body);
        
        // webhookData chính là phần 'data' bên trong, ta chỉ cần kiểm tra orderCode
        if (webhookData && webhookData.orderCode) {
            const orderCode = webhookData.orderCode;
            const amount = webhookData.amount;
            
            // Tìm lệnh nạp tiền
            const { data: request, error: reqErr } = await supabase.from('deposit_requests').select('*').eq('payos_order_code', orderCode).eq('status', 'pending').single();
            if (reqErr || !request) {
                return res.json({ success: true }); // Bỏ qua nếu không tìm thấy hoặc đã xử lý
            }

            // 1. Cập nhật trạng thái
            await supabase.from('deposit_requests').update({ status: 'approved' }).eq('id', request.id);
            
            // 2. Cộng tiền cho User
            const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', request.user_id).single();
            const newBalance = wallet ? wallet.balance + amount : amount;
            
            if (wallet) {
                await supabase.from('wallets').update({ balance: newBalance }).eq('user_id', request.user_id);
            } else {
                await supabase.from('wallets').insert([{ user_id: request.user_id, balance: newBalance, locked_balance: 0 }]);
            }
            
            // 3. Ghi log transactions
            await supabase.from('transactions').insert([{
                user_id: request.user_id,
                amount: amount,
                type: 'deposit',
                status: 'success'
            }]);
            
            // 4. Gửi thông báo
            await supabase.from('notifications').insert([{
                user_id: request.user_id,
                title: 'Nạp tiền tự động thành công!',
                content: `Bạn vừa nạp thành công ${amount} Token thông qua PayOS.`
            }]);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Webhook error:', error.message);
        res.json({ success: false, error: error.message });
    }
});

// 11. API: Khách hàng tạo lệnh nạp Token (Có chống Spam)
app.post('/api/deposit', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        // Kiểm tra xem user có lệnh pending nào không
        const { data: existing } = await supabase
            .from('deposit_requests')
            .select('*')
            .eq('user_id', user_id)
            .eq('status', 'pending');
            
        if (existing && existing.length > 0) {
            // Nếu có lệnh pending, lấy luôn lệnh đó không tạo mới (ghi đè số tiền nếu muốn, hoặc báo lỗi)
            // Ở đây ta báo lỗi để client dùng lệnh cũ
            return res.status(400).json({ error: 'Bạn đang có một lệnh nạp tiền chờ xử lý. Vui lòng thanh toán hoặc chờ lệnh cũ hết hạn.' });
        }

        const { data, error } = await supabase.from('deposit_requests').insert([{ user_id, amount }]).select('id, created_at').single();
        if (error) throw error;
        
        // Tạo mã chuyển khoản từ 6 ký tự đầu của ID
        const transferCode = 'HTword ' + data.id.substring(0, 6).toUpperCase();

        res.status(200).json({ 
            message: 'Đã gửi lệnh nạp tiền. Vui lòng chờ Admin duyệt.',
            transferCode: transferCode,
            request: data
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Lấy lệnh nạp đang Pending của User
app.get('/api/deposit/pending/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('id, amount, created_at, status')
            .eq('user_id', user_id)
            .eq('status', 'pending')
            .order('created_at', { ascending: false })
            .limit(1);

        if (error) throw error;
        
        let activeRequest = null;
        if (data && data.length > 0) {
            const reqData = data[0];
            const ageMinutes = (new Date() - new Date(reqData.created_at)) / 60000;
            
            // Nếu lệnh pending quá 15 phút, tự động bỏ qua (coi như hết hạn)
            if (reqData.status === 'pending' && ageMinutes > 15) {
                // Tùy chọn: Gọi cập nhật status = 'expired' trong database
                await supabase.from('deposit_requests').update({ status: 'expired' }).eq('id', reqData.id);
            } else if (reqData.status === 'pending') {
                // Trả về lệnh nếu vẫn còn hạn pending
                activeRequest = reqData;
            }
        }

        res.status(200).json({ request: activeRequest });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Kiểm tra trạng thái của một lệnh nạp cụ thể
app.get('/api/deposit/check/:request_id', async (req, res) => {
    const { request_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('status')
            .eq('id', request_id)
            .single();

        if (error) throw error;
        res.status(200).json({ status: data.status });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 12. API: Admin lấy danh sách lệnh nạp tiền chờ duyệt
app.get('/api/admin/deposits', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('*, users(full_name, email)')
            .eq('status', 'pending')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ deposits: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 13. API: Admin duyệt nạp tiền (Chuẩn Core Banking)
app.post('/api/admin/deposits/approve', async (req, res) => {
    const { request_id, admin_id } = req.body;
    try {
        const admin_id_to_use = admin_id || '11111111-1111-1111-1111-111111111111';
        // Gọi Stored Function xử lý ACID
        const { data: rpcResult, error: rpcError } = await supabase.rpc('fn_approve_deposit', {
            p_request_id: request_id,
            p_admin_id: admin_id_to_use
        });

        if (rpcError) throw rpcError;

        if (!rpcResult.success) {
            return res.status(400).json({ error: rpcResult.error });
        }

        // Lấy thông tin user_id để gửi thông báo
        const { data: reqData } = await supabase.from('deposit_requests').select('user_id, amount').eq('id', request_id).single();

        if (reqData) {
            // ĐỒNG BỘ LÊN BLOCKCHAIN (WEB2.5)
            if (blockchain.isConfigured()) {
                await blockchain.addBalance(reqData.user_id, reqData.amount);
            }

            await supabase.from('notifications').insert([{
                user_id: reqData.user_id,
                title: '💰 Nạp Token Thành Công',
                content: `Lệnh nạp ${reqData.amount} Token của bạn đã được duyệt và cộng vào ví khả dụng.`
            }]);
        }

        res.status(200).json({ message: rpcResult.message });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Admin từ chối lệnh nạp tiền
app.post('/api/admin/deposits/reject', async (req, res) => {
    const { request_id } = req.body;
    try {
        // Cập nhật trạng thái thành 'rejected'
        const { data, error } = await supabase
            .from('deposit_requests')
            .update({ status: 'rejected' })
            .eq('id', request_id)
            .select('user_id, amount')
            .single();

        if (error) throw error;

        // Gửi thông báo cho user
        if (data) {
            await supabase.from('notifications').insert([{
                user_id: data.user_id,
                title: '❌ Lệnh Nạp Tiền Bị Từ Chối',
                content: `Lệnh nạp ${data.amount} Token của bạn đã bị từ chối. Vui lòng kiểm tra lại thông tin giao dịch.`
            }]);
        }

        res.status(200).json({ message: 'Đã từ chối lệnh nạp tiền.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 14. API: Lấy thông báo của user
app.get('/api/notifications/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('notifications')
            .select('*')
            .eq('user_id', user_id)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ notifications: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15. API: Xóa thông báo
app.delete('/api/notifications/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const { error } = await supabase.from('notifications').delete().eq('id', id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã xóa thông báo' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 16. API: Đánh dấu thông báo đã đọc
app.put('/api/notifications/:id/read', async (req, res) => {
    const { id } = req.params;
    try {
        const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', id);
        if (error) throw error;
        res.status(200).json({ message: 'Đã đánh dấu đã đọc' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15. API: Lấy thông tin ví của user
app.get('/api/wallet/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase.from('wallets').select('*').eq('user_id', user_id).single();
        if (error && error.code !== 'PGRST116') throw error; // PGRST116 = no rows returned
        
        let dbBalance = data ? data.balance : 0;
        let dbLocked = data ? data.locked_balance : 0;

        // BẢO MẬT WEB2.5: ĐỐI CHIẾU BLOCKCHAIN (SOURCE OF TRUTH)
        if (blockchain.isConfigured() && data) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance !== null) {
                // Trên blockchain, số dư = số dư khả dụng + số dư đang bị khóa (escrow)
                const expectedTotal = dbBalance + dbLocked;
                
                if (bcBalance !== expectedTotal) {
                    console.error(`[CẢNH BÁO HACK] User ${user_id} bị lệch số dư! DB: ${expectedTotal} != Blockchain: ${bcBalance}`);
                    // Cơ chế tự động sửa lỗi: Đè lại dữ liệu DB bằng Blockchain (Lấy Blockchain làm gốc)
                    // Giả định: Không thay đổi số tiền đang bị khóa, chỉ điều chỉnh lại số dư khả dụng
                    let correctedBalance = bcBalance - dbLocked;
                    if (correctedBalance < 0) {
                        correctedBalance = 0; // Nếu âm, reset về 0 (có thể escrow bị lỗi)
                    }
                    
                    await supabase.from('wallets').update({ balance: correctedBalance }).eq('user_id', user_id);
                    console.log(`[Khắc phục] Đã đồng bộ lại DB cho User ${user_id}: Balance = ${correctedBalance}`);
                    dbBalance = correctedBalance;
                }
            }
        }

        res.status(200).json({ 
            balance: dbBalance, 
            locked_balance: dbLocked,
            wallet: { ...data, balance: dbBalance, locked_balance: dbLocked } || { balance: 0, locked_balance: 0 }
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15.1 API: Lấy lịch sử giao dịch (Sổ cái) của user
app.get('/api/wallet/:user_id/transactions', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('*')
            .or(`sender_id.eq.${user_id},receiver_id.eq.${user_id}`)
            .order('created_at', { ascending: false })
            .limit(50);
            
        if (error) throw error;
        res.status(200).json({ transactions: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DEV / TESTER (DỌN DẸP VÍ)
// ==========================================
const ALLOWED_TESTERS = ['admin@htwork.com', 'hoanglubo2004@gmail.com', 'burlee2004@gmail.com'];

app.post('/api/test/reset-wallet', async (req, res) => {
    const { user_id, email } = req.body;
    try {
        if (!ALLOWED_TESTERS.includes(email)) {
            return res.status(403).json({ error: 'Truy cập bị từ chối! Bạn không nằm trong danh sách Tester.' });
        }

        // 1. Reset Database
        await supabase.from('wallets').update({ balance: 0, locked_balance: 0 }).eq('user_id', user_id);
        
        // 2. Xóa các giao dịch đang treo và Job (Escrow)
        await supabase.from('wallet_ledger').delete().or(`sender_id.eq.${user_id},receiver_id.eq.${user_id}`);
        await supabase.from('withdraw_requests').delete().eq('user_id', user_id);
        await supabase.from('jobs').delete().or(`client_id.eq.${user_id},freelancer_id.eq.${user_id}`);
        
        // 3. Reset Blockchain
        if (blockchain.isConfigured()) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance > 0) {
                await blockchain.deductBalance(user_id, bcBalance);
            }
        }

        res.status(200).json({ message: 'Đã reset toàn bộ Ví và Blockchain về 0 thành công!' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/audit/users', async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select(`
                id, email, 
                wallets (balance, locked_balance)
            `);
            
        if (error) throw error;
        
        const formatData = users.map(u => ({
            id: u.id,
            email: u.email,
            balance: u.wallets?.[0]?.balance || 0,
            locked_balance: u.wallets?.[0]?.locked_balance || 0
        }));
        
        res.status(200).json(formatData);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO VÍ (WALLET & TRANSACTIONS)
// ==========================================

// 1. Tạo lệnh rút tiền (Web2.5)
app.post('/api/withdraw', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        if (!user_id || !amount || amount <= 0) throw new Error('Dữ liệu không hợp lệ');

        // Kiểm tra thông tin ngân hàng
        const { data: user } = await supabase.from('users').select('bank_name, bank_account, bank_owner').eq('id', user_id).single();
        if (!user || !user.bank_account) {
            return res.status(400).json({ error: 'Vui lòng cập nhật tài khoản ngân hàng trong Profile trước khi rút tiền.' });
        }

        // Kiểm tra ví DB
        const { data: wallet } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', user_id).single();
        if (!wallet || wallet.balance < amount) {
            return res.status(400).json({ error: 'Không đủ số dư khả dụng để rút tiền.' });
        }

        // BẢO MẬT WEB2.5: ĐỐI CHIẾU BLOCKCHAIN
        if (blockchain.isConfigured()) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance !== null) {
                const expectedTotal = wallet.balance + wallet.locked_balance;
                if (bcBalance < expectedTotal || bcBalance < amount) {
                    return res.status(400).json({ error: '[BẢO MẬT] Lệch số dư với Blockchain. Giao dịch bị từ chối.' });
                }
            }
        }

        // Xử lý logic DB: Trừ balance, cộng locked_balance, tạo lệnh
        await supabase.from('wallets').update({ 
            balance: wallet.balance - amount,
            locked_balance: wallet.locked_balance + amount 
        }).eq('user_id', user_id);

        const { data: request, error: reqErr } = await supabase.from('withdraw_requests').insert([{
            user_id, amount, status: 'pending'
        }]).select().single();

        if (reqErr) throw reqErr;

        res.status(200).json({ message: 'Tạo lệnh rút tiền thành công. Vui lòng chờ Admin duyệt.', request });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 2. Admin lấy danh sách rút tiền
app.get('/api/admin/withdrawals', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('withdraw_requests')
            .select('*, user:users(full_name, email, bank_name, bank_account, bank_owner)')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. Admin duyệt lô (Bulk Approve)
app.post('/api/admin/withdrawals/bulk-approve', async (req, res) => {
    const { request_ids } = req.body;
    try {
        if (!request_ids || request_ids.length === 0) throw new Error('Không có lệnh nào được chọn');

        // Lấy danh sách lệnh
        const { data: requests } = await supabase.from('withdraw_requests').select('*').in('id', request_ids).eq('status', 'pending');
        
        for (let reqData of requests) {
            const user_id = reqData.user_id;
            const amount = reqData.amount;

            // Lấy ví
            const { data: wallet } = await supabase.from('wallets').select('locked_balance').eq('user_id', user_id).single();
            if (wallet) {
                // Trừ tiền tạm giữ trong DB
                await supabase.from('wallets').update({ locked_balance: wallet.locked_balance - amount }).eq('user_id', user_id);
                
                // Đồng bộ trừ Blockchain
                if (blockchain.isConfigured()) {
                    await blockchain.deductBalance(user_id, amount);
                }

                // Đổi trạng thái lệnh
                await supabase.from('withdraw_requests').update({ status: 'approved' }).eq('id', reqData.id);

                // Ghi transaction vào wallet_ledger
                await supabase.from('wallet_ledger').insert([{
                    sender_id: user_id, 
                    receiver_id: '11111111-1111-1111-1111-111111111111', 
                    amount: amount, 
                    type: 'WITHDRAW', 
                    idempotency_key: `WITHDRAW_${reqData.id}`,
                    note: 'Giải ngân rút tiền (Chuyển khoản lô)'
                }]);

                // Báo notification
                await supabase.from('notifications').insert([{
                    user_id: user_id, title: 'Tiền đã về ví!', content: `Lệnh rút ${amount} Token của bạn đã được Admin giải ngân thành công.`
                }]);
            }
        }
        res.status(200).json({ message: `Đã duyệt thành công ${requests.length} lệnh rút tiền.` });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. Admin từ chối rút tiền (Hoàn tiền)
app.post('/api/admin/withdrawals/reject', async (req, res) => {
    const { request_id } = req.body;
    try {
        const { data: reqData } = await supabase.from('withdraw_requests').select('*').eq('id', request_id).eq('status', 'pending').single();
        if (!reqData) throw new Error('Lệnh không tồn tại hoặc đã xử lý');

        const user_id = reqData.user_id;
        const amount = reqData.amount;

        const { data: wallet } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', user_id).single();
        if (wallet) {
            // Hoàn lại tiền tạm giữ về khả dụng
            await supabase.from('wallets').update({ 
                locked_balance: wallet.locked_balance - amount,
                balance: wallet.balance + amount 
            }).eq('user_id', user_id);

            await supabase.from('withdraw_requests').update({ status: 'rejected' }).eq('id', request_id);

            await supabase.from('notifications').insert([{
                user_id: user_id, title: 'Lệnh rút tiền bị từ chối', content: `Lệnh rút ${amount} Token bị từ chối. Tiền đã được hoàn lại vào ví.`
            }]);
        }
        res.status(200).json({ message: 'Đã từ chối lệnh và hoàn tiền thành công.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO LUỒNG CHAT & UPLOAD (YÊU CẦU MỚI)
// ==========================================

// Upload Ảnh (Cloudinary) - Theo yêu cầu của user giữ lại Cloudinary
app.post('/api/upload/image', (req, res) => {
    uploadImage.single('file')(req, res, function (err) {
        if (err) return res.status(500).json({ error: 'Cloudinary Error: ' + err.message });
        if (!req.file) return res.status(400).json({ error: 'Không có file ảnh' });
        res.status(200).json({ url: req.file.path, type: 'image' });
    });
});

// Upload File nặng/Video (S3)
app.post('/api/upload/file', (req, res) => {
    uploadFile.single('file')(req, res, function (err) {
        if (err) return res.status(500).json({ error: 'S3 Error: ' + err.message });
        if (!req.file) return res.status(400).json({ error: 'Không có file' });
        
        let type = 'document';
        if (req.file.mimetype.startsWith('video/')) type = 'video';
        else if (req.file.mimetype.startsWith('audio/')) type = 'audio';

        res.status(200).json({ url: req.file.location, type: type });
    });
});

// Lấy tin nhắn Chat
app.get('/api/jobs/:job_id/messages', async (req, res) => {
    const { job_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('messages')
            .select('*, users(full_name, role)')
            .eq('job_id', job_id)
            .order('created_at', { ascending: true });
        if (error) throw error;
        res.status(200).json({ messages: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Gửi tin nhắn Chat
app.post('/api/jobs/:job_id/messages', async (req, res) => {
    const { job_id } = req.params;
    const { sender_id, milestone_id, content, file_url, file_type } = req.body;
    try {
        const { data, error } = await supabase.from('messages').insert([{
            job_id, sender_id, milestone_id, content, file_url, file_type
        }]).select('*, users(full_name, role)');
        if (error) throw error;

        // Lấy thông tin user để push thông báo
        const { data: jobData } = await supabase.from('jobs').select('client_id').eq('id', job_id).single();
        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        
        if (jobData && appData) {
            const recipient_id = (sender_id === jobData.client_id) ? appData.freelancer_id : jobData.client_id;
            await supabase.from('notifications').insert([{
                user_id: recipient_id,
                title: 'Tin nhắn mới',
                content: `Bạn có tin nhắn hoặc tệp đính kèm mới trong dự án. Hãy vào phòng chat kiểm tra!`
            }]);
        }

        res.status(201).json({ message: data[0] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API TEST DEMO - ESCROW CORE BANKING
// (Dành riêng cho trang test Admin, demo bảo mật)
// ==========================================

// Lấy danh sách milestones đang PENDING_REVIEW để test
app.get('/api/test/milestones', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('milestones')
            .select('id, title, amount, status, job_id, created_at')
            .in('status', ['PENDING_REVIEW', 'FUNDED', 'PAID', 'IN_PROGRESS', 'approved'])
            .order('created_at', { ascending: false })
            .limit(10);
        if (error) throw error;
        res.status(200).json({ milestones: data });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy thông tin ví của 1 user
app.get('/api/test/wallet/:user_id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallets')
            .select('balance, locked_balance, created_at')
            .eq('user_id', req.params.user_id)
            .single();
        if (error) throw error;
        res.status(200).json({ wallet: data });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy lịch sử sổ cái của 1 milestone
app.get('/api/test/ledger/:milestone_id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('type, amount, sender_id, receiver_id, idempotency_key, created_at')
            .eq('milestone_id', req.params.milestone_id)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ ledger: data || [] });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy thông tin đầy đủ 1 milestone (kèm client_id + freelancer_id)
app.get('/api/test/milestone-detail/:milestone_id', async (req, res) => {
    try {
        const { data: ms, error: mErr } = await supabase
            .from('milestones')
            .select('id, title, amount, status, job_id, paid_at')
            .eq('id', req.params.milestone_id)
            .single();
        if (mErr) throw mErr;

        const { data: job } = await supabase.from('jobs').select('client_id').eq('id', ms.job_id).single();
        const { data: appl } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', ms.job_id).eq('status', 'accepted').single();

        res.status(200).json({
            milestone: ms,
            client_id: job ? job.client_id : null,
            freelancer_id: appl ? appl.freelancer_id : null
        });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Gọi fn_release_milestone trực tiếp với idempotency_key tùy chỉnh (cho mục đích demo)
app.post('/api/test/simulate-release', async (req, res) => {
    const { milestone_id, client_id, freelancer_id, custom_key } = req.body;
    try {
        const { data: rpc, error } = await supabase.rpc('fn_release_milestone', {
            p_milestone_id:    milestone_id,
            p_client_id:       client_id,
            p_freelancer_id:   freelancer_id,
            p_idempotency_key: custom_key || ('SIM_' + milestone_id + '_' + Date.now())
        });
        if (error) throw error;
        res.status(200).json({ result: rpc });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// 17. API: Dọn dẹp dự án cũ
app.delete('/api/jobs/cleanup/:client_id', async (req, res) => {
    const { client_id } = req.params;
    try {
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
        
        // Supabase REST không trả về count delete trực tiếp nếu không cài đặt đặc biệt, 
        // nhưng ta có thể chạy query. (Lưu ý: status 'completed' hoặc 'closed')
        const { data, error } = await supabase
            .from('jobs')
            .delete()
            .eq('client_id', client_id)
            .in('status', ['completed', 'closed'])
            .lt('created_at', oneMonthAgo.toISOString());
            
        if (error) throw error;
        res.status(200).json({ message: 'Đã dọn dẹp các dự án cũ đã hoàn thành quá 1 tháng!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// TÒA ÁN BLOCKCHAIN (DISPUTE CENTER)
// ==========================================
const fs = require('fs');
const path = require('path');
const disputesFilePath = path.join(__dirname, 'disputes.json');

// Hàm đọc/ghi DB phụ (File JSON)
function getDisputes() {
    if (fs.existsSync(disputesFilePath)) {
        return JSON.parse(fs.readFileSync(disputesFilePath, 'utf8'));
    }
    return {};
}
function saveDisputes(data) {
    fs.writeFileSync(disputesFilePath, JSON.stringify(data, null, 2));
}

// 1. Tạo Khiếu nại (Dispute)
app.post('/api/jobs/dispute', async (req, res) => {
    const { job_id, user_id, reason, evidence_url } = req.body;
    try {
        const { data, error } = await supabase.from('jobs').update({ status: 'disputed' }).eq('id', job_id);
        if (error) throw error;
        
        let disputes = getDisputes();
        disputes[job_id] = { user_id, reason, evidence_url, created_at: new Date().toISOString() };
        saveDisputes(disputes);

        res.status(200).json({ message: 'Đã gửi khiếu nại thành công. Hệ thống đã đóng băng dự án.' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 2. Lấy danh sách dự án cho Admin Giám sát & Xử lý Tranh chấp
app.get('/api/admin/projects', async (req, res) => {
    try {
        const { data: jobs, error } = await supabase.from('jobs').select('*, clients:client_id(full_name, email), milestones(*)');
        if (error) throw error;

        // Fetch applications to get freelancers for these jobs
        const { data: apps } = await supabase.from('job_applications').select('job_id, freelancer_id, freelancers:freelancer_id(full_name, email)').eq('status', 'accepted');
        
        const disputes = getDisputes();

        const fullJobs = jobs.map(j => {
            const app = (apps || []).find(a => a.job_id === j.id);
            return {
                ...j,
                freelancer: app ? app.freelancers : null,
                freelancer_id: app ? app.freelancer_id : null,
                dispute: disputes[j.id] || null
            };
        });

        res.status(200).json({ projects: fullJobs });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 3. Admin Phán Quyết Tranh Chấp (Resolve Dispute)
app.post('/api/admin/projects/resolve-dispute', async (req, res) => {
    const { job_id, winner } = req.body; // winner: 'client' | 'freelancer'
    try {
        const { data: job, error: jobErr } = await supabase.from('jobs').select('*').eq('id', job_id).single();
        if (jobErr) throw jobErr;

        const { data: appData } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', job_id).eq('status', 'accepted').single();
        if (!appData) throw new Error('Không tìm thấy Freelancer');

        const client_id = job.client_id;
        const freelancer_id = appData.freelancer_id;

        // TÍNH TOÁN SỐ TIỀN THỰC TẾ CÒN BỊ KHÓA CỦA DỰ ÁN NÀY (Tổng các Milestone chưa PAID)
        const { data: pendingMilestones } = await supabase.from('milestones').select('amount').eq('job_id', job_id).neq('status', 'PAID');
        const amount = (pendingMilestones || []).reduce((sum, m) => sum + parseFloat(m.amount || 0), 0);

        const { data: clientWallet } = await supabase.from('wallets').select('*').eq('user_id', client_id).single();
        const { data: freeWallet } = await supabase.from('wallets').select('*').eq('user_id', freelancer_id).single();

        if (clientWallet.locked_balance < amount) throw new Error(`Số dư đóng băng không khớp! Chỉ còn ${clientWallet.locked_balance} Token trong ví nhưng dự án yêu cầu xử lý ${amount} Token.`);

        if (winner === 'client') {
            // Hoàn tiền Khách Hàng (trả lại những gì chưa giải ngân)
            if (amount > 0) {
                await supabase.from('wallets').update({ 
                    locked_balance: clientWallet.locked_balance - amount,
                    balance: clientWallet.balance + amount 
                }).eq('user_id', client_id);
            }
            await supabase.from('jobs').update({ status: 'cancelled' }).eq('id', job_id);
            
        } else if (winner === 'freelancer') {
            // Ép Giải Ngân Freelancer (trả nốt những gì chưa giải ngân)
            if (amount > 0) {
                await supabase.from('wallets').update({ locked_balance: clientWallet.locked_balance - amount }).eq('user_id', client_id);
                
                // Cập nhật ví Freelancer nếu chưa có
                const currentFreeBalance = freeWallet ? freeWallet.balance : 0;
                if (!freeWallet) {
                    await supabase.from('wallets').insert([{ user_id: freelancer_id, balance: amount, locked_balance: 0 }]);
                } else {
                    await supabase.from('wallets').update({ balance: currentFreeBalance + amount }).eq('user_id', freelancer_id);
                }
                
                // ĐỒNG BỘ BLOCKCHAIN ÉP BUỘC
                if (blockchain.isConfigured()) {
                    await blockchain.transferBalance(client_id, freelancer_id, amount);
                }
                
                // Đánh dấu tất cả milestone còn lại thành PAID
                await supabase.from('milestones').update({ status: 'PAID' }).eq('job_id', job_id).neq('status', 'PAID');
            }
            await supabase.from('jobs').update({ status: 'completed' }).eq('id', job_id);
        }

        // Cleanup dispute record
        let disputes = getDisputes();
        if(disputes[job_id]) {
            delete disputes[job_id];
            saveDisputes(disputes);
        }

        res.status(200).json({ message: `Đã phán quyết thành công cho ${winner === 'client' ? 'Khách Hàng' : 'Freelancer'}!` });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Khởi chạy server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});