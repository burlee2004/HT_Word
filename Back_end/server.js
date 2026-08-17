require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

// Import cấu hình Upload
const uploadImage = require('./config/cloudinary');
const uploadFile = require('./config/s3');

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
// API DÀNH CHO JOBS & ESCROW (PHASE 1 MVP)
// ==========================================

// 1. API: Khách hàng đăng Job mới
app.post('/api/jobs', async (req, res) => {
    const { client_id, title, description, budget } = req.body;
    try {
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

// 4. API: Escrow - Khách hàng duyệt Freelancer và Khóa tiền
// Mô phỏng Escrow: Trừ tiền từ Ví của Client, tăng số dư Locked của Client
app.post('/api/escrow/lock', async (req, res) => {
    const { client_id, application_id, amount } = req.body;
    
    // Ghi chú tiếng Việt quan trọng:
    // Thực tế sẽ cần Transaction Database (Begin -> Commit) để tránh lỗi một phần.
    // Dưới đây là logic giả lập (Mock) cho quá trình Test đơn giản.
    try {
        // Lấy ví của Client
        const { data: wallet, error: walletError } = await supabase
            .from('wallets')
            .select('*')
            .eq('user_id', client_id)
            .single();
            
        // Nếu không có ví hoặc không đủ tiền
        if (walletError || !wallet || wallet.balance < amount) {
            return res.status(400).json({ error: 'Ví không đủ tiền hoặc chưa tồn tại!' });
        }

        // Cập nhật số dư Ví: Trừ Balance khả dụng, cộng vào Locked Balance
        const { error: updateError } = await supabase
            .from('wallets')
            .update({ 
                balance: wallet.balance - amount,
                locked_balance: wallet.locked_balance + amount 
            })
            .eq('user_id', client_id);
            
        if (updateError) throw updateError;

        // Cập nhật trạng thái Application thành 'accepted' và lấy thông tin
        const { data: updatedApp, error: appErr } = await supabase
            .from('job_applications')
            .update({ status: 'accepted' })
            .eq('id', application_id)
            .select()
            .single();
            
        if (appErr) throw appErr;

        // Đổi trạng thái Job sang in_progress
        await supabase.from('jobs').update({ status: 'in_progress' }).eq('id', updatedApp.job_id);

        // Tự động tạo 1 Milestone mặc định
        await supabase.from('milestones').insert([{
            job_id: updatedApp.job_id,
            description: 'Giai đoạn 1 (Bàn giao toàn bộ)',
            amount: amount,
            status: 'pending'
        }]);
        
        // Ghi lại lịch sử giao dịch vào bảng transactions cho Admin quản lý
        await supabase.from('transactions').insert([{
            user_id: client_id,
            amount: amount,
            type: 'escrow_lock',
            status: 'success'
        }]);

        // Gửi thông báo cho Freelancer
        await supabase.from('notifications').insert([{
            user_id: updatedApp.freelancer_id,
            title: 'Dự án đã bắt đầu',
            content: `Khách hàng đã chốt hợp đồng và khóa ${amount} Token Escrow. Bạn có thể bắt tay vào làm việc ngay!`
        }]);

        // Trả kết quả
        res.status(200).json({ message: 'Đã khóa tiền Escrow thành công! Dự án bắt đầu.' });
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

// 6. API: Admin xem toàn bộ Giao dịch và Thống kê
app.get('/api/admin/transactions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('transactions')
            .select('*, users(full_name, email, role)')
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

// 7. API: Lấy danh sách job Freelancer đang làm
app.get('/api/freelancer/:id/active-jobs', async (req, res) => {
    const { id } = req.params;
    try {
        const { data: apps, error } = await supabase
            .from('job_applications')
            .select(`
                job_id,
                jobs (id, title, description, budget, client_id)
            `)
            .eq('freelancer_id', id)
            .eq('status', 'accepted');
            
        if (error) throw error;
        if (!apps || apps.length === 0) return res.status(200).json({ jobs: [] });
        
        const jobs = apps.map(app => app.jobs);
        
        // Lấy thêm milestone cho từng job
        for (let job of jobs) {
            const { data: milestones } = await supabase
                .from('milestones')
                .select('*')
                .eq('job_id', job.id);
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

// 9. API: Khách hàng xem danh sách Milestone đang chờ duyệt
app.get('/api/client/:client_id/pending-milestones', async (req, res) => {
    const { client_id } = req.params;
    try {
        const { data: jobs, error: jobsError } = await supabase
            .from('jobs')
            .select('id, title')
            .eq('client_id', client_id);
            
        if (jobsError) throw jobsError;
        if (!jobs || jobs.length === 0) return res.status(200).json({ milestones: [] });
        const jobIds = jobs.map(j => j.id);

        const { data: milestones, error: mError } = await supabase
            .from('milestones')
            .select('*, jobs(title)')
            .in('job_id', jobIds)
            .eq('status', 'pending_review');
            
        if (mError) throw mError;
        res.status(200).json({ milestones });
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
                evidence_url: report_text, -- Tạm dùng trường cũ lưu text báo cáo
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

// 13. API: Approve Milestone (Sử dụng ACID Transaction qua PostgreSQL RPC)
app.post('/api/milestones/advanced/approve', async (req, res) => {
    const { client_id, milestone_id } = req.body;
    try {
        // Lấy thông tin job_id để tìm freelancer
        const { data: mData, error: mErr } = await supabase.from('milestones').select('job_id').eq('id', milestone_id).single();
        if (mErr) throw new Error('Không tìm thấy milestone');

        const { data: appData, error: appErr } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', mData.job_id).eq('status', 'accepted').single();
        if (appErr) throw new Error('Không tìm thấy Freelancer của dự án này');

        const freelancer_id = appData.freelancer_id;

        // Gọi hàm RPC của PostgreSQL để thực thi chuỗi lệnh ACID
        const { data, error: rpcError } = await supabase.rpc('approve_milestone_transaction', {
            p_milestone_id: milestone_id,
            p_client_id: client_id,
            p_freelancer_id: freelancer_id
        });

        if (rpcError) throw rpcError;

        // Gửi thông báo cho Freelancer
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: 'Đã nhận thanh toán!',
            content: `Khách hàng đã duyệt Milestone. Tiền đang được chuyển theo chính sách Payment Mode của dự án.`
        }]);

        res.status(200).json({ message: 'Nghiệm thu thành công và thực thi dòng tiền an toàn!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// API DÀNH CHO PHASE 3 (NẠP TOKEN & THÔNG BÁO)
// ==========================================

// 11. API: Khách hàng tạo lệnh nạp Token
app.post('/api/deposit', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        const { error } = await supabase.from('deposit_requests').insert([{ user_id, amount }]);
        if (error) throw error;
        res.status(200).json({ message: 'Đã gửi lệnh nạp tiền. Vui lòng chờ Admin duyệt.' });
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

// 13. API: Admin duyệt nạp tiền
app.post('/api/admin/deposits/approve', async (req, res) => {
    const { request_id } = req.body;
    try {
        const { data: request, error: reqErr } = await supabase.from('deposit_requests').select('*').eq('id', request_id).single();
        if (reqErr || !request) throw new Error('Không tìm thấy yêu cầu nạp tiền');

        // Lấy ví user
        const { data: wallet, error: walErr } = await supabase.from('wallets').select('*').eq('user_id', request.user_id).single();
        
        let newBalance = parseFloat(request.amount);
        if (wallet) {
            newBalance += parseFloat(wallet.balance);
            await supabase.from('wallets').update({ balance: newBalance }).eq('user_id', request.user_id);
        } else {
            await supabase.from('wallets').insert([{ user_id: request.user_id, balance: request.amount }]);
        }

        // Cập nhật trạng thái request
        await supabase.from('deposit_requests').update({ status: 'approved' }).eq('id', request_id);

        // Ghi transaction
        await supabase.from('transactions').insert([{
            user_id: request.user_id,
            amount: request.amount,
            type: 'deposit',
            status: 'success'
        }]);

        // Thông báo cho user
        await supabase.from('notifications').insert([{
            user_id: request.user_id,
            title: 'Nạp Token Thành Công',
            content: `Admin đã duyệt lệnh nạp ${request.amount} Token của bạn. Tiền đã được cộng vào ví khả dụng.`
        }]);

        res.status(200).json({ message: 'Duyệt nạp tiền thành công!' });
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
            .order('created_at', { ascending: false })
            .limit(10);
        if (error) throw error;
        res.status(200).json({ notifications: data });
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
        res.status(200).json({ wallet: data || { balance: 0, locked_balance: 0 } });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Khởi động Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});