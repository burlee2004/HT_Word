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

        // Cập nhật trạng thái Application thành 'accepted'
        await supabase.from('job_applications').update({ status: 'accepted' }).eq('id', application_id);
        
        // Trả kết quả
        res.status(200).json({ message: 'Đã khóa tiền Escrow thành công! Dự án bắt đầu.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. Khởi động Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});