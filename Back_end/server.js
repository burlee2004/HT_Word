require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

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

// 5. Khởi động Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});