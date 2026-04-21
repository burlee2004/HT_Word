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

// 3. API Đăng ký (/register)
app.post('/register', async (req, res) => {
    try {
        const { email, password, full_name } = req.body;

        if (!email || !password || !full_name) {
            return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin.' });
        }

        // Băm mật khẩu (Hashing) với độ khó 10 (Salt rounds)
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Lưu thông tin vào bảng users trên Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([
                { email: email, password: hashedPassword, full_name: full_name }
            ]);

        if (error) {
            // Lỗi phổ biến: Email đã tồn tại (do cài đặt Unique ở cột email)
            if (error.code === '23505') {
                return res.status(409).json({ error: 'Email này đã được sử dụng.' });
            }
            throw error;
        }

        res.status(201).json({ message: 'Đăng ký thành công!', data });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Lỗi server khi đăng ký.' });
    }
});

// 4. API Đăng nhập (/login)
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Vui lòng nhập email và mật khẩu.' });
        }

        // Lấy thông tin user từ Supabase dựa vào email
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email);

        if (error) throw error;

        // Kiểm tra xem user có tồn tại không
        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'Email hoặc mật khẩu không chính xác.' });
        }

        const user = users[0];

        // So sánh mật khẩu người dùng nhập với mật khẩu đã băm trong database
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'Email hoặc mật khẩu không chính xác.' });
        }

        // Đăng nhập thành công
        res.status(200).json({ 
            message: 'Đăng nhập thành công!',
            user: {
                id: user.id,
                email: user.email,
                full_name: user.full_name
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Lỗi server khi đăng nhập.' });
    }
});

// 5. Khởi động Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});