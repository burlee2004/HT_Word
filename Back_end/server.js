require('dotenv').config();
const express = require('express');
const cors = require('cors');

// 1. Khởi tạo Express app & Middleware toàn cục
const app = express();
app.use(cors()); // Cho phép Frontend gọi API
app.use(express.json()); // Hỗ trợ đọc dữ liệu JSON từ request body

// 2. Route kiểm tra trạng thái Server
app.get('/', (req, res) => {
    res.send('HT Work Backend is running in Modular Architecture!');
});

// 3. Đăng ký (Mount) các Route Module theo từng cụm chức năng
app.use(require('./routes/authRoutes'));
app.use(require('./routes/jobRoutes'));
app.use(require('./routes/milestoneRoutes'));
app.use(require('./routes/paymentRoutes'));
app.use(require('./routes/withdrawRoutes'));
app.use(require('./routes/walletRoutes'));
app.use(require('./routes/notificationRoutes'));
app.use(require('./routes/messageRoutes'));
app.use(require('./routes/disputeRoutes'));
app.use(require('./routes/settingRoutes'));
app.use(require('./routes/categoryRoutes'));
app.use(require('./routes/reviewRoutes'));
app.use(require('./routes/aiRoutes'));
app.use(require('./routes/adminRoutes'));
app.use(require('./routes/connectionRoutes'));
app.use(require('./routes/testRoutes'));

// 4. Khởi chạy Server (Tích hợp AI Groq Llama 3.3)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
});