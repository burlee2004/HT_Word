require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');

// Import bộ khiên bảo mật đa tầng (Anti-Bot, XSS Sanitizer, Rate Limiters, CORS Whitelist)
const {
    authRateLimiter,
    publicApiRateLimiter,
    financialRateLimiter,
    antiBotMiddleware,
    xssSanitizerMiddleware,
    corsOptions
} = require('./services/securityMiddleware');

// 1. Khởi tạo Express app & Middleware toàn cục
const app = express();

// 1.1 Khiên bảo vệ HTTP Security Headers (OWASP)
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false // Cho phép nạp CDN FontAwesome, Tailwind, Google Fonts
}));

// 1.2 Siết chặt nguồn gọi API với CORS Whitelist
app.use(cors(corsOptions));

// 1.3 Chặn đứng các công cụ cào dữ liệu tự động (Anti-Scraping / Anti-Bot)
app.use(antiBotMiddleware);

// 1.4 Hỗ trợ đọc dữ liệu JSON & Base64 từ request body
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 1.5 Làm sạch dữ liệu đầu vào chống Stored XSS Injection
app.use(xssSanitizerMiddleware);

// 1.6 Áp dụng Rate Limiter cho các vùng nhạy cảm
app.use('/login', authRateLimiter);
app.use('/register', authRateLimiter);
app.use('/api/auth', authRateLimiter);
app.use('/api/jobs', publicApiRateLimiter);
app.use('/api/freelancers', publicApiRateLimiter);
app.use('/api/categories', publicApiRateLimiter);
app.use('/api/withdraw', financialRateLimiter);
app.use('/api/payment/create-deposit', financialRateLimiter);
app.use('/api/escrow/release', financialRateLimiter);

// Đảm bảo thư mục uploads tồn tại để phục vụ static files & fallback uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Fallback chuyển hướng sang Cloudinary nếu file cục bộ bị xóa trên Render
app.get('/uploads/:filename', (req, res) => {
    const filename = req.params.filename;
    console.log(`[Uploads Fallback] Redirecting to Cloudinary for file: ${filename}`);
    return res.redirect(`https://res.cloudinary.com/burlee2004/raw/upload/deliverables/${filename}`);
});

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
app.use(require('./routes/supportRoutes'));
app.use(require('./routes/connectionRoutes'));
app.use(require('./routes/testRoutes'));

// 4. Khởi chạy Server (Tích hợp AI Groq Llama 3.3 & Telegram OTP Bot)
const { initTelegramBot } = require('./services/telegramService');

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại http://localhost:${PORT}`);
    // Khởi động bot Telegram lắng nghe tin nhắn OTP
    initTelegramBot();
});
