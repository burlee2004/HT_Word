const rateLimit = require('express-rate-limit');
const { logEvent } = require('./auditLogger');

// 1. Rate Limiter cho các API Xác Thực & Đăng Nhập (Chống Brute-Force)
const authRateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 phút
    max: 15, // Tối đa 15 requests trong 10 phút trên mỗi IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Bạn đã thực hiện quá nhiều yêu cầu xác thực. Vui lòng thử lại sau 10 phút để bảo vệ tài khoản.'
    },
    handler: (req, res, next, options) => {
        logEvent({
            module: 'SECURITY',
            action: 'AUTH_RATE_LIMIT_TRIGGERED',
            level: 'WARN',
            ip: req.ip,
            details: `IP ${req.ip} bị chặn do vượt ngưỡng giới hạn đăng nhập/xác thực.`
        }).catch(() => {});
        res.status(429).json(options.message);
    }
});

// 2. Rate Limiter cho API Công Khai (Chống Bot Cào Dữ Liệu - Anti-Scraping)
const publicApiRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 phút
    max: 80, // Tối đa 80 requests/phút/IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Tần suất truy vấn dữ liệu quá nhanh. Vui lòng giảm tốc độ truy cập.'
    }
});

// 3. Rate Limiter cho API Dòng Tiền & Ký Quỹ (Chống Spam Giao Dịch)
const financialRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 phút
    max: 25, // Tối đa 25 thao tác tài chính trong 5 phút
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Thao tác tài chính quá thường xuyên. Vui lòng chờ vài phút trước khi tiếp tục giao dịch.'
    }
});

// Danh sách các User-Agent của tool cào dữ liệu độc hại
const BLOCKED_SCRAPERS = [
    'python-requests',
    'scrapy',
    'aiohttp',
    'httpclient',
    'libwww-perl',
    'wget',
    'bytespider',
    'go-http-client',
    'headlesschrome',
    'phantomjs'
];

/**
 * Middleware phát hiện và chặn đứng Crawler/Scraper/Bot tự động
 */
function antiBotMiddleware(req, res, next) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    
    // Bỏ qua cho các request nội bộ/localhost khi test nếu có header bypass
    if (req.headers['x-internal-test'] === 'htwork_trusted_testing') {
        return next();
    }

    // 1. Kiểm tra User-Agent trống (hầu hết bot tự chế không gửi User-Agent)
    if (!userAgent && req.method !== 'OPTIONS' && !req.path.startsWith('/uploads')) {
        return res.status(403).json({
            error: '[BẢO MẬT] Truy cập bị từ chối: Thiếu định danh trình duyệt hợp lệ (User-Agent Required).'
        });
    }

    // 2. Kiểm tra danh sách User-Agent của tool cào dữ liệu
    const isBot = BLOCKED_SCRAPERS.some(bot => userAgent.includes(bot));
    if (isBot) {
        logEvent({
            module: 'SECURITY',
            action: 'SCRAPER_BLOCKED',
            level: 'SECURITY',
            ip: req.ip,
            details: `Phát hiện và chặn đứng Scraper tool: "${userAgent}" truy cập "${req.originalUrl}".`
        }).catch(() => {});

        return res.status(403).json({
            error: '[BẢO MẬT] Yêu cầu bị từ chối: Công cụ tự động cào dữ liệu (Automated Scraper) không được phép truy cập sàn HT Work.'
        });
    }

    next();
}

/**
 * Hàm làm sạch ký tự độc hại XSS (Cross-Site Scripting)
 */
function cleanXssString(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Xóa thẻ script
        .replace(/javascript:/gi, '')
        .replace(/onerror\s*=/gi, '')
        .replace(/onload\s*=/gi, '')
        .replace(/onclick\s*=/gi, '');
}

/**
 * Middleware đệ quy làm sạch XSS trong req.body và req.query
 */
function xssSanitizerMiddleware(req, res, next) {
    function sanitizeObject(obj) {
        if (!obj || typeof obj !== 'object') return obj;
        for (let key in obj) {
            if (typeof obj[key] === 'string') {
                obj[key] = cleanXssString(obj[key]);
            } else if (typeof obj[key] === 'object') {
                sanitizeObject(obj[key]);
            }
        }
    }

    if (req.body) sanitizeObject(req.body);
    if (req.query) sanitizeObject(req.query);
    next();
}

/**
 * Cấu hình CORS Whitelist chặt chẽ
 */
const allowedOrigins = [
    'http://localhost:5000',
    'http://localhost:5500',
    'http://localhost:8080',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:5000',
    'https://htwork.id.vn',
    'https://www.htwork.id.vn'
];

const corsOptions = {
    origin: function (origin, callback) {
        // Cho phép các request không có origin (như mobile apps, server-to-server hoặc local dev tools)
        if (!origin) return callback(null, true);
        
        const isAllowed = allowedOrigins.includes(origin) ||
                          origin.endsWith('.netlify.app') ||
                          origin.endsWith('.onrender.com');

        if (isAllowed) {
            callback(null, true);
        } else {
            callback(new Error('[BẢO MẬT CORS] Tên miền này không có quyền truy cập API của HT Work!'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Idempotency-Key', 'x-internal-test']
};

module.exports = {
    authRateLimiter,
    publicApiRateLimiter,
    financialRateLimiter,
    antiBotMiddleware,
    xssSanitizerMiddleware,
    corsOptions
};
