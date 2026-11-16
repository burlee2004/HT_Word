const express = require('express');
const router = express.Router();
const trafficService = require('../services/trafficService');

// Middleware hỗ trợ CORS chuẩn & xử lý OPTIONS preflight cho các tracker/presence endpoints
const handleTrackerCors = (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }
    next();
};

router.options('/api/analytics/track', handleTrackerCors);
router.options('/api/presence/ping', handleTrackerCors);
router.options('/api/presence/heartbeat', handleTrackerCors);
router.options('/api/presence/leave', handleTrackerCors);

// Hàm dùng chung ghi nhận phiên hoạt động & lưu lượng
const processPresencePing = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');

    try {
        let payload = req.body;
        if (typeof payload === 'string') {
            try { payload = JSON.parse(payload); } catch(e) {}
        }
        if (!payload || typeof payload !== 'object') payload = {};

        const {
            path,
            title,
            referrer,
            visitor_id,
            session_id,
            screen_width,
            user_id,
            user_name,
            user_email,
            user_role,
            user_avatar
        } = payload;

        const userAgent = req.headers['user-agent'] || '';
        
        // Lấy IP của client (hỗ trợ reverse proxy / Cloudflare / Render)
        const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() 
            || req.headers['x-real-ip'] 
            || req.socket.remoteAddress 
            || '127.0.0.1';

        const result = trafficService.recordVisit({
            path: path || '/',
            title: title || 'KGS Work',
            referrer: referrer || '',
            userAgent,
            ip,
            visitorId: visitor_id || '',
            sessionId: session_id || '',
            screenWidth: parseInt(screen_width) || 1920,
            user_id: user_id || null,
            user_name: user_name || 'Khách vãng lai',
            user_email: user_email || '',
            user_role: user_role || 'guest',
            user_avatar: user_avatar || ''
        });

        // Trả về kết quả ngay lập tức (< 3ms)
        return res.status(200).json({
            success: true,
            active_live_users: result.active_live_users
        });
    } catch (error) {
        console.error('[AnalyticsRoute] Lỗi ghi nhận lượt truy cập:', error);
        return res.status(200).json({ success: false }); // Không làm lỗi trang client
    }
};

// 1. Endpoint thu thập dữ liệu truy cập từ phía client (Hỗ trợ cả endpoint tàng hình presence chống AdBlock và analytics truyền thống)
router.post('/api/presence/ping', handleTrackerCors, processPresencePing);
router.post('/api/presence/heartbeat', handleTrackerCors, processPresencePing);
router.post('/api/analytics/track', handleTrackerCors, processPresencePing);

// 1.1 Endpoint thoát phiên tức thì (khi User Đăng xuất hoặc Đóng tab)
router.post('/api/presence/leave', handleTrackerCors, (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');

    try {
        let payload = req.body;
        if (typeof payload === 'string') {
            try { payload = JSON.parse(payload); } catch(e) {}
        }
        const { session_id, user_id } = payload || {};
        const result = trafficService.removeVisit({ sessionId: session_id, user_id });
        return res.status(200).json(result);
    } catch(err) {
        return res.status(200).json({ success: false });
    }
});

// 2. Endpoint lấy toàn bộ báo cáo tổng quan dành cho Admin (Biểu đồ ngày, giờ, Top trang, thiết bị)
router.get('/api/admin/analytics/overview', (req, res) => {
    try {
        const range = req.query.range || '24h'; // '24h', '7d', '14d', '30d'
        const overview = trafficService.getAnalyticsOverview(range);
        return res.status(200).json(overview);
    } catch (error) {
        console.error('[AnalyticsRoute] Lỗi lấy báo cáo analytics:', error);
        return res.status(500).json({
            success: false,
            message: 'Lỗi máy chủ khi tạo báo cáo lưu lượng truy cập'
        });
    }
});

// 3. Endpoint lấy dữ liệu nhịp đập trực tiếp (Live pulse - cho badge nhấp nháy trên Admin)
router.get('/api/admin/analytics/live', (req, res) => {
    try {
        const overview = trafficService.getAnalyticsOverview('24h');
        return res.status(200).json({
            success: true,
            live_visitors: overview.summary.live_visitors,
            today_pageviews: overview.summary.today_pageviews,
            today_unique_visitors: overview.summary.today_unique_visitors,
            active_users: overview.active_users
        });
    } catch (error) {
        return res.status(500).json({ success: false });
    }
});

// 4. Endpoint giả lập lưu lượng truy cập test (Simulate) để Admin kiểm thử thời gian thực
router.post('/api/admin/analytics/simulate-visit', (req, res) => {
    try {
        const samplePages = [
            { path: '/', title: 'KGS Work - Trang Chủ Sàn IT Freelancer' },
            { path: '/explore-jobs.html', title: 'Khám Phá Việc Làm IT Freelance' },
            { path: '/explore-freelancers.html', title: 'Danh Sách Chuyên Gia Lập Trình Viên' },
            { path: '/how-it-works.html', title: 'Quy Trình Hoạt Động & Bảo Hộ Escrow' },
            { path: '/freelancer/home.html', title: 'Bảng Điều Khiển Freelancer' }
        ];
        const sampleDevices = ['desktop', 'mobile'];
        const sampleBrowsers = ['Chrome', 'Safari', 'Edge'];
        const sampleIps = ['113.161.45.12', '14.238.89.201', '171.244.11.89', '118.69.102.4', '42.112.55.99'];

        const randomPage = samplePages[Math.floor(Math.random() * samplePages.length)];
        const randomIp = sampleIps[Math.floor(Math.random() * sampleIps.length)];
        const randomDevice = sampleDevices[Math.floor(Math.random() * sampleDevices.length)];

        const sampleUsers = [
            { name: 'Nguyễn Văn Toàn', email: 'toan.dev@gmail.com', role: 'freelancer' },
            { name: 'Công Ty TechVina', email: 'contact@techvina.vn', role: 'client' },
            { name: 'Trần Thị Mai', email: 'maitran.uiux@gmail.com', role: 'freelancer' },
            { name: 'Khách vãng lai (Tìm việc)', email: '', role: 'guest' }
        ];
        const randomUser = sampleUsers[Math.floor(Math.random() * sampleUsers.length)];

        const result = trafficService.recordVisit({
            path: randomPage.path,
            title: randomPage.title,
            referrer: 'https://google.com/search?q=tuyen+freelancer+it',
            userAgent: randomDevice === 'mobile' ? 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            ip: randomIp,
            visitorId: 'sim_' + Math.random().toString(36).substring(2, 9),
            sessionId: 'sess_' + Math.random().toString(36).substring(2, 9),
            screenWidth: randomDevice === 'mobile' ? 390 : 1920,
            user_id: randomUser.role !== 'guest' ? 'usr_' + Math.random().toString(36).substring(2, 8) : null,
            user_name: randomUser.name,
            user_email: randomUser.email,
            user_role: randomUser.role
        });

        return res.status(200).json({
            success: true,
            message: `Đã giả lập thành công 1 lượt truy cập vào ${randomPage.path}`,
            active_live_users: result.active_live_users
        });
    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
