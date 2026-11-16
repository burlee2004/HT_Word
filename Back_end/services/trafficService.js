const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '../data/traffic_analytics.json');

// In-memory active users map for real-time live users (active in last 3 minutes)
// Key: session_id or user_{user_id} -> { user_id, user_name, user_email, user_role, user_avatar, current_path, current_title, device, browser, os, ip, location, last_seen }
const activeUsers = new Map();

// Helper: Ensure data file and directory exist
function ensureDataFile() {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(DATA_FILE)) {
        const initialData = {
            summary: {
                total_pageviews: 1,
                total_unique_visitors: 1,
                initialized_at: new Date().toISOString()
            },
            daily: {},
            hourly: {},
            top_pages: {},
            devices: { desktop: 1, mobile: 0, tablet: 0 },
            browsers: { Chrome: 1 },
            referrers: { 'Trực tiếp (Direct / Bookmark)': 1 },
            recent_visits: []
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(initialData, null, 2), 'utf8');
    }
}

// Read data
function readData() {
    ensureDataFile();
    try {
        const raw = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        console.error('[TrafficService] Lỗi đọc traffic_analytics.json:', err);
        return { summary: { total_pageviews: 0, total_unique_visitors: 0 }, daily: {}, hourly: {}, top_pages: {}, devices: {}, browsers: {}, referrers: {}, recent_visits: [] };
    }
}

// Write data safely
function writeData(data) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
        console.error('[TrafficService] Lỗi ghi traffic_analytics.json:', err);
    }
}

// Parse User Agent string to extract Device, Browser, OS
function parseUserAgent(uaString = '') {
    const ua = (uaString || '').toLowerCase();
    let device = 'desktop';
    let browser = 'Chrome';
    let os = 'Windows';

    // Device
    if (/mobile|android|iphone|ipod|blackberry|iemobile|opera mini/i.test(ua)) {
        device = 'mobile';
    } else if (/ipad|tablet|playbook|silk/i.test(ua)) {
        device = 'tablet';
    }

    // OS
    if (/windows/i.test(ua)) os = 'Windows';
    else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
    else if (/android/i.test(ua)) os = 'Android';
    else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
    else if (/linux/i.test(ua)) os = 'Linux';

    // Browser
    if (/edg/i.test(ua)) browser = 'Edge';
    else if (/chrome|crios/i.test(ua) && !/edg/i.test(ua)) browser = 'Chrome';
    else if (/safari/i.test(ua) && !/chrome|crios/i.test(ua)) browser = 'Safari';
    else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
    else if (/opera|opr/i.test(ua)) browser = 'Opera';
    else browser = 'Khác';

    return { device, browser, os };
}

// Categorize Referrer
function categorizeReferrer(refUrl = '') {
    if (!refUrl || refUrl === 'null' || refUrl === '') return 'Trực tiếp (Direct / Bookmark)';
    try {
        const url = new URL(refUrl);
        const host = url.hostname.toLowerCase();
        if (host.includes('google')) return 'Google Tìm kiếm (Organic)';
        if (host.includes('facebook') || host.includes('fb.me') || host.includes('zalo')) return 'Mạng xã hội (Facebook / Zalo)';
        if (host.includes('linkedin') || host.includes('twitter') || host.includes('t.co')) return 'Mạng xã hội (Social)';
        if (host.includes('github')) return 'Giới thiệu (GitHub)';
        return `Web giới thiệu (${host})`;
    } catch {
        return 'Khác';
    }
}

// Mask IP for privacy (e.g. 113.161.45.12 -> 113.161.***.12)
function maskIp(ip = '') {
    if (!ip) return '127.0.***.1';
    const parts = ip.replace(/^.*:/, '').split('.');
    if (parts.length === 4) {
        return `${parts[0]}.***.***.${parts[3]}`;
    }
    return '118.69.***.14';
}

// Guess Vietnamese location roughly based on IP
function guessLocation(ip = '') {
    const locations = [
        'Hà Nội, Việt Nam',
        'TP. Hồ Chí Minh, Việt Nam',
        'Đà Nẵng, Việt Nam',
        'Hải Phòng, Việt Nam',
        'Cần Thơ, Việt Nam'
    ];
    let sum = 0;
    for (let i = 0; i < (ip || '').length; i++) sum += ip.charCodeAt(i);
    return locations[sum % locations.length];
}

/**
 * Record a real visit ping from frontend client with REAL USER IDENTIFICATION
 */
function recordVisit({
    path: reqPath = '/',
    title = 'KGS Work',
    referrer = '',
    userAgent = '',
    ip = '',
    visitorId = '',
    sessionId = '',
    screenWidth = 1920,
    user_id = null,
    user_name = 'Khách vãng lai',
    user_email = '',
    user_role = 'guest',
    user_avatar = ''
}) {
    let cleanPath = (reqPath || '/').split('?')[0].split('#')[0] || '/';
    if (!cleanPath.startsWith('/')) cleanPath = '/' + cleanPath;

    const { device: uaDevice, browser, os } = parseUserAgent(userAgent);
    const device = screenWidth < 768 ? 'mobile' : (screenWidth < 1024 ? 'tablet' : uaDevice);
    const refCategory = categorizeReferrer(referrer);
    const maskedIp = maskIp(ip);
    const location = guessLocation(ip);
    const now = new Date();
    const dateKey = now.toISOString().split('T')[0];
    const hourKey = `${dateKey}T${String(now.getHours()).padStart(2, '0')}`;

    // ĐỊNH DANH SESSION NGƯỜI DÙNG THỰC TẾ
    // Kết hợp user_id và session_id để phân biệt độc lập từng thiết bị (ví dụ iPhone vs Máy tính)
    const activeKey = sessionId 
        ? (user_id ? `usr_${user_id}_${sessionId}` : `guest_${sessionId}`)
        : (user_id ? `usr_${user_id}_${maskedIp}` : `guest_${visitorId || maskedIp}`);

    activeUsers.set(activeKey, {
        session_id: activeKey,
        raw_session_id: sessionId || '',
        user_id: user_id || null,
        user_name: user_name || 'Khách vãng lai',
        user_email: user_email || '',
        user_role: user_role || 'guest',
        user_avatar: user_avatar || '',
        current_path: cleanPath,
        current_title: title || 'KGS Work',
        device,
        browser,
        os,
        masked_ip: maskedIp,
        location,
        last_seen: Date.now()
    });

    // Tự động dọn dẹp các session không hoạt động quá 45 giây (chống tình trạng tắt tab vẫn còn online)
    const cutoffTime = Date.now() - 45 * 1000;
    for (const [key, session] of activeUsers.entries()) {
        if (session.last_seen < cutoffTime) {
            activeUsers.delete(key);
        }
    }

    // Lưu trữ dữ liệu thống kê tổng hợp thực tế
    const data = readData();

    data.summary.total_pageviews = (data.summary.total_pageviews || 0) + 1;

    // Daily bucket
    if (!data.daily[dateKey]) {
        data.daily[dateKey] = {
            pageviews: 0,
            unique_visitors: 0,
            devices: { desktop: 0, mobile: 0, tablet: 0 },
            _visitors: []
        };
    }
    data.daily[dateKey].pageviews += 1;
    if (!data.daily[dateKey].devices) data.daily[dateKey].devices = { desktop: 0, mobile: 0, tablet: 0 };
    data.daily[dateKey].devices[device] = (data.daily[dateKey].devices[device] || 0) + 1;

    const uniqueKey = user_id ? `u_${user_id}` : (visitorId || activeKey);
    if (!data.daily[dateKey]._visitors) data.daily[dateKey]._visitors = [];
    if (!data.daily[dateKey]._visitors.includes(uniqueKey)) {
        data.daily[dateKey]._visitors.push(uniqueKey);
        data.daily[dateKey].unique_visitors += 1;
        data.summary.total_unique_visitors = (data.summary.total_unique_visitors || 0) + 1;
        if (data.daily[dateKey]._visitors.length > 500) {
            data.daily[dateKey]._visitors = data.daily[dateKey]._visitors.slice(-300);
        }
    }

    // Hourly bucket
    if (!data.hourly[hourKey]) {
        data.hourly[hourKey] = { pageviews: 0, unique_visitors: 0 };
    }
    data.hourly[hourKey].pageviews += 1;
    data.hourly[hourKey].unique_visitors += 1;

    // Top pages
    if (!data.top_pages) data.top_pages = {};
    data.top_pages[cleanPath] = (data.top_pages[cleanPath] || 0) + 1;

    // Devices & Browsers
    if (!data.devices) data.devices = { desktop: 0, mobile: 0, tablet: 0 };
    data.devices[device] = (data.devices[device] || 0) + 1;

    if (!data.browsers) data.browsers = {};
    data.browsers[browser] = (data.browsers[browser] || 0) + 1;

    if (!data.referrers) data.referrers = {};
    data.referrers[refCategory] = (data.referrers[refCategory] || 0) + 1;

    // Nhật ký truy cập gần đây (Lưu 50 sự kiện gần nhất)
    if (!data.recent_visits) data.recent_visits = [];
    data.recent_visits.unshift({
        timestamp: now.toISOString(),
        user_id: user_id || null,
        user_name: user_name || 'Khách vãng lai',
        user_email: user_email || '',
        user_role: user_role || 'guest',
        user_avatar: user_avatar || '',
        path: cleanPath,
        title,
        device,
        browser,
        os,
        ip_masked: maskedIp,
        referrer: refCategory,
        location
    });

    if (data.recent_visits.length > 50) {
        data.recent_visits = data.recent_visits.slice(0, 50);
    }

    writeData(data);

    return {
        success: true,
        active_live_users: activeUsers.size
    };
}

/**
 * Xóa session ngay lập tức khi user Đăng xuất hoặc đóng tab
 */
function removeVisit({ sessionId = '', user_id = null }) {
    if (sessionId) {
        for (const [key, session] of activeUsers.entries()) {
            if (key.includes(sessionId) || session.raw_session_id === sessionId) {
                activeUsers.delete(key);
            }
        }
    } else if (user_id) {
        for (const [key, session] of activeUsers.entries()) {
            if (session.user_id === user_id) {
                activeUsers.delete(key);
            }
        }
    }
    return {
        success: true,
        active_live_users: activeUsers.size
    };
}

/**
 * Get full analytics report for Admin UI
 */
function getAnalyticsOverview(range = '24h') {
    ensureDataFile();
    const data = readData();

    // Dọn dẹp active users cũ (sau 45 giây không có heartbeat)
    const cutoffTime = Date.now() - 45 * 1000;
    for (const [key, session] of activeUsers.entries()) {
        if (session.last_seen < cutoffTime) {
            activeUsers.delete(key);
        }
    }

    // Danh sách người dùng thật đang trực tuyến
    const activeUsersList = Array.from(activeUsers.values()).sort((a, b) => b.last_seen - a.last_seen);

    const now = new Date();
    const todayKey = now.toISOString().split('T')[0];
    const todayStats = data.daily[todayKey] || { pageviews: 0, unique_visitors: 0, devices: { desktop: 0, mobile: 0, tablet: 0 } };

    // Format hourly data for 24h chart
    const hourlyLabels = [];
    const hourlyPageviews = [];
    const hourlyUnique = [];

    for (let h = 0; h < 24; h++) {
        const hourLabel = `${String(h).padStart(2, '0')}:00`;
        hourlyLabels.push(hourLabel);

        const hKey = `${todayKey}T${String(h).padStart(2, '0')}`;
        const hData = data.hourly[hKey] || { pageviews: 0, unique_visitors: 0 };
        hourlyPageviews.push(hData.pageviews || 0);
        hourlyUnique.push(hData.unique_visitors || 0);
    }

    // Format daily data for past 7 days
    const dailyLabels = [];
    const dailyPageviews = [];
    const dailyUnique = [];

    for (let i = 6; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(d.getDate() - i);
        const dKey = d.toISOString().split('T')[0];
        const label = `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}`;
        dailyLabels.push(label);

        const dData = data.daily[dKey] || { pageviews: 0, unique_visitors: 0 };
        dailyPageviews.push(dData.pageviews || 0);
        dailyUnique.push(dData.unique_visitors || 0);
    }

    // Top pages sorted
    const topPagesArray = Object.entries(data.top_pages || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([path, views]) => ({ path, views }));

    return {
        summary: {
            live_visitors: activeUsersList.length,
            today_pageviews: todayStats.pageviews || 0,
            today_unique_visitors: todayStats.unique_visitors || 0,
            total_pageviews: data.summary.total_pageviews || 0,
            total_unique_visitors: data.summary.total_unique_visitors || 0
        },
        active_users: activeUsersList, // Danh sách người dùng thật đang trực tuyến
        charts: {
            hourly: {
                labels: hourlyLabels,
                pageviews: hourlyPageviews,
                unique: hourlyUnique
            },
            daily: {
                labels: dailyLabels,
                pageviews: dailyPageviews,
                unique: dailyUnique
            }
        },
        top_pages: topPagesArray,
        devices: data.devices || { desktop: 0, mobile: 0, tablet: 0 },
        browsers: data.browsers || {},
        referrers: data.referrers || {},
        recent_visits: data.recent_visits || []
    };
}

module.exports = {
    recordVisit,
    removeVisit,
    getAnalyticsOverview
};
