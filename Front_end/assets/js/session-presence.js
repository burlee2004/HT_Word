/**
 * KGS Work - Real-time Presence & Active User Session Tracker (v6)
 * Multi-tab, multi-device, instant leave on logout/close, adblock-immune
 */
(function() {
    'use strict';
    if (window.__kgsPresenceTrackerActive) return;
    window.__kgsPresenceTrackerActive = true;

    try {
        // 1. Xác định API Backend URL
        const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
        const API_BASE = isLocal 
            ? 'http://localhost:5000' 
            : 'https://project-internship-8z76.onrender.com';

        // 2. Lấy thông tin người dùng đang đăng nhập (nếu có)
        function getCurrentUser() {
            try {
                const raw = localStorage.getItem('user');
                if (raw) return JSON.parse(raw);
            } catch(e) {}
            return null;
        }

        // 3. Mỗi Tab / Thiết bị có một Session ID độc lập tuyệt đối (iPhone, iPad, PC không bao giờ bị đè)
        let tabSessionId = sessionStorage.getItem('__kgs_tab_sid');
        if (!tabSessionId) {
            tabSessionId = 'tab_' + Math.random().toString(36).substring(2, 9) + '_' + Date.now().toString(36);
            sessionStorage.setItem('__kgs_tab_sid', tabSessionId);
        }

        let visitorId = localStorage.getItem('__kgs_vid');
        if (!visitorId) {
            visitorId = 'vid_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 8);
            localStorage.setItem('__kgs_vid', visitorId);
        }

        // 4. Hàm gửi tín hiệu hiện diện (Presence Ping - Stealth & CORS-safe)
        function sendPresencePing(isHeartbeat = false) {
            const user = getCurrentUser();

            const payload = {
                path: window.location.pathname || '/',
                title: document.title || 'KGS Work',
                referrer: document.referrer || '',
                visitor_id: visitorId,
                session_id: tabSessionId,
                is_heartbeat: isHeartbeat,
                screen_width: window.innerWidth || (window.screen ? window.screen.width : 1920),
                
                // THÔNG TIN NGƯỜI DÙNG THẬT
                user_id: user ? user.id : null,
                user_name: user ? (user.full_name || user.email) : 'Khách vãng lai',
                user_email: user ? user.email : '',
                user_role: user ? (user.role || 'user') : 'guest',
                user_avatar: user ? (user.avatar_url || '') : ''
            };

            const jsonBody = JSON.stringify(payload);

            // Gửi duy nhất đến endpoint tàng hình '/api/presence/ping' (Không bị AdBlock chặn, không sinh lỗi đỏ)
            fetch(`${API_BASE}/api/presence/ping`, {
                method: 'POST',
                mode: 'cors',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody,
                keepalive: true
            }).catch(() => {});
        }

        // 5. Hàm báo rời phiên ngay lập tức (khi Đăng xuất hoặc Đóng tab)
        function sendPresenceLeave() {
            const user = getCurrentUser();
            const leavePayload = JSON.stringify({
                session_id: tabSessionId,
                user_id: user ? user.id : null
            });

            // text/plain blob an toàn 100% khi sendBeacon lúc tắt tab
            if (navigator.sendBeacon) {
                try {
                    const blob = new Blob([leavePayload], { type: 'text/plain' });
                    navigator.sendBeacon(`${API_BASE}/api/presence/leave`, blob);
                    return;
                } catch(e) {}
            }

            fetch(`${API_BASE}/api/presence/leave`, {
                method: 'POST',
                mode: 'cors',
                headers: { 'Content-Type': 'application/json' },
                body: leavePayload,
                keepalive: true
            }).catch(() => {});
        }

        window.__kgsSendPresencePing = sendPresencePing;
        window.__kgsSendPresenceLeave = sendPresenceLeave;

        // 6. Gửi ping ngay lập tức khi file vừa nạp xong
        sendPresencePing(false);

        // 7. Gửi ping khi trang tải hoàn tất
        if (document.readyState === 'complete') {
            sendPresencePing(false);
        } else {
            window.addEventListener('load', () => sendPresencePing(false));
            document.addEventListener('DOMContentLoaded', () => sendPresencePing(false));
        }

        // 8. Bắt sự kiện chuyển tab (quay lại trang -> gửi ping; ẩn đi -> không tốn tài nguyên)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                sendPresencePing(true);
            }
        });

        // 9. Bắt sự kiện đóng tab / tắt trình duyệt -> Xóa ngay khỏi Radar
        window.addEventListener('beforeunload', sendPresenceLeave);
        window.addEventListener('pagehide', sendPresenceLeave);

        // 10. Duy trì trạng thái trực tuyến mỗi 10 giây
        setInterval(() => {
            if (!document.hidden) {
                sendPresencePing(true);
            }
        }, 10000);

    } catch (err) {
        console.warn('[PresenceTracker] Init bypassed:', err);
    }
})();
