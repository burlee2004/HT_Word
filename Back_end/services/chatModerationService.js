const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'node_modules', '.cache', 'htwork_data');
const RULES_FILE = path.join(DATA_DIR, 'chat_moderation_rules.json');
const LEGACY_RULES_FILE = path.join(__dirname, '..', 'data', 'chat_moderation_rules.json');

// Đảm bảo file cấu hình quy tắc tồn tại
function ensureRulesFile() {
    try {
        if (!fs.existsSync(DATA_DIR)) {
            fs.mkdirSync(DATA_DIR, { recursive: true });
        }
        if (!fs.existsSync(RULES_FILE)) {
            if (fs.existsSync(LEGACY_RULES_FILE)) {
                fs.copyFileSync(LEGACY_RULES_FILE, RULES_FILE);
            } else {
                saveRules(getDefaultRules());
            }
        }
    } catch (e) {
        console.error('Lỗi khởi tạo chat_moderation_rules.json:', e.message);
    }
}

function getDefaultRules() {
    return {
        is_enabled: true,
        default_action: 'BLOCK', // BLOCK | MASK | WARN
        mask_character: '***',
        enable_pre_send_warning: true,
        categories: {
            BYPASS_SOCIAL: {
                id: 'BYPASS_SOCIAL',
                name: 'Mạng Xã Hội & Ứng Dụng Chat Ngoài',
                description: 'Ngăn chặn lôi kéo giao dịch ra ngoài sàn qua Zalo, Facebook, Telegram, WhatsApp...',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: 'Vui lòng chỉ trao đổi và giao dịch trên nền tảng HT Work để được bảo vệ quyền lợi và bảo hiểm Escrow!',
                keywords: [
                    'zalo', 'zl', 'z.a.l.o', 'za lo', 'zal0', 'za_lo',
                    'facebook', 'fb', 'face book', 'f.a.c.e.b.o.o.k', 'f.b', 'fbook', 'fb.com',
                    'tele', 'telegram', 't.e.l.e', 'tele gram', 't.me',
                    'whatsapp', 'wa', 'w.h.a.t.s.a.p.p',
                    'viber', 'skype', 'wechat', 'we chat',
                    'instagram', 'ig', 'insta',
                    'tiktok', 'tik tok', 'thread', 'threads',
                    'discord', 'zoom riêng', 'google meet riêng'
                ]
            },
            BYPASS_CONTACT: {
                id: 'BYPASS_CONTACT',
                name: 'Số Điện Thoại & Thông Tin Cá Nhân',
                description: 'Phát hiện số điện thoại, email ngoài, link liên lạc cá nhân',
                severity: 'HIGH',
                action: 'BLOCK',
                warning_message: 'Không được chia sẻ Số Điện Thoại hoặc Email cá nhân trực tiếp trong khung chat!',
                keywords: [
                    'sdt', 'sđt', 'so dien thoai', 'số điện thoại', 'phone', 'call me', 'hotline',
                    'nhắn tin số', 'add sdt', 'inbox sdt', 'lh sdt', 'liên hệ qua số', 'gọi số'
                ],
                detect_phone_regex: true,
                detect_email_regex: true,
                detect_url_regex: true
            },
            BYPASS_PAYMENT: {
                id: 'BYPASS_PAYMENT',
                name: 'Tài Khoản Ngân Hàng & Chuyển Khoản Ngoài',
                description: 'Ngăn chặn giao dịch chuyển tiền trực tiếp ngoài hệ thống ký quỹ Escrow',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: 'Nghiêm cấm chuyển khoản hoặc thanh toán riêng ngoài hệ thống Escrow!',
                keywords: [
                    'chuyen khoan ngoai', 'chuyển khoản ngoài', 'ck ngoai', 'ck ngoài',
                    'chuyen khoan rieng', 'chuyển khoản riêng', 'ck rieng', 'ck riêng',
                    'ban tien rieng', 'bắn tiền riêng', 'ban tien ngoai', 'bắn tiền ngoài',
                    'stk', 'so tai khoan', 'số tài khoản', 'so tk', 'số tk',
                    'vietcombank', 'vcb', 'techcombank', 'tcb', 'mbbank', 'mb bank',
                    'bidv', 'agribank', 'vpbank', 'tpbank', 'acb', 'sacombank', 'vib', 'vietinbank',
                    'momo', 'vi momo', 'ví momo', 'zalopay', 'zalo pay', 'vnpay',
                    'tien mat', 'tiền mặt', 'tra ngoai', 'trả ngoài', 'thanh toan ngoai', 'thanh toán ngoài'
                ]
            },
            PROFANITY: {
                id: 'PROFANITY',
                name: 'Ngôn Từ Thô Tục & Xúc Phạm',
                description: 'Lọc từ ngữ tục tĩu, chửi thề, lăng mạ hoặc xúc phạm danh dự',
                severity: 'MEDIUM',
                action: 'MASK',
                warning_message: 'Vui lòng giữ văn hóa giao tiếp lịch sự, chuyên nghiệp trên nền tảng!',
                keywords: [
                    'đm', 'dm', 'dcm', 'đcm', 'dmm', 'đmm', 'vcl', 'vkl', 'vl',
                    'cl', 'cc', 'ccl', 'cặc', 'cac', 'buồi', 'buoi', 'lồn', 'lon',
                    'mẹ mày', 'con mẹ', 'đĩ', 'chó chết', 'súc vật', 'thằng chó', 'đồ chó',
                    'fuck', 'shit', 'bitch', 'bastard', 'asshole', 'dick'
                ]
            },
            SCAM_FRAUD: {
                id: 'SCAM_FRAUD',
                name: 'Chiêu Trò Lừa Đảo & Đặt Cọc Ảo',
                description: 'Cảnh báo các hành vi lừa đảo, yêu cầu cọc tiền ngoài, nạp tiền giả mạo',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: 'Cảnh báo an ninh: Phát hiện dấu hiệu lừa đảo / yêu cầu tiền cọc ngoài sàn!',
                keywords: [
                    'lua dao', 'lừa đảo', 'scam', 'scammer', 'dat coc rieng', 'đặt cọc riêng',
                    'nap tien vao link', 'nạp tiền vào link', 'app kiem tien', 'app kiếm tiền',
                    'hoa hong cao', 'hoa hồng cao', 'lam nhiem vu', 'làm nhiệm vụ'
                ]
            },
            GAMBLING_BETTING: {
                id: 'GAMBLING_BETTING',
                name: 'Cờ Bạc, Cá Độ & Web Đánh Bài',
                description: 'Ngăn chặn tạo/thuê làm web cờ bạc, cá độ bóng đá, game bài đổi thưởng, tài xỉu, lô đề trái pháp luật',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: 'Nghiêm cấm các nội dung, dịch vụ hoặc yêu cầu làm web liên quan đến Cờ Bạc, Cá Độ, Game Bài Đổi Thưởng và Đánh Bạc bất hợp pháp!',
                keywords: [
                    'đánh bài', 'danh bai', 'game bài', 'game bai', 'tài xỉu', 'tai xiu', 'tai_xiu', 'tài_xỉu',
                    'cá độ', 'ca do', 'cá cược', 'ca cuoc', 'đặt cược', 'dat cuoc', 'kèo bóng', 'keo bong', 'bóng đá cược',
                    'lô đề', 'lo de', 'đánh đề', 'danh de', 'so de', 'số đề', 'casino', 'baccarat', 'roulette', 'blackjack',
                    'poker đổi thưởng', 'poker doi thuong', 'slot game', 'nổ hũ', 'no hu', 'kubet', 'thabet', 'sunwin',
                    'go88', 'hitclub', '789club', 'b52 club', 'rikvip', 'web cờ bạc', 'web co bac', 'làm web cờ bạc',
                    'lam web co bac', 'code game bài', 'code game bai', 'source game bài', 'source game bai',
                    'làm web đánh bài', 'lam web danh bai', 'làm web cá độ', 'lam web ca do', 'bot tài xỉu', 'tool tài xỉu',
                    'nhà cái', 'nha cai', 'đá gà', 'da ga', 'bắn cá đổi thưởng', 'ban ca doi thuong', 'cờ bạc online', 'co bac online'
                ]
            },
            MEDIA_CONTENT: {
                id: 'MEDIA_CONTENT',
                name: 'Hình Ảnh, Khiêu Dâm & Tệp Độc Hại',
                description: 'Kiểm duyệt tệp tin đính kèm và hình ảnh, ngăn chặn nội dung khiêu dâm, đồi trụy (18+ / NSFW) và mã độc thực thi',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: 'Tệp tin hoặc hình ảnh vi phạm tiêu chuẩn cộng đồng về an toàn nội dung (khiêu dâm / đồi trụy / file không an toàn)!',
                keywords: [
                    'sex', 'porn', 'xxx', '18+', 'khieudam', 'khiêu dâm', 'doitruy', 'đồi trụy', 'khoathan', 'khỏa thân',
                    'nude', 'hentai', 'clip nong', 'clip nóng', 'lo clip', 'lộ clip', 'anh nong', 'ảnh nóng', 'video sex',
                    'phim sex', 'jav', 'leak', 'gore', 'virus', 'trojan', 'keylogger', 'malware', 'hack', 'phishing',
                    'deepfake', 'bạo lực', 'chatsex', 'chat sex'
                ],
                forbidden_extensions: ['.exe', '.bat', '.cmd', '.sh', '.vbs', '.msi', '.scr', '.pif', '.com', '.jar', '.iso', '.apk'],
                max_file_size_mb: 50
            }
        },
        whitelist: [
            'htwork', 'ht work', 'escrow', 'token', 'milestone', 'hợp đồng', 'dự án',
            'github.com', 'gitlab.com', 'figma.com', 'drive.google.com', 'notion.so'
        ],
        stats: {
            total_scanned: 0,
            total_blocked: 0,
            total_masked: 0,
            total_warned: 0,
            last_violation_at: null
        }
    };
}

function loadRules() {
    ensureRulesFile();
    try {
        let rules = null;
        if (fs.existsSync(RULES_FILE)) {
            const raw = fs.readFileSync(RULES_FILE, 'utf8');
            rules = JSON.parse(raw);
        } else if (fs.existsSync(LEGACY_RULES_FILE)) {
            const raw = fs.readFileSync(LEGACY_RULES_FILE, 'utf8');
            rules = JSON.parse(raw);
        }
        if (rules) {
            // Auto-merge any missing default categories like GAMBLING_BETTING or MEDIA_CONTENT
            const defaults = getDefaultRules();
            if (!rules.categories) rules.categories = {};
            for (const [key, val] of Object.entries(defaults.categories)) {
                if (!rules.categories[key]) {
                    rules.categories[key] = val;
                }
            }
            if (!rules.whitelist) rules.whitelist = defaults.whitelist;
            return rules;
        }
    } catch (e) {
        console.error('Lỗi đọc chat_moderation_rules.json:', e.message);
    }
    return getDefaultRules();
}

function saveRules(rules) {
    try {
        ensureRulesFile();
        fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2), 'utf8');
        try {
            fs.writeFileSync(LEGACY_RULES_FILE, JSON.stringify(rules, null, 2), 'utf8');
        } catch (e) {}
    } catch (e) {
        console.error('Lỗi lưu chat_moderation_rules.json:', e.message);
    }
}

// === THUẬT TOÁN CHUẨN HÓA TIẾNG VIỆT & CHỐNG LÁCH LUẬT (ANTI-EVASION) ===
function removeVietnameseTones(str) {
    if (!str) return '';
    str = str.toLowerCase();
    str = str.replace(/à|á|ạ|ả|ã|â|ầ|ấ|ậ|ẩ|ẫ|ă|ằ|ắ|ặ|ẳ|ẵ/g, 'a');
    str = str.replace(/è|é|ẹ|ẻ|ẽ|ê|ề|ế|ệ|ể|ễ/g, 'e');
    str = str.replace(/ì|í|ị|ỉ|ĩ/g, 'i');
    str = str.replace(/ò|ó|ọ|ỏ|õ|ô|ồ|ố|ộ|ổ|ỗ|ơ|ờ|ớ|ợ|ở|ỡ/g, 'o');
    str = str.replace(/ù|ú|ụ|ủ|ũ|ư|ừ|ứ|ự|ử|ữ/g, 'u');
    str = str.replace(/ỳ|ý|ỵ|ỷ|ỹ/g, 'y');
    str = str.replace(/đ/g, 'd');
    str = str.replace(/\u0300|\u0301|\u0303|\u0309|\u0323/g, ''); // Huyền sắc hỏi ngã nặng
    str = str.replace(/\u02C6|\u0306|\u031B/g, ''); // Â, Ê, Ă, Ơ, Ư
    return str;
}

function normalizeEvasion(str) {
    if (!str) return '';
    let s = removeVietnameseTones(str);
    
    // Leetspeak translation
    s = s.replace(/@/g, 'a')
         .replace(/1/g, 'i')
         .replace(/3/g, 'e')
         .replace(/4/g, 'a')
         .replace(/5/g, 's')
         .replace(/7/g, 't')
         .replace(/\$/g, 's');

    // Chuyển các ký tự phân cách giữa các chữ cái rời rạc (z.a.l.o -> zalo, z a l o -> zalo)
    for (let i = 0; i < 4; i++) {
        s = s.replace(/(?:^|[^a-z0-9])([a-z0-9]{1,4})[\s._\-*/#@+:]{1,2}([a-z0-9])(?=[\s._\-*/#@+:]{1,2}[a-z0-9]|[^a-z0-9]|$)/gi, (m, p1, p2) => {
            return ' ' + p1 + p2;
        });
    }

    return s;
}

function checkKeywordMatch(sourceText, keyword) {
    if (!sourceText || !keyword) return false;
    const kw = keyword.trim().toLowerCase();
    if (!kw) return false;

    // Đối với từ khóa ngắn (<= 3 ký tự như 'stk', 'fb', 'đĩ', 'dm', 'vcb'), kiểm tra ranh giới từ để tránh bắt nhầm từ ghép
    if (kw.length <= 3) {
        const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const boundaryRegex = new RegExp(`(?:^|[^a-zA-Z0-9_À-ỹ])${escaped}(?:$|[^a-zA-Z0-9_À-ỹ])`, 'i');
        return boundaryRegex.test(sourceText);
    }

    // Đối với cụm từ hoặc từ dài, kiểm tra includes
    return sourceText.includes(kw);
}

// Nhận diện số điện thoại tiếng Việt (kể cả số cách nhau hoặc +84)
const VN_PHONE_REGEX = /(?:(?:\+84|84|0)(?:[3|5|7|8|9]))(?:\d[\s\.\-]?){8}\b/i;

// Nhận diện số điện thoại viết bằng chữ (vd: "không chín tám bảy...", "ko chin tam...")
const WRITTEN_NUMBER_MAP = {
    'không': '0', 'khong': '0', 'ko': '0', 'k': '0',
    'một': '1', 'mot': '1',
    'hai': '2',
    'ba': '3',
    'bốn': '4', 'bon': '4', 'tư': '4', 'tu': '4',
    'năm': '5', 'nam': '5',
    'sáu': '6', 'sau': '6',
    'bảy': '7', 'bay': '7',
    'tám': '8', 'tam': '8',
    'chín': '9', 'chin': '9'
};

function parseWrittenPhone(rawText) {
    if (!rawText) return null;
    const words = removeVietnameseTones(rawText).split(/[\s,.-]+/);
    let digitStr = '';
    for (const w of words) {
        if (WRITTEN_NUMBER_MAP[w]) {
            digitStr += WRITTEN_NUMBER_MAP[w];
        } else if (/^\d+$/.test(w)) {
            digitStr += w;
        } else {
            if (digitStr.length >= 10 && (/^(03|05|07|08|09|84)/.test(digitStr))) {
                return digitStr;
            }
            digitStr = '';
        }
    }
    if (digitStr.length >= 10 && (/^(03|05|07|08|09|84)/.test(digitStr))) {
        return digitStr;
    }
    return null;
}

// Nhận diện email ngoài
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@(?!htwork\.com)[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/i;

// Nhận diện link ngoài (trừ domain whitelist)
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s/$.?#].[^\s]*/i;

/**
 * Kiểm duyệt nội dung tin nhắn thời gian thực
 * @param {string} content - Nội dung tin nhắn cần kiểm tra
 * @returns {Object} Kết quả kiểm duyệt
 */
function moderateMessage(content) {
    if (!content || typeof content !== 'string') {
        return { is_flagged: false, sanitized_content: content || '', violations: [] };
    }

    const rules = loadRules();
    rules.stats.total_scanned++;

    if (!rules.is_enabled) {
        saveRules(rules);
        return { is_flagged: false, sanitized_content: content, violations: [] };
    }

    const raw = content.trim();
    const cleanLower = raw.toLowerCase();
    const noTone = removeVietnameseTones(raw);
    const normalized = normalizeEvasion(raw);

    const violations = [];
    let sanitized = raw;

    // 1. Kiểm tra danh sách trắng (Whitelist)
    for (const white of (rules.whitelist || [])) {
        if (cleanLower.includes(white.toLowerCase())) {
            // Có chứa từ khóa được phép
        }
    }

    // 2. Quét qua các danh mục quy tắc
    const categories = rules.categories || {};

    for (const [catKey, cat] of Object.entries(categories)) {
        let catViolated = false;
        const matchedKeywords = [];

        // 2.1 Quét từ khóa
        const keywords = cat.keywords || [];
        for (const kw of keywords) {
            const kwLower = kw.toLowerCase();
            const kwNoTone = removeVietnameseTones(kwLower);
            const kwNormalized = normalizeEvasion(kwLower);

            // Kiểm tra trong cả 3 biến thể: nguyên bản, không dấu, và chuẩn hóa chống lách luật
            const matchedRaw = checkKeywordMatch(cleanLower, kwLower);
            const matchedNoTone = checkKeywordMatch(noTone, kwNoTone);
            const matchedNorm = checkKeywordMatch(normalized, kwNormalized) || checkKeywordMatch(normalized, kwNoTone.replace(/\s+/g, ''));

            if (matchedRaw || matchedNoTone || matchedNorm) {
                catViolated = true;
                matchedKeywords.push(kw);

                // Nếu chế độ MASK, thay thế từ khóa trong chuỗi sanitized
                if (cat.action === 'MASK' || rules.default_action === 'MASK') {
                    const regexSafe = new RegExp(kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
                    sanitized = sanitized.replace(regexSafe, rules.mask_character || '***');
                }
            }
        }

        // 2.2 Quét Regex Số điện thoại (nếu được bật)
        if (cat.detect_phone_regex) {
            const phoneMatch = raw.match(VN_PHONE_REGEX);
            const writtenPhone = parseWrittenPhone(raw);
            if (phoneMatch || writtenPhone) {
                catViolated = true;
                const foundPhone = phoneMatch ? phoneMatch[0] : writtenPhone;
                matchedKeywords.push(`Số điện thoại (${foundPhone})`);
                if (cat.action === 'MASK' || rules.default_action === 'MASK') {
                    sanitized = sanitized.replace(VN_PHONE_REGEX, '[SĐT đã ẩn]');
                }
            }
        }

        // 2.3 Quét Regex Email ngoài
        if (cat.detect_email_regex) {
            const emailMatch = raw.match(EMAIL_REGEX);
            if (emailMatch) {
                // Kiểm tra xem có trong whitelist không
                const isWhitelisted = (rules.whitelist || []).some(w => emailMatch[0].toLowerCase().includes(w.toLowerCase()));
                if (!isWhitelisted) {
                    catViolated = true;
                    matchedKeywords.push(`Email (${emailMatch[0]})`);
                    if (cat.action === 'MASK' || rules.default_action === 'MASK') {
                        sanitized = sanitized.replace(EMAIL_REGEX, '[Email đã ẩn]');
                    }
                }
            }
        }

        // 2.4 Quét Regex URL ngoài
        if (cat.detect_url_regex) {
            const urlMatch = raw.match(URL_REGEX);
            if (urlMatch) {
                const isWhitelisted = (rules.whitelist || []).some(w => urlMatch[0].toLowerCase().includes(w.toLowerCase()));
                if (!isWhitelisted) {
                    catViolated = true;
                    matchedKeywords.push(`Link ngoài (${urlMatch[0]})`);
                    if (cat.action === 'MASK' || rules.default_action === 'MASK') {
                        sanitized = sanitized.replace(URL_REGEX, '[Link đã ẩn]');
                    }
                }
            }
        }

        if (catViolated) {
            violations.push({
                category_id: cat.id,
                category_name: cat.name,
                severity: cat.severity || 'HIGH',
                action: cat.action || rules.default_action,
                warning_message: cat.warning_message,
                matched_keywords: Array.from(new Set(matchedKeywords))
            });
        }
    }

    const is_flagged = violations.length > 0;

    if (is_flagged) {
        rules.stats.last_violation_at = new Date().toISOString();

        // Quyết định hành động ưu tiên cao nhất: BLOCK > MASK > WARN
        let effectiveAction = 'WARN';
        if (violations.some(v => v.action === 'BLOCK')) {
            effectiveAction = 'BLOCK';
            rules.stats.total_blocked++;
        } else if (violations.some(v => v.action === 'MASK')) {
            effectiveAction = 'MASK';
            rules.stats.total_masked++;
        } else {
            rules.stats.total_warned++;
        }

        saveRules(rules);

        const primaryViolation = violations[0];
        const allKeywords = violations.flatMap(v => v.matched_keywords).join(', ');

        return {
            is_flagged: true,
            action: effectiveAction,
            violations: violations,
            sanitized_content: sanitized,
            warning_message: primaryViolation.warning_message || 'Nội dung chứa từ khóa vi phạm quy tắc trao đổi của nền tảng!',
            matched_summary: allKeywords
        };
    }

    saveRules(rules);
    return {
        is_flagged: false,
        action: 'ALLOW',
        violations: [],
        sanitized_content: content
    };
}

// === CÁC HÀM QUẢN TRỊ CHO ADMIN (ADMIN MANAGEMENT APIs) ===
function getModerationConfig() {
    return loadRules();
}

function updateModerationConfig(newConfig) {
    const current = loadRules();
    const updated = {
        ...current,
        ...newConfig,
        stats: current.stats || {}
    };
    saveRules(updated);
    return updated;
}

function addKeywordToCategory(categoryId, keyword) {
    if (!categoryId || !keyword) return false;
    const rules = loadRules();
    if (!rules.categories[categoryId]) return false;

    const trimmed = keyword.trim().toLowerCase();
    if (!rules.categories[categoryId].keywords.includes(trimmed)) {
        rules.categories[categoryId].keywords.unshift(trimmed);
        saveRules(rules);
    }
    return rules;
}

function removeKeywordFromCategory(categoryId, keyword) {
    if (!categoryId || !keyword) return false;
    const rules = loadRules();
    if (!rules.categories[categoryId]) return false;

    const trimmed = keyword.trim().toLowerCase();
    rules.categories[categoryId].keywords = rules.categories[categoryId].keywords.filter(k => k.toLowerCase() !== trimmed);
    saveRules(rules);
    return rules;
}

function addWhitelistItem(item) {
    if (!item) return false;
    const rules = loadRules();
    const trimmed = item.trim().toLowerCase();
    if (!rules.whitelist.includes(trimmed)) {
        rules.whitelist.push(trimmed);
        saveRules(rules);
    }
    return rules;
}

function removeWhitelistItem(item) {
    if (!item) return false;
    const rules = loadRules();
    const trimmed = item.trim().toLowerCase();
    rules.whitelist = rules.whitelist.filter(w => w.toLowerCase() !== trimmed);
    saveRules(rules);
    return rules;
}

/**
 * Kiểm duyệt tệp tin đính kèm & hình ảnh (Media & Attachment Moderation)
 * @param {Object} media - { file_name, file_url, file_type, file_size, caption }
 * @returns {Object} Kết quả kiểm duyệt media
 */
function moderateMediaFile(media = {}) {
    const { file_name, file_url, file_type, file_size, caption } = media;
    const rules = loadRules();

    if (!rules.is_enabled) {
        return { is_flagged: false, action: 'ALLOW', violations: [] };
    }

    const violations = [];
    const mediaCat = rules.categories.MEDIA_CONTENT || {
        severity: 'CRITICAL',
        action: 'BLOCK',
        warning_message: 'Tệp tin hoặc hình ảnh vi phạm tiêu chuẩn cộng đồng về an toàn nội dung!',
        forbidden_extensions: ['.exe', '.bat', '.cmd', '.sh', '.vbs', '.msi', '.scr', '.pif', '.com', '.jar', '.iso', '.apk'],
        max_file_size_mb: 50
    };

    // 1. Kiểm tra phần mở rộng file độc hại / mã thực thi (Forbidden Extensions)
    if (file_name) {
        const ext = path.extname(file_name).toLowerCase();
        const forbiddenExts = mediaCat.forbidden_extensions || ['.exe', '.bat', '.cmd', '.sh', '.vbs', '.msi', '.scr', '.pif', '.com', '.jar', '.iso', '.apk'];
        if (forbiddenExts.includes(ext)) {
            violations.push({
                category_id: 'MEDIA_CONTENT',
                category_name: 'Hình Ảnh, Khiêu Dâm & Tệp Độc Hại',
                severity: 'CRITICAL',
                action: 'BLOCK',
                warning_message: `Hệ thống cấm tải lên tệp tin có định dạng thực thi nguy hiểm (${ext})!`,
                matched_keywords: [`Định dạng tệp cấm: ${ext}`]
            });
        }
    }

    // 2. Kiểm tra tên tệp tin (File Name) đối với từ khóa khiêu dâm, đồi trụy, cờ bạc, lừa đảo
    if (file_name) {
        const nameCheck = moderateMessage(file_name);
        if (nameCheck.is_flagged) {
            for (const v of nameCheck.violations) {
                violations.push({
                    ...v,
                    warning_message: `Tên tệp tin "${file_name}" chứa nội dung không an toàn hoặc từ khóa vi phạm: ${v.matched_keywords.join(', ')}`
                });
            }
        }
    }

    // 3. Kiểm tra Caption / Lời nhắn đính kèm
    if (caption) {
        const captionCheck = moderateMessage(caption);
        if (captionCheck.is_flagged) {
            for (const v of captionCheck.violations) {
                if (!violations.some(existing => existing.category_id === v.category_id)) {
                    violations.push(v);
                }
            }
        }
    }

    if (violations.length > 0) {
        let effectiveAction = 'WARN';
        if (violations.some(v => v.action === 'BLOCK' || mediaCat.action === 'BLOCK')) {
            effectiveAction = 'BLOCK';
            rules.stats.total_blocked++;
        } else if (violations.some(v => v.action === 'MASK')) {
            effectiveAction = 'MASK';
            rules.stats.total_masked++;
        } else {
            rules.stats.total_warned++;
        }

        saveRules(rules);
        const primary = violations[0];
        const allKeywords = violations.flatMap(v => v.matched_keywords).join(', ');

        return {
            is_flagged: true,
            action: effectiveAction,
            violations,
            warning_message: primary.warning_message || 'Tệp đính kèm hoặc hình ảnh vi phạm chính sách nội dung an toàn!',
            matched_summary: allKeywords
        };
    }

    return {
        is_flagged: false,
        action: 'ALLOW',
        violations: []
    };
}

// === HỆ THỐNG CẢNH BÁO VI PHẠM & TỰ ĐỘNG KHÓA TÀI KHOẢN 30 NGÀY NẾU VI PHẠM 5 LẦN ===
const VIOLATIONS_FILE = path.join(DATA_DIR, 'user_policy_violations.json');
const MAX_VIOLATION_STRIKES = 5;
const LOCKOUT_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 ngày (30 days)

function readViolationsMap() {
    try {
        if (fs.existsSync(VIOLATIONS_FILE)) {
            const raw = fs.readFileSync(VIOLATIONS_FILE, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('Lỗi đọc user_policy_violations.json:', e.message);
    }
    return {};
}

function saveViolationsMap(map) {
    try {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(VIOLATIONS_FILE, JSON.stringify(map, null, 2), 'utf8');
    } catch (e) {
        console.error('Lỗi lưu user_policy_violations.json:', e.message);
    }
}

function getUserViolationStatus(userId) {
    if (!userId) return { violation_count: 0, strikes_remaining: MAX_VIOLATION_STRIKES, is_locked: false };
    const map = readViolationsMap();
    const strId = String(userId);
    const userRecord = map[strId] || { violation_count: 0, strikes: [], is_locked: false, locked_until: null };

    // Kiểm tra nếu tài khoản đang bị khóa và đã hết hạn khóa 30 ngày chưa
    if (userRecord.is_locked && userRecord.locked_until) {
        if (new Date(userRecord.locked_until) <= new Date()) {
            // Hết hạn 30 ngày -> tự động mở khóa & reset số lần vi phạm
            userRecord.is_locked = false;
            userRecord.violation_count = 0;
            userRecord.locked_until = null;
            map[strId] = userRecord;
            saveViolationsMap(map);
        }
    }

    const strikesRemaining = Math.max(0, MAX_VIOLATION_STRIKES - (userRecord.violation_count || 0));

    return {
        violation_count: userRecord.violation_count || 0,
        max_violations: MAX_VIOLATION_STRIKES,
        strikes_remaining: strikesRemaining,
        is_locked: !!userRecord.is_locked,
        locked_until: userRecord.locked_until || null,
        history: userRecord.strikes || []
    };
}

function recordUserViolation(userId, details = {}) {
    if (!userId) return { violation_count: 0, strikes_remaining: MAX_VIOLATION_STRIKES, is_locked: false };
    const map = readViolationsMap();
    const strId = String(userId);
    const userRecord = map[strId] || { violation_count: 0, strikes: [], is_locked: false, locked_until: null };

    userRecord.violation_count = (userRecord.violation_count || 0) + 1;
    userRecord.strikes = userRecord.strikes || [];
    userRecord.strikes.push({
        timestamp: new Date().toISOString(),
        reason: details.reason || 'Vi phạm chính sách sàn',
        violations: details.violations || [],
        raw_content: details.raw_content || ''
    });

    // Nếu vi phạm đủ 5 lần -> Tự động khóa tài khoản 30 ngày
    if (userRecord.violation_count >= MAX_VIOLATION_STRIKES) {
        userRecord.is_locked = true;
        userRecord.locked_until = new Date(Date.now() + LOCKOUT_DURATION_MS).toISOString();
    }

    map[strId] = userRecord;
    saveViolationsMap(map);

    const strikesRemaining = Math.max(0, MAX_VIOLATION_STRIKES - userRecord.violation_count);

    return {
        violation_count: userRecord.violation_count,
        max_violations: MAX_VIOLATION_STRIKES,
        strikes_remaining: strikesRemaining,
        is_locked: userRecord.is_locked,
        locked_until: userRecord.locked_until
    };
}

function resetUserViolations(userId) {
    if (!userId) return false;
    const map = readViolationsMap();
    const strId = String(userId);
    if (map[strId]) {
        map[strId].violation_count = 0;
        map[strId].is_locked = false;
        map[strId].locked_until = null;
        saveViolationsMap(map);
    }
    return true;
}

function getAllViolations() {
    return readViolationsMap();
}

module.exports = {
    moderateMessage,
    moderateMediaFile,
    getUserViolationStatus,
    recordUserViolation,
    resetUserViolations,
    getAllViolations,
    getModerationConfig,
    updateModerationConfig,
    addKeywordToCategory,
    removeKeywordFromCategory,
    addWhitelistItem,
    removeWhitelistItem,
    removeVietnameseTones,
    normalizeEvasion
};

