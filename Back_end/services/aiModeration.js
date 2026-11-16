const fs = require('fs');
const path = require('path');

const primaryModerationPath = path.join(__dirname, '..', 'data', 'job_moderation.json');
const secondaryModerationPath = path.join(__dirname, '..', 'node_modules', '.cache', 'kgs_work_data', 'job_moderation.json');

function ensureDir(filePath) {
    try {
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch (e) {}
}

function loadModerations() {
    for (const p of [primaryModerationPath, secondaryModerationPath]) {
        try {
            if (fs.existsSync(p)) {
                return JSON.parse(fs.readFileSync(p, 'utf-8'));
            }
        } catch (e) {}
    }
    return {};
}

let moderationStore = loadModerations();

function saveModerationToDisk() {
    for (const p of [primaryModerationPath, secondaryModerationPath]) {
        try {
            ensureDir(p);
            fs.writeFileSync(p, JSON.stringify(moderationStore, null, 2), 'utf-8');
        } catch (e) {}
    }
}

// Danh sách từ khóa cấm/nhạy cảm cho heuristic fallback
const BANNED_PATTERNS = [
    /cá\s*độ/i, /cờ\s*bạc/i, /lô\s*đề/i, /tài\s*xỉu/i, /nhà\s*cái/i,
    /nạp\s*tiền\s*hoa\s*hồng/i, /đa\s*cấp/i, /vay\s*nóng/i, /tín\s*dụng\s*đen/i,
    /hack\s*tài\s*khoản/i, /kéo\s*telegram/i, /bốc\s*bát\s*họ/i, /lừa\s*đảo/i
];

function fallbackHeuristicModeration(title = '', description = '') {
    const fullText = `${title} ${description}`;
    for (const pattern of BANNED_PATTERNS) {
        if (pattern.test(fullText)) {
            return {
                is_approved: false,
                score: 15,
                flagged: true,
                reason: `Phát hiện từ khóa nghi vấn / không phù hợp: "${pattern.source}"`,
                model: 'Local-Safety-Guard',
                moderated_at: new Date().toISOString()
            };
        }
    }

    // Nếu sạch từ khóa cấm
    return {
        is_approved: true,
        score: 85,
        flagged: false,
        reason: 'Nội dung hợp chuẩn tuyển dụng công nghệ IT (Bộ lọc an toàn cục bộ).',
        model: 'Local-Safety-Guard',
        moderated_at: new Date().toISOString()
    };
}

/**
 * Gọi Groq AI Llama / GPT-OSS để kiểm duyệt nội dung tin tuyển dụng
 */
async function moderateJobContent({ title = '', description = '', category_name = '' }) {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
        console.warn('⚠️ [AI Moderation] Không tìm thấy GROQ_API_KEY, chuyển sang kiểm duyệt an toàn cục bộ.');
        return fallbackHeuristicModeration(title, description);
    }

    try {
        const prompt = `Bạn là Trợ lý AI Kiểm Duyệt Tin Đăng Tuyển Dụng IT chuyên nghiệp cho sàn KGS Work.
Hãy đánh giá bài đăng sau:
- Tiêu đề: "${title}"
- Danh mục: "${category_name}"
- Mô tả chi tiết: "${description}"

Quy tắc duyệt:
1. PHÊ DUYỆT (is_approved: true, score >= 70): Bài đăng tìm lập trình viên, thiết kế, công nghệ, giải pháp phần mềm, bảo mật, dữ liệu, nội dung văn minh, nghiêm túc.
2. TỪ CHỐI / CẢNH BÁO (is_approved: false, score < 70): Bài đăng chứa nội dung cờ bạc, cá độ, đa cấp lừa đảo, nạp hoa hồng ảo, quấy rối, từ ngữ tục tĩu, mua bán tài khoản hack, nội dung không có ý nghĩa hoặc spam lặp lại.

BẮT BUỘC TRẢ VỀ DUY NHẤT 1 ĐỐI TƯỢNG JSON chuẩn định dạng sau, không kèm bất kỳ giải thích nào khác ngoài JSON:
{
  "is_approved": true hoặc false,
  "score": số điểm từ 0 đến 100,
  "reason": "Lý do ngắn gọn súc tích bằng tiếng Việt giải thích vì sao duyệt hoặc vì sao từ chối/cảnh báo"
}`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4500); // 4.5s timeout

        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            signal: controller.signal,
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'openai/gpt-oss-20b',
                messages: [
                    {
                        role: 'system',
                        content: 'You are an AI job moderation system for an IT freelancing platform. Return raw JSON only with keys: is_approved (boolean), score (number), reason (string in Vietnamese).'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.1,
                max_tokens: 250
            })
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            console.warn(`⚠️ [AI Moderation] Groq API trả về mã lỗi ${response.status}, dùng fallback.`);
            return fallbackHeuristicModeration(title, description);
        }

        const data = await response.json();
        const content = data.choices?.[0]?.message?.content || '';
        
        // Parse JSON từ phản hồi của Groq
        let parsed = null;
        try {
            parsed = JSON.parse(content);
        } catch (e) {
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                parsed = JSON.parse(jsonMatch[0]);
            }
        }

        if (parsed && typeof parsed.is_approved === 'boolean') {
            const score = typeof parsed.score === 'number' ? parsed.score : (parsed.is_approved ? 88 : 30);
            return {
                is_approved: parsed.is_approved,
                score: score,
                flagged: !parsed.is_approved,
                reason: parsed.reason || (parsed.is_approved ? 'Bài đăng chuẩn mực, đáp ứng tiêu chuẩn cộng đồng KGS Work.' : 'Bài đăng có dấu hiệu vi phạm tiêu chuẩn cộng đồng.'),
                model: 'Groq AI (GPT-OSS / Llama)',
                moderated_at: new Date().toISOString()
            };
        }

        return fallbackHeuristicModeration(title, description);
    } catch (err) {
        console.warn(`⚠️ [AI Moderation] Lỗi kết nối Groq (${err.message}), dùng fallback an toàn.`);
        return fallbackHeuristicModeration(title, description);
    }
}

const aiModeration = {
    moderateJobContent,
    getModeration: (jobId) => moderationStore[jobId] || null,
    saveModeration: (jobId, record) => {
        moderationStore[jobId] = {
            ...record,
            updated_at: new Date().toISOString()
        };
        saveModerationToDisk();
        return moderationStore[jobId];
    },
    getAllModerations: () => ({ ...moderationStore }),
    adminOverride: (jobId, { action, note = '', admin_id = null }) => {
        const current = moderationStore[jobId] || {};
        const isApproved = action === 'approve';
        moderationStore[jobId] = {
            ...current,
            is_approved: isApproved,
            score: isApproved ? 100 : 0,
            flagged: !isApproved,
            admin_overridden: true,
            admin_id: admin_id,
            reason: note || (isApproved ? 'Admin đã kiểm tra và phê duyệt thủ công.' : 'Admin đã từ chối bài đăng này.'),
            moderated_at: new Date().toISOString()
        };
        saveModerationToDisk();
        return moderationStore[jobId];
    }
};

module.exports = aiModeration;
