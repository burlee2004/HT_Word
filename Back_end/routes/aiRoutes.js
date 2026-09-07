const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const catFilePath = path.join(__dirname, '..', 'data', 'categories.json');

function getCategories() {
    try {
        if (fs.existsSync(catFilePath)) {
            return JSON.parse(fs.readFileSync(catFilePath, 'utf-8'));
        }
    } catch (e) {
        console.error('Lỗi đọc categories trong AI route:', e);
    }
    return [
        { id: "cat_web", name: "Phát triển Website & Web App" },
        { id: "cat_app", name: "Ứng dụng Di Động (Mobile App)" },
        { id: "cat_uiux", name: "Thiết kế UI/UX & Đồ Họa" },
        { id: "cat_ai", name: "Trí Tuệ Nhân Tạo & Dữ Liệu (AI/ML)" },
        { id: "cat_blockchain", name: "Blockchain, Web3 & Smart Contract" },
        { id: "cat_devops", name: "Hạ Tầng, DevOps & Sửa Lỗi" },
        { id: "cat_other", name: "Lĩnh vực Khác (Miscellaneous)" }
    ];
}

// Hàm dự phòng ngoại tuyến thông minh (Offline Heuristic Parser) - Đảm bảo 100% không bao giờ sập
function generateOfflineHeuristicJob(promptText, currentCat) {
    const p = (promptText || '').toLowerCase();
    const categories = getCategories();

    let matchedCat = categories[0];
    if (p.includes('app') || p.includes('mobile') || p.includes('flutter') || p.includes('ios') || p.includes('android') || p.includes('react native')) {
        matchedCat = categories.find(c => c.id === 'cat_app') || matchedCat;
    } else if (p.includes('ui') || p.includes('ux') || p.includes('figma') || p.includes('thiết kế') || p.includes('design') || p.includes('logo') || p.includes('banner')) {
        matchedCat = categories.find(c => c.id === 'cat_uiux') || matchedCat;
    } else if (p.includes('ai') || p.includes('gpt') || p.includes('bot') || p.includes('chatbot') || p.includes('dữ liệu') || p.includes('machine learning') || p.includes('openai')) {
        matchedCat = categories.find(c => c.id === 'cat_ai') || matchedCat;
    } else if (p.includes('smart contract') || p.includes('web3') || p.includes('solidity') || p.includes('crypto') || p.includes('blockchain') || p.includes('dapp') || p.includes('metamask')) {
        matchedCat = categories.find(c => c.id === 'cat_blockchain') || matchedCat;
    } else if (p.includes('devops') || p.includes('vps') || p.includes('docker') || p.includes('fix bug') || p.includes('sửa lỗi') || p.includes('bảo mật') || p.includes('tối ưu')) {
        matchedCat = categories.find(c => c.id === 'cat_devops') || matchedCat;
    } else if (p.includes('web') || p.includes('website') || p.includes('bán hàng') || p.includes('landing') || p.includes('frontend') || p.includes('backend') || p.includes('fullstack')) {
        matchedCat = categories.find(c => c.id === 'cat_web') || matchedCat;
    } else if (currentCat) {
        const found = categories.find(c => c.id === currentCat || c.name.toLowerCase() === currentCat.toLowerCase());
        if (found) matchedCat = found;
    }

    // Trích xuất số ngày deadline nếu có
    let deadlineDays = 7;
    const dayMatch = p.match(/(\d+)\s*(ngày|day|hôm)/);
    const weekMatch = p.match(/(\d+)\s*(tuần|week)/);
    const monthMatch = p.match(/(\d+)\s*(tháng|month)/);
    if (dayMatch) deadlineDays = parseInt(dayMatch[1]);
    else if (weekMatch) deadlineDays = parseInt(weekMatch[1]) * 7;
    else if (monthMatch) deadlineDays = parseInt(monthMatch[1]) * 30;

    // Trích xuất ngân sách nếu có
    let budget = 300000;
    const budgetKMatch = p.match(/(\d+)\s*(k|nghìn|ngàn)/);
    const budgetTrMatch = p.match(/(\d+([.,]\d+)?)\s*(triệu|tr|m)/);
    const budgetNumMatch = p.match(/(\d{5,8})/);
    if (budgetTrMatch) budget = Math.round(parseFloat(budgetTrMatch[1].replace(',', '.')) * 100000);
    else if (budgetKMatch) budget = parseInt(budgetKMatch[1]) * 1000;
    else if (budgetNumMatch) budget = parseInt(budgetNumMatch[1]);

    const titleWords = promptText.replace(/tôi cần|tôi muốn|hãy giúp tôi|cần làm|thuê|tìm/gi, '').trim();
    const cleanTitle = titleWords.length > 5 
        ? titleWords.charAt(0).toUpperCase() + titleWords.slice(1)
        : `Dự án ${matchedCat.name}`;

    return {
        title: cleanTitle.length > 70 ? cleanTitle.substring(0, 70) + '...' : cleanTitle,
        category_id: matchedCat.id,
        category_name: matchedCat.name,
        description: `🎯 [MỤC TIÊU DỰ ÁN]
Triển khai xây dựng sản phẩm: ${cleanTitle}. Yêu cầu chất lượng cao, chuẩn quy trình chuyên nghiệp trên nền tảng HT Work.

⚙️ [YÊU CẦU CHỨC NĂNG CHÍNH]
1. Xây dựng giao diện hiện đại, chuẩn UI/UX, hỗ trợ Responsive đầy đủ trên Mobile & Desktop.
2. Xử lý luồng dữ liệu mượt mà, tối ưu hiệu năng và thời gian phản hồi.
3. Tích hợp đầy đủ các chức năng theo mô tả: ${promptText}.
4. Đảm bảo tính bảo mật và dễ bảo trì, mở rộng trong tương lai.

💻 [YÊU CẦU KỸ THUẬT & CÔNG NGHỆ]
- Sử dụng các công nghệ tiêu chuẩn hiện đại, code sạch, có comment rõ ràng.
- Đảm bảo mã nguồn chạy ổn định, không phát sinh lỗi nghiêm trọng.

📦 [TIÊU CHUẨN NGHIỆM THU & BÀN GIAO]
- Bàn giao đầy đủ mã nguồn (Source code) và tài liệu hướng dẫn cài đặt.
- Hỗ trợ bảo hành và giải đáp thắc mắc sau khi bàn giao dự án.`,
        tags: matchedCat.tags_preset || ['ReactJS', 'NodeJS', 'TypeScript'],
        freelancer_type: 'Cá nhân',
        deadline_days: deadlineDays,
        estimated_budget: budget,
        ai_summary: `Trợ lý AI đã phân tích yêu cầu "${promptText}" và tự động chuẩn hóa thành dự án thuộc lĩnh vực [${matchedCat.name}].`,
        source: 'heuristic_fallback'
    };
}

// 1. API: Trợ Lý AI Gợi Ý & Soạn Thảo Dự Án (Groq AI + 3-Tier Failover)
router.post('/api/ai/suggest-job', async (req, res) => {
    const { prompt, current_category } = req.body;

    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
        return res.status(400).json({ error: 'Vui lòng nhập mô tả hoặc yêu cầu dự án để AI tư vấn!' });
    }

    const categories = getCategories();
    const catListText = categories.map(c => `- id: "${c.id}", name: "${c.name}", mô tả: "${c.description || ''}"`).join('\n');

    const systemPrompt = `Bạn là Trợ lý AI Quản lý Dự án Công nghệ Cấp cao của sàn Freelance IT "HT Work".
Nhiệm vụ của bạn: Đọc mô tả hoặc yêu cầu của khách hàng (bằng văn nói hoặc văn viết) và chuẩn hóa thành một ĐẶC TẢ DỰ ÁN HOÀN CHỈNH, CHUYÊN NGHIỆP để đăng tuyển Freelancer.

Danh mục dự án hợp lệ trên sàn:
${catListText}

BẠN PHẢI TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON HỢP LỆ (KHÔNG THÊM BẤT KỲ VĂN BẢN NÀO NGOÀI JSON) THEO CẤU TRÚC SAU:
{
  "title": "Tiêu đề dự án ngắn gọn, thu hút, đúng trọng tâm (tối đa 70 ký tự)",
  "category_id": "Một trong các id hợp lệ ở danh sách trên (vd: cat_web, cat_app, cat_uiux, cat_ai, cat_blockchain, cat_devops, cat_other)",
  "category_name": "Tên tương ứng của category_id",
  "description": "Bản mô tả chi tiết được chia làm 4 phần rõ ràng:\\n🎯 [MỤC TIÊU DỰ ÁN]\\n...\\n⚙️ [YÊU CẦU CHỨC NĂNG CHÍNH]\\n1. ...\\n2. ...\\n\\n💻 [YÊU CẦU KỸ THUẬT & CÔNG NGHỆ]\\n- ...\\n\\n📦 [TIÊU CHUẨN NGHIỆM THU & BÀN GIAO]\\n- ...",
  "tags": ["3 đến 6 tags công nghệ ngắn gọn, vd: ReactJS, NodeJS, Figma, Solidity"],
  "freelancer_type": "Cá nhân hoặc Đội nhóm/Agency",
  "deadline_days": 7,
  "estimated_budget": 300000,
  "ai_summary": "1-2 câu tóm tắt tư vấn thân thiện cho khách hàng về dự án này"
}`;

    const userPrompt = `Yêu cầu từ khách hàng: "${prompt.trim()}"${currentCatHint(current_category, categories)}`;

    function currentCatHint(catId, cats) {
        if (!catId) return '';
        const found = cats.find(c => c.id === catId);
        return found ? `\n(Khách hàng đang ưu tiên danh mục: "${found.name}")` : '';
    }

    console.log(`\n🔮 [API POST /api/ai/suggest-job] Yêu cầu AI tư vấn: "${prompt.trim().substring(0, 60)}..."`);

    // TẦNG 1: GỌI GROQ API (Qwen 3.8 27B - Siêu thông minh & tối ưu tiếng Việt)
    const groqKey = process.env.GROQ_API_KEY ? process.env.GROQ_API_KEY.trim() : '';
    console.log('🔑 [AI Tier 1] GROQ_API_KEY hiện tại:', groqKey ? (groqKey.substring(0, 10) + '... (độ dài: ' + groqKey.length + ')') : 'CHƯA CÓ');
    if (groqKey && !groqKey.includes('YOUR_GROQ_KEY')) {
        try {
            console.log('⚡ [AI Tier 1] Đang gọi Groq API (qwen/qwen3.8-27b)...');
            const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${groqKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'qwen/qwen3.8-27b',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt }
                    ],
                    response_format: { type: 'json_object' },
                    temperature: 0.2,
                    max_tokens: 1500
                })
            });

            if (groqResponse.ok) {
                const data = await groqResponse.json();
                const contentStr = data.choices?.[0]?.message?.content;
                if (contentStr) {
                    const parsed = JSON.parse(contentStr);
                    const sanitized = sanitizeAiJobData(parsed, categories);
                    return res.status(200).json({
                        success: true,
                        source: 'groq_qwen3.8',
                        job: sanitized,
                        data: sanitized
                    });
                }
            } else {
                const errBody = await groqResponse.text();
                console.warn(`⚠️ [AI Tier 1] Groq API trả về mã lỗi ${groqResponse.status}:`, errBody);
            }
        } catch (groqErr) {
            console.warn('⚠️ [AI Tier 1] Lỗi kết nối Groq API:', groqErr.message);
        }
    } else {
        console.warn('⚠️ [AI Tier 1] Chưa cấu hình GROQ_API_KEY hợp lệ trong .env');
    }

    // TẦNG 2: THỬ MODEL GROQ PHỤ (qwen/qwen3.6-27b hoặc openai/gpt-oss-120b) NẾU TẦNG 1 BỊ GIỚI HẠN
    if (groqKey && !groqKey.includes('YOUR_GROQ_KEY')) {
        try {
            console.log('⚡ [AI Tier 2] Đang thử Groq backup model (qwen/qwen3.6-27b)...');
            const backupResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${groqKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'qwen/qwen3.6-27b',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt }
                    ],
                    response_format: { type: 'json_object' },
                    temperature: 0.2,
                    max_tokens: 1500
                })
            });

            if (backupResponse.ok) {
                const data = await backupResponse.json();
                const contentStr = data.choices?.[0]?.message?.content;
                if (contentStr) {
                    const parsed = JSON.parse(contentStr);
                    console.log('✅ [AI Tier 2] Groq Qwen3.6 phản hồi thành công:', parsed.title);
                    const sanitized = sanitizeAiJobData(parsed, categories);
                    return res.status(200).json({
                        success: true,
                        source: 'groq_qwen3.6',
                        job: sanitized,
                        data: sanitized
                    });
                }
            }
        } catch (tier2Err) {
            console.warn('⚠️ [AI Tier 2] Lỗi Groq Tier 2:', tier2Err.message);
        }
    }

    // TẦNG 3: OFFLINE HEURISTIC PARSER (Đảm bảo 100% không bao giờ gián đoạn)
    console.log('🛡️ [AI Tier 3] Kích hoạt Bộ Phân Tích Thông Minh Dự Phòng Ngoại Tuyến (Offline Failover)...');
    const fallbackData = generateOfflineHeuristicJob(prompt, current_category);
    return res.status(200).json({
        success: true,
        source: 'heuristic_fallback',
        job: fallbackData,
        data: fallbackData
    });
});

function sanitizeAiJobData(parsed, categories) {
    let catId = parsed.category_id;
    let validCat = categories.find(c => c.id === catId);
    if (!validCat) {
        validCat = categories.find(c => c.name.toLowerCase().includes((parsed.category_name || '').toLowerCase())) || categories[0];
        catId = validCat.id;
    }

    return {
        title: parsed.title || 'Dự án Phát Triển Phần Mềm',
        category_id: validCat.id,
        category_name: validCat.name,
        description: parsed.description || 'Chi tiết yêu cầu dự án.',
        tags: Array.isArray(parsed.tags) ? parsed.tags : ['ReactJS', 'NodeJS'],
        freelancer_type: parsed.freelancer_type === 'Đội nhóm/Agency' ? 'Đội nhóm/Agency' : 'Cá nhân',
        deadline_days: parseInt(parsed.deadline_days) || 7,
        estimated_budget: parseInt(parsed.estimated_budget) || 300000,
        ai_summary: parsed.ai_summary || 'Dự án đã được phân tích và tối ưu bởi AI.'
    };
}

// 2. API: Trợ Lý AI Viết Đề Xuất Ứng Tuyển / Cover Letter Cho Freelancer (Groq AI + Failover)
router.post('/api/ai/suggest-proposal', async (req, res) => {
    const { job_title, job_description, category_name, job_budget, freelancer_skills, freelancer_name } = req.body;

    if (!job_title && !job_description) {
        return res.status(400).json({ error: 'Thiếu thông tin dự án để AI viết đề xuất!' });
    }

    const flName = freelancer_name || 'Freelancer';
    const flSkills = freelancer_skills || 'Fullstack Developer, UI/UX, Git';
    const budgetVal = parseFloat(job_budget) || 300000;
    const suggestedBid = Math.round(budgetVal * 0.95); // Chào thầu hợp lý ~95% ngân sách

    const systemPrompt = `Bạn là Trợ lý AI Cố vấn Đấu thầu & Soạn thảo Đề xuất chuyên nghiệp của sàn Freelance IT "HT Work".
Nhiệm vụ của bạn: Giúp Freelancer tên "${flName}" soạn một BỨC THƯ ỨNG TUYỂN (COVER LETTER / PROPOSAL) CỰC KỲ CHUYÊN NGHIỆP, THUYẾT PHỤC VÀ TẬP TRUNG ĐÚNG VÀO YÊU CẦU DỰ ÁN CỦA KHÁCH HÀNG.

Cấu trúc Cover Letter tiêu chuẩn:
1. Lời chào trang trọng & Bày tỏ sự quan tâm chính xác vào dự án.
2. Nêu bật kinh nghiệm, kỹ năng phù hợp nhất với yêu cầu kỹ thuật của bài đăng.
3. Kế hoạch triển khai & giải pháp kỹ thuật ngắn gọn (các bước rõ ràng).
4. Cam kết chất lượng, bảo mật, nghiệm thu đúng hạn và bảo hành sau bàn giao.
5. Lời kêu gọi hành động (Call to action) thân thiện, sẵn sàng trao đổi chi tiết.

BẠN PHẢI TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON HỢP LỆ THEO CẤU TRÚC:
{
  "cover_letter": "Nội dung thư ứng tuyển hoàn chỉnh, ngắt dòng đẹp mắt bằng \\n\\n",
  "suggested_bid": ${suggestedBid},
  "suggested_days": 7,
  "key_highlights": ["3 điểm mạnh nổi bật, ví dụ: 'Kinh nghiệm 3+ năm React/NodeJS', 'Cam kết bàn giao đúng hạn 100%'"]
}`;

    const userPrompt = `Dự án cần ứng tuyển:
- Tiêu đề: "${job_title || 'Dự án'}"
- Lĩnh vực: "${category_name || 'Công nghệ thông tin'}"
- Ngân sách khách hàng: ${budgetVal} Token
- Yêu cầu chi tiết:
${(job_description || '').substring(0, 1000)}

Thông tin Freelancer:
- Họ tên: ${flName}
- Kỹ năng thế mạnh: ${flSkills}`;

    console.log(`\n🔮 [API POST /api/ai/suggest-proposal] Freelancer "${flName}" yêu cầu AI viết đề xuất cho job: "${job_title}"`);

    const groqKey = process.env.GROQ_API_KEY ? process.env.GROQ_API_KEY.trim() : '';

    // TẦNG 1: GROQ Qwen 3.8 27B
    if (groqKey && !groqKey.includes('YOUR_GROQ_KEY')) {
        try {
            console.log('⚡ [AI Proposal Tier 1] Đang gọi Groq API (qwen/qwen3.8-27b)...');
            const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${groqKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'qwen/qwen3.8-27b',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt }
                    ],
                    response_format: { type: 'json_object' },
                    temperature: 0.3,
                    max_tokens: 1200
                })
            });

            if (groqRes.ok) {
                const data = await groqRes.json();
                const contentStr = data.choices?.[0]?.message?.content;
                if (contentStr) {
                    const parsed = JSON.parse(contentStr);
                    console.log('✅ [AI Proposal Tier 1] Groq sinh đề xuất thành công!');
                    return res.status(200).json({
                        success: true,
                        source: 'groq_qwen3.8',
                        proposal: parsed
                    });
                }
            } else {
                console.warn(`⚠️ [AI Proposal Tier 1] Groq API lỗi ${groqRes.status}`);
            }
        } catch (e) {
            console.warn('⚠️ [AI Proposal Tier 1] Lỗi kết nối Groq:', e.message);
        }
    }

    // TẦNG 2: GROQ Qwen 3.6 27B backup
    if (groqKey && !groqKey.includes('YOUR_GROQ_KEY')) {
        try {
            console.log('⚡ [AI Proposal Tier 2] Đang thử Groq backup model (qwen/qwen3.6-27b)...');
            const backupRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${groqKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'qwen/qwen3.6-27b',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userPrompt }
                    ],
                    response_format: { type: 'json_object' },
                    temperature: 0.3,
                    max_tokens: 1200
                })
            });

            if (backupRes.ok) {
                const data = await backupRes.json();
                const contentStr = data.choices?.[0]?.message?.content;
                if (contentStr) {
                    const parsed = JSON.parse(contentStr);
                    console.log('✅ [AI Proposal Tier 2] Groq backup sinh đề xuất thành công!');
                    return res.status(200).json({
                        success: true,
                        source: 'groq_qwen3.6',
                        proposal: parsed
                    });
                }
            }
        } catch (e) {
            console.warn('⚠️ [AI Proposal Tier 2] Lỗi kết nối:', e.message);
        }
    }

    // TẦNG 3: OFFLINE HEURISTIC PROPOSAL (Không bao giờ lỗi)
    console.log('🛡️ [AI Proposal Tier 3] Kích hoạt Offline Heuristic Proposal Generator...');
    const offlineLetter = `Kính gửi Quý Khách hàng,

Tôi là ${flName}, một Freelancer chuyên sâu trong lĩnh vực ${category_name || 'Phát triển Phần mềm & CNTT'}. Tôi đã đọc kỹ yêu cầu dự án "${job_title}" và rất tự tin có thể hoàn thành xuất sắc mục tiêu này.

🎯 Thế mạnh & Kinh nghiệm phù hợp:
- Thành thạo các công nghệ: ${flSkills}.
- Đã từng triển khai nhiều sản phẩm tương tự với chất lượng cao, giao diện tối ưu và mã nguồn chuẩn sạch.

📋 Phương án triển khai dự kiến:
1. Giai đoạn 1: Phân tích kỹ lưỡng yêu cầu, thống nhất kiến trúc và giao diện.
2. Giai đoạn 2: Lập trình các module tính năng cốt lõi theo đúng đặc tả.
3. Giai đoạn 3: Kiểm thử toàn diện (Function, Responsive, Performance) và bàn giao mã nguồn.

🤝 Cam kết từ tôi:
- Báo cáo tiến độ đầy đủ theo từng phân kỳ Milestones trên HT Work.
- Hỗ trợ bảo hành, sửa lỗi nhanh chóng và hướng dẫn triển khai chu đáo.

Rất mong có cơ hội được đồng hành và hợp tác cùng Quý Khách hàng.

Trân trọng,
${flName}`;

    return res.status(200).json({
        success: true,
        source: 'heuristic_fallback',
        proposal: {
            cover_letter: offlineLetter,
            suggested_bid: suggestedBid,
            suggested_days: 7,
            key_highlights: [
                `Kỹ năng thế mạnh: ${flSkills}`,
                'Cam kết chuẩn tiến độ & chất lượng',
                'Hỗ trợ bảo hành chu đáo sau bàn giao'
            ]
        }
    });
});

module.exports = router;