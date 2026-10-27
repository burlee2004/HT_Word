const { logEvent } = require('./auditLogger');

/**
 * 15+ Danh mục Công nghệ Chuẩn hóa Toàn diện cho KGS Work
 * Bao phủ 100% ngành nghề IT, Công nghệ cao (IoT, Drone/UAV, Robotics, Game, AR/VR...)
 */
const STANDARD_CATEGORIES = [
    { 
        id: 'web', 
        name: 'Phát triển Website & Web App', 
        icon: '🌐',
        description: 'Frontend, Backend, Full-stack Web, RESTful API, Microservices, UI Design'
    },
    { 
        id: 'mobile', 
        name: 'Ứng dụng Di Động (iOS / Android / Flutter)', 
        icon: '📱',
        description: 'Native iOS/Android, Flutter, React Native, Cross-platform App'
    },
    { 
        id: 'uiux', 
        name: 'Thiết kế UI/UX & Đồ Họa', 
        icon: '🎨',
        description: 'Figma, Adobe XD, Design System, Wireframe, Prototyping, Brand Identity'
    },
    { 
        id: 'ai_ml', 
        name: 'Trí Tuệ Nhân Tạo & Học Máy (AI / ML / LLM)', 
        icon: '🤖',
        description: 'Machine Learning, Deep Learning, NLP, Generative AI, RAG, Computer Vision'
    },
    { 
        id: 'iot_embedded', 
        name: 'IoT & Hệ Thống Nhúng (Internet of Things & Embedded)', 
        icon: '📡',
        description: 'Vi điều khiển STM32/ESP32, Firmware C/C++, RTOS, MQTT, Cảm biến, Smart Home'
    },
    { 
        id: 'uav_drone', 
        name: 'UAV, Drone & Thiết Bị Bay Tự Hành', 
        icon: '🛸',
        description: 'Phần mềm điều khiển bay, PX4, ArduPilot, MAVLink, Thiết bị bay nông nghiệp/khảo sát'
    },
    { 
        id: 'robotics', 
        name: 'Robotics, Cơ Điện Tử & Tự Động Hóa', 
        icon: '🦾',
        description: 'Robot công nghiệp, ROS/ROS2, PLC, SCADA, Tự động hóa dây chuyền, Xử lý ảnh'
    },
    { 
        id: 'game', 
        name: 'Lập Trình Game (Unity / Unreal Engine / 3D)', 
        icon: '🎮',
        description: 'Game 2D/3D, Unity, Unreal Engine, Gameplay Programming, Shaders, Animation'
    },
    { 
        id: 'ar_vr', 
        name: 'Thực Tế Ảo & AR / VR / Metaverse', 
        icon: '🕶️',
        description: 'Augmented Reality, Virtual Reality, WebXR, 3D Modeling, Không gian ảo'
    },
    { 
        id: 'blockchain', 
        name: 'Blockchain, Web3 & Smart Contract', 
        icon: '⛓️',
        description: 'Solidity, Rust, Ethereum, EVM, DApp, Smart Contract Audit, DeFi, Web3 Security'
    },
    { 
        id: 'data_engineering', 
        name: 'Kỹ Sư Dữ Liệu & Big Data (Data Engineering)', 
        icon: '📊',
        description: 'Xử lý dữ liệu lớn, ETL Pipeline, Data Warehouse, Spark, Kafka, SQL, Power BI'
    },
    { 
        id: 'cloud_devops', 
        name: 'Điện Toán Đám Mây & DevOps (Cloud / CI/CD)', 
        icon: '☁️',
        description: 'AWS, GCP, Azure, Docker, Kubernetes, CI/CD Pipeline, Linux Server, Terraform'
    },
    { 
        id: 'cybersecurity', 
        name: 'An Ninh Mạng & Bảo Mật (Cybersecurity)', 
        icon: '🛡️',
        description: 'Penetration Testing, Đánh giá an toàn thông tin, Rà soát lỗ hổng, Bảo mật hệ thống'
    },
    { 
        id: 'ecommerce_erp', 
        name: 'Thương Mại Điện Tử & Hệ Thống ERP / CRM', 
        icon: '🛒',
        description: 'Hệ thống ERP, CRM, Odoo, SAP, Shopify, WooCommerce, Tích hợp cổng thanh toán'
    },
    { 
        id: 'other', 
        name: 'Lĩnh vực Khác (Tự do nhập - AI Kiểm duyệt)', 
        icon: '💡',
        description: 'Các chuyên môn kỹ thuật đặc thù khác sẽ được AI kiểm duyệt và gắn tự động'
    }
];

/**
 * Danh sách từ khóa cấm/nhạy cảm (Blacklist Regex cơ bản làm lá chắn bảo vệ ban đầu)
 */
const PROFANITY_PATTERN = /(sex|porn|đụ|địt|cặc|lồn|buồi|chó đẻ|lừa đảo|hack acc|bán nick|cờ bạc|tài xỉu|gái gọi|mua bán ma túy|hack pass)/i;

/**
 * Kiểm duyệt & Chuẩn hóa Lĩnh Vực Chuyên Môn tự nhập bằng Groq AI (Llama 3.3 / Qwen)
 * @param {string} rawInput - Tên chuyên môn do người dùng tự nhập
 * @returns {Promise<{ isValid: boolean, normalizedName: string, parentCategory: string, reason: string, suggestedSkills: string[] }>}
 */
async function validateAndNormalizeCustomCategory(rawInput) {
    if (!rawInput || typeof rawInput !== 'string' || rawInput.trim().length < 2) {
        return {
            isValid: false,
            normalizedName: '',
            parentCategory: 'Lĩnh vực Khác',
            reason: 'Tên chuyên môn quá ngắn. Vui lòng nhập tối thiểu 2 ký tự.',
            suggestedSkills: []
        };
    }

    const text = rawInput.trim();

    // 1. Kiểm tra nhanh bằng Regex Blacklist
    if (PROFANITY_PATTERN.test(text)) {
        return {
            isValid: false,
            normalizedName: '',
            parentCategory: 'Lĩnh vực Khác',
            reason: 'Nội dung chứa từ ngữ không phù hợp với quy chuẩn chuyên nghiệp của sàn KGS Work.',
            suggestedSkills: []
        };
    }

    // 2. Kiểm tra chuỗi vô nghĩa dạng gõ phím bừa bãi (vd: "asdfghjkl", "1111111")
    if (/^[a-zA-Z]{6,}$/.test(text) && !/[aeiouyAEIOUY]/.test(text)) {
        return {
            isValid: false,
            normalizedName: '',
            parentCategory: 'Lĩnh vực Khác',
            reason: 'Tên chuyên môn không có ý nghĩa hoặc gõ phím ngẫu nhiên.',
            suggestedSkills: []
        };
    }

    // 3. Gọi Groq AI để phân tích ngữ nghĩa, phát hiện chuyên môn và tự động phê duyệt (Auto-Approve)
    const groqKey = process.env.GROQ_API_KEY ? process.env.GROQ_API_KEY.trim() : '';

    if (groqKey && !groqKey.includes('YOUR_GROQ_KEY')) {
        try {
            const systemPrompt = `Bạn là Chuyên gia Kiểm Duyệt & Phân Loại Danh Mục Nghề Nghiệp IT cao cấp của nền tảng sàn tuyển dụng công nghệ KGS Work.
Nhiệm vụ của bạn là kiểm duyệt cụm từ chuyên môn do người dùng tự nhập và chuẩn hóa về ngữ pháp tiếng Việt trang trọng.

Quy tắc kiểm duyệt:
1. "isValid": true nếu cụm từ đại diện cho một chuyên môn, công nghệ, nghề nghiệp, kỹ năng kỹ thuật/IT/khoa học/thiết kế hợp lệ (Ví dụ: "Lập trình điều khiển Drone nông nghiệp", "Hệ thống nhúng STM32", "Robotics ROS2", "Vi điều khiển FPGA", "Quantum Computing", "Game Unity 3D", "Lập trình backend Golang"...).
2. "isValid": false nếu cụm từ là từ ngữ tục tĩu, xúc phạm, spam rác, quảng cáo cờ bạc, vô nghĩa, hoặc không liên quan đến công việc chuyên môn.
3. "normalizedName": Viết hoa chữ cái đầu trang trọng, chuẩn tiếng Việt (Ví dụ: "Lập Trình Drone Nông Nghiệp", "Hệ Thống Nhúng & Vi Điều Khiển STM32").
4. "parentCategory": Gán vào 1 trong các nhóm ngành cha: "Website & Web App", "Mobile App", "UI/UX & Đồ Họa", "AI & Machine Learning", "IoT & Hệ Thống Nhúng", "UAV & Drone", "Robotics & Tự Động Hóa", "Lập Trình Game", "AR/VR & Metaverse", "Blockchain & Web3", "Data Engineering", "Cloud & DevOps", "Cybersecurity", "ERP/CRM & E-Commerce", "Khác".
5. "suggestedSkills": Mảng 3-5 kỹ năng/công nghệ cốt lõi liên quan (Ví dụ: ["PX4", "MAVLink", "ROS", "C++"]).
6. "reason": Giải thích ngắn gọn 1 câu tiếng Việt.

BẮT BUỘC trả về định dạng JSON thuần:
{
  "isValid": boolean,
  "normalizedName": string,
  "parentCategory": string,
  "suggestedSkills": string[],
  "reason": string
}`;

            const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${groqKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'llama-3.3-70b-versatile',
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: `Hãy kiểm duyệt và chuẩn hóa chuyên môn sau: "${text}"` }
                    ],
                    response_format: { type: 'json_object' },
                    temperature: 0.1,
                    max_tokens: 500
                })
            });

            if (response.ok) {
                const data = await response.json();
                const contentStr = data.choices?.[0]?.message?.content;
                if (contentStr) {
                    const parsed = JSON.parse(contentStr);
                    console.log(`🤖 [AI CATEGORY MODERATION] "${text}" -> isValid: ${parsed.isValid} | Normalized: "${parsed.normalizedName}"`);

                    await logEvent({
                        module: 'CATEGORY_AI',
                        action: parsed.isValid ? 'CATEGORY_AUTO_APPROVED' : 'CATEGORY_REJECTED',
                        level: parsed.isValid ? 'INFO' : 'WARN',
                        details: `Kiểm duyệt chuyên môn tự nhập: "${text}" -> ${parsed.isValid ? 'Hợp lệ' : 'Từ chối'}: ${parsed.reason}`,
                        metadata: { originalText: text, aiResult: parsed }
                    });

                    return {
                        isValid: Boolean(parsed.isValid),
                        normalizedName: parsed.normalizedName || text,
                        parentCategory: parsed.parentCategory || 'Lĩnh vực Khác',
                        suggestedSkills: Array.isArray(parsed.suggestedSkills) ? parsed.suggestedSkills : [],
                        reason: parsed.reason || (parsed.isValid ? 'Chuyên môn hợp lệ.' : 'Nội dung không hợp lệ.')
                    };
                }
            }
        } catch (aiErr) {
            console.warn('⚠️ [Category AI Error]:', aiErr.message);
        }
    }

    // 4. Fallback Heuristic nếu không kết nối được AI
    // Chuẩn hóa viết hoa các chữ cái đầu
    const normalizedFallback = text
        .toLowerCase()
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');

    return {
        isValid: true,
        normalizedName: normalizedFallback,
        parentCategory: 'Lĩnh vực Khác',
        suggestedSkills: [],
        reason: 'Chuyên môn đã được chuẩn hóa thành công.'
    };
}

module.exports = {
    STANDARD_CATEGORIES,
    validateAndNormalizeCustomCategory
};
