const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data', 'subscriptions.json');

const DEFAULT_DATA = {
    plans: {
        client: [
            {
                id: 'starter',
                name: 'Khởi Tạo (Starter)',
                price_monthly: 0,
                price_annual: 0,
                badge: 'Miễn Phí',
                features: [
                    'Đăng tin dự án hoàn toàn Miễn Phí (Không giới hạn)',
                    'Tiếp cận mạng lưới Freelancer tiêu chuẩn',
                    'Ký quỹ Escrow bảo chứng 100%',
                    'Hỗ trợ cộng đồng qua Ticket'
                ]
            },
            {
                id: 'client_pro',
                name: 'Doanh Nghiệp Pro',
                price_monthly: 199000,
                price_annual: 1900000,
                badge: 'Phổ Biến Nhất',
                popular: true,
                features: [
                    'Đăng tin không giới hạn (Ưu tiên tiếp cận Freelancer)',
                    'Tặng 3 lượt Đẩy Top 1 bài đăng / tháng',
                    'Khung viền tin Xanh Nổi Bật & Ưu Tiên',
                    'Mở khóa xem Zalo/SĐT 10 Senior Dev',
                    'AI duyệt bài tức thì (<0.1s)',
                    'Trọng tài phân xử ưu tiên trong 4h'
                ]
            },
            {
                id: 'client_vip',
                name: 'Enterprise VIP',
                price_monthly: 499000,
                price_annual: 4790000,
                badge: 'Đẳng Cấp',
                features: [
                    'Đăng tin không giới hạn (Vị trí nổi bật & Ghim đầu)',
                    'Tặng 10 lượt Đẩy Top + Ghim đầu 7 ngày',
                    'Huy hiệu Vương Miện Doanh Nghiệp VIP',
                    'Mở khóa xem thông tin trực tiếp 30 Dev',
                    'AI gợi ý Freelancer chính xác nhất',
                    'Chuyên viên hỗ trợ 1-1 riêng'
                ]
            }
        ],
        freelancer: [
            {
                id: 'newbie',
                name: 'Tân Binh (Newbie)',
                price_monthly: 0,
                price_annual: 0,
                badge: 'Miễn Phí',
                features: [
                    '5 lượt chào thầu (bids) / ngày (Tự động làm mới mỗi ngày)',
                    'Hồ sơ năng lực công khai tiêu chuẩn',
                    'Nhận tiền ví an toàn qua Escrow',
                    'Rút tiền thưởng miễn phí'
                ]
            },
            {
                id: 'freelancer_pro',
                name: 'Chuyên Gia Pro',
                price_monthly: 99000,
                price_annual: 950000,
                badge: 'Khuyên Dùng',
                popular: true,
                features: [
                    '25 lượt chào thầu (bids) / ngày (Gấp 5 lần Tân Binh)',
                    'Huy hiệu Tích Xanh Verified Pro Dev',
                    'Luôn xuất hiện đầu mục Chuyên Gia IT',
                    'Nhận thông báo Job mới sớm hơn 15 phút',
                    'Hồ sơ luôn nằm trong Top 3 khi nộp bài',
                    'Ưu tiên giải ngân & rút tiền nhanh'
                ]
            },
            {
                id: 'freelancer_agency',
                name: 'Đội Ngũ / Agency',
                price_monthly: 299000,
                price_annual: 2870000,
                badge: 'Đội Ngũ Lớn',
                features: [
                    'Không giới hạn lượt chào thầu (Unlimited Bids)',
                    'Vương Miện Vàng Top Rated Agency',
                    'Nằm trong Carousel Đối tác chiến lược',
                    'Đóng khung nổi bật hồ sơ đấu thầu',
                    'Tích hợp nhóm làm việc nhiều thành viên'
                ]
            }
        ],
        addons: [
            {
                id: 'job_boost',
                name: '⚡ Đẩy Tin Lên Top 1',
                price: 25000,
                duration_hours: 24,
                for_role: 'client',
                desc: 'Ghim bài đăng lên vị trí Top 1 trang tìm kiếm trong 24 giờ'
            },
            {
                id: 'urgent_tag',
                name: '🔥 Gắn Nhãn Tuyển Gấp',
                price: 50000,
                duration_hours: 72,
                for_role: 'client',
                desc: 'Đóng khung đỏ rực + gửi thông báo đẩy đến tất cả Freelancer phù hợp'
            },
            {
                id: 'bid_pack',
                name: '🎯 Gói 5 Lượt Chào Thầu',
                price: 20000,
                bids: 5,
                for_role: 'freelancer',
                desc: 'Bổ sung ngay 5 lượt nộp hồ sơ ứng tuyển dự án mới'
            }
        ]
    },
    discount_campaign: {
        active: false,
        percent: 0,
        title: '',
        applies_to: 'all'
    },
    user_subscriptions: {},
    user_subscription_history: {},
    user_addons: {},
    boosted_jobs: {},
    platform_revenue: {
        total_profit: 0,
        transactions: []
    }
};

function readData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            writeData(DEFAULT_DATA);
            return DEFAULT_DATA;
        }
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (!parsed.platform_revenue) {
            parsed.platform_revenue = { total_profit: 0, transactions: [] };
        }
        if (!parsed.user_subscription_history) parsed.user_subscription_history = {};
        if (!parsed.user_addons) parsed.user_addons = {};
        if (!parsed.discount_campaign) {
            parsed.discount_campaign = { active: false, percent: 0, title: '', applies_to: 'all' };
        }
        return parsed;
    } catch (e) {
        console.error('[SubscriptionService] Error reading data, fallback to default:', e.message);
        return DEFAULT_DATA;
    }
}

function writeData(data) {
    try {
        const dir = path.dirname(DATA_FILE);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
    } catch (e) {
        console.error('[SubscriptionService] Error writing data:', e.message);
    }
}

function getAllPlans() {
    const data = readData();
    return {
        ...data.plans,
        discount_campaign: data.discount_campaign || { active: false, percent: 0, title: '', applies_to: 'all' }
    };
}

function getUserSubscription(userId) {
    if (!userId) return null;
    const data = readData();
    const sub = data.user_subscriptions?.[userId];
    if (!sub) return null;

    const now = new Date();
    const expDate = new Date(sub.expires_at);
    if (sub.expires_at && expDate < now) {
        sub.is_expired = true;
        sub.is_active = false;
        sub.days_remaining = 0;
    } else {
        sub.is_expired = false;
        sub.is_active = true;
        sub.days_remaining = Math.max(0, Math.ceil((expDate - now) / (1000 * 60 * 60 * 24)));
    }
    // Gắn thêm lịch sử nâng cấp & kho tiện ích Addon Credits
    sub.history = data.user_subscription_history?.[userId] || [];
    sub.addons = data.user_addons?.[userId] || { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
    return sub;
}

function getUserAddons(userId) {
    if (!userId) return { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
    const data = readData();
    return data.user_addons?.[userId] || { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
}

function getUserSubscriptionHistory(userId) {
    if (!userId) return [];
    const data = readData();
    const list = data.user_subscription_history?.[userId] || [];
    return [...list].sort((a, b) => new Date(b.subscribed_at || 0) - new Date(a.subscribed_at || 0));
}

function recordPlatformProfit(amount, serviceName, userId, details = {}) {
    const data = readData();
    const parsedAmount = parseFloat(amount) || 0;
    if (parsedAmount <= 0) return;

    if (!data.platform_revenue) {
        data.platform_revenue = { total_profit: 0, transactions: [] };
    }

    data.platform_revenue.total_profit = (parseFloat(data.platform_revenue.total_profit) || 0) + parsedAmount;
    data.platform_revenue.transactions.unshift({
        id: 'REV-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        amount: parsedAmount,
        service: serviceName,
        user_id: userId,
        created_at: new Date().toISOString(),
        details: details
    });

    if (data.platform_revenue.transactions.length > 200) {
        data.platform_revenue.transactions = data.platform_revenue.transactions.slice(0, 200);
    }

    writeData(data);
}

function getPlatformProfitStats() {
    const data = readData();
    return data.platform_revenue || { total_profit: 0, transactions: [] };
}

function subscribeUser(userId, planId, billingCycle = 'monthly', role = 'client', pricePaid = 0) {
    const data = readData();
    const plansPool = role === 'freelancer' ? data.plans.freelancer : data.plans.client;
    const plan = plansPool.find(p => p.id === planId);
    if (!plan) throw new Error('Gói dịch vụ không tồn tại');

    const durationDays = billingCycle === 'annual' ? 365 : 30;

    if (!data.user_subscriptions) data.user_subscriptions = {};
    const existingSub = data.user_subscriptions[userId];

    // CỘNG DỒN THỜI HẠN: Nếu đang có gói còn hạn, cộng dồn tiếp tục từ ngày hết hạn cũ!
    let baseTime = Date.now();
    if (existingSub && existingSub.expires_at) {
        const existingExpires = new Date(existingSub.expires_at).getTime();
        if (existingExpires > baseTime) {
            baseTime = existingExpires; // Cộng dồn ngày sử dụng
        }
    }

    const expiresAt = new Date(baseTime + durationDays * 24 * 60 * 60 * 1000).toISOString();
    const now = new Date();
    const daysRemaining = Math.max(1, Math.ceil((new Date(expiresAt) - now) / (1000 * 60 * 60 * 24)));

    const subRecord = {
        user_id: userId,
        plan_id: planId,
        plan_name: plan.name,
        role: role,
        billing_cycle: billingCycle,
        started_at: (existingSub && existingSub.started_at) ? existingSub.started_at : new Date().toISOString(),
        expires_at: expiresAt,
        days_remaining: daysRemaining,
        is_active: true,
        is_expired: false,
        features: plan.features
    };

    data.user_subscriptions[userId] = subRecord;

    // Ghi nhận vào Lịch sử Nâng Cấp (Subscription History)
    if (!data.user_subscription_history) data.user_subscription_history = {};
    if (!data.user_subscription_history[userId]) data.user_subscription_history[userId] = [];
    data.user_subscription_history[userId].unshift({
        id: 'SUBHIST-' + Date.now(),
        plan_id: planId,
        plan_name: plan.name,
        role: role,
        billing_cycle: billingCycle,
        price: pricePaid,
        subscribed_at: new Date().toISOString(),
        expires_at: expiresAt
    });

    writeData(data);

    if (pricePaid > 0) {
        recordPlatformProfit(pricePaid, `Gói Hội Viên: ${plan.name} (${billingCycle === 'annual' ? 'Năm' : 'Tháng'})`, userId, { plan_id: planId, billing_cycle: billingCycle });
    }

    return subRecord;
}

function purchaseAddon(userId, addonId, targetJobId = null, pricePaid = 0) {
    const data = readData();
    const addon = (data.plans.addons || []).find(a => a.id === addonId);
    if (!addon) throw new Error('Tiện ích không tồn tại');

    if (!data.user_addons) data.user_addons = {};
    if (!data.user_addons[userId]) {
        data.user_addons[userId] = { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
    }

    let resultMsg = '';
    let boostResult = null;

    if (addonId === 'bid_pack') {
        const added = addon.bids || 5;
        data.user_addons[userId].extra_bids = (data.user_addons[userId].extra_bids || 0) + added;
        resultMsg = `Đã cộng thêm ${added} lượt chào thầu (Bids) vào tài khoản của bạn!`;
    } else if (addonId === 'job_boost') {
        if (targetJobId) {
            boostResult = boostJob(targetJobId, 'job_boost', pricePaid, userId);
            resultMsg = `Đã đẩy Top 1 bài đăng #${targetJobId} thành công trong 24 giờ!`;
        } else {
            data.user_addons[userId].job_boost_credits = (data.user_addons[userId].job_boost_credits || 0) + 1;
            resultMsg = `Đã thêm 1 lượt Đẩy Tin Top 1 vào Kho Tiện Ích của bạn!`;
        }
    } else if (addonId === 'urgent_tag') {
        if (targetJobId) {
            boostResult = boostJob(targetJobId, 'urgent_tag', pricePaid, userId);
            resultMsg = `Đã gắn nhãn Tuyển Gấp 🔥 cho bài đăng #${targetJobId} thành công trong 72 giờ!`;
        } else {
            data.user_addons[userId].urgent_tag_credits = (data.user_addons[userId].urgent_tag_credits || 0) + 1;
            resultMsg = `Đã thêm 1 lượt Gắn Nhãn Tuyển Gấp vào Kho Tiện Ích của bạn!`;
        }
    }

    if (pricePaid > 0) {
        recordPlatformProfit(pricePaid, `Tiện ích lẻ: ${addon.name}`, userId, { addon_id: addonId, target_job_id: targetJobId });
    }

    // Ghi nhận tiện ích đã mua vào Lịch sử mua hàng của user
    if (!data.user_subscription_history) data.user_subscription_history = {};
    if (!data.user_subscription_history[userId]) data.user_subscription_history[userId] = [];
    data.user_subscription_history[userId].unshift({
        id: 'ADDONHIST-' + Date.now(),
        plan_id: addonId,
        plan_name: `Tiện ích: ${addon.name}`,
        role: 'addon',
        billing_cycle: 'one-time',
        price: pricePaid,
        subscribed_at: new Date().toISOString(),
        status: 'completed'
    });

    writeData(data);
    return {
        success: true,
        message: resultMsg,
        addon,
        boost: boostResult,
        user_addons: data.user_addons[userId]
    };
}

function useAddonCredit(userId, addonId, targetJobId) {
    const data = readData();
    if (!data.user_addons || !data.user_addons[userId]) {
        throw new Error('Bạn chưa có lượt tiện ích nào trong kho');
    }
    const userCredits = data.user_addons[userId];

    if (addonId === 'job_boost') {
        if ((userCredits.job_boost_credits || 0) < 1) {
            throw new Error('Bạn đã hết lượt Đẩy Tin Top 1. Vui lòng mua thêm trong Bảng Giá.');
        }
        userCredits.job_boost_credits -= 1;
        const boostRecord = boostJob(targetJobId, 'job_boost', 0, userId);
        writeData(data);
        return { success: true, message: `Đã sử dụng 1 lượt Đẩy Top 1 cho bài đăng!`, boost: boostRecord, remaining: userCredits.job_boost_credits };
    } else if (addonId === 'urgent_tag') {
        if ((userCredits.urgent_tag_credits || 0) < 1) {
            throw new Error('Bạn đã hết lượt Gắn Nhãn Tuyển Gấp. Vui lòng mua thêm trong Bảng Giá.');
        }
        userCredits.urgent_tag_credits -= 1;
        const boostRecord = boostJob(targetJobId, 'urgent_tag', 0, userId);
        writeData(data);
        return { success: true, message: `Đã sử dụng 1 lượt Gắn Nhãn Tuyển Gấp 🔥 cho bài đăng!`, boost: boostRecord, remaining: userCredits.urgent_tag_credits };
    } else {
        throw new Error('Loại tiện ích không hợp lệ');
    }
}

function boostJob(jobId, boostType = 'job_boost', pricePaid = 0, userId = null) {
    const data = readData();
    const durationHours = boostType === 'urgent_tag' ? 72 : 24;
    const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();

    const boostRecord = {
        job_id: jobId,
        boost_type: boostType,
        boosted_at: new Date().toISOString(),
        expires_at: expiresAt,
        active: true
    };

    if (!data.boosted_jobs) data.boosted_jobs = {};
    data.boosted_jobs[jobId] = boostRecord;
    writeData(data);

    if (pricePaid > 0 && userId) {
        recordPlatformProfit(pricePaid, `Tiện ích bài đăng: ${boostType}`, userId, { job_id: jobId, boost_type: boostType });
    }

    return boostRecord;
}

function isJobBoosted(jobId) {
    if (!jobId) return false;
    const data = readData();
    const record = data.boosted_jobs?.[jobId];
    if (!record || !record.active) return false;
    if (new Date(record.expires_at) < new Date()) {
        record.active = false;
        writeData(data);
        return false;
    }
    return record;
}

function getBoostedJobsMap() {
    const data = readData();
    const result = {};
    const now = new Date();
    let hasChanges = false;

    if (data.boosted_jobs) {
        for (const [id, item] of Object.entries(data.boosted_jobs)) {
            if (item.active && new Date(item.expires_at) > now) {
                result[id] = item;
            } else if (item.active) {
                item.active = false;
                hasChanges = true;
            }
        }
    }
    if (hasChanges) writeData(data);
    return result;
}

// ADMIN PLAN MANAGEMENT
function createPlan(category, planData) {
    const data = readData();
    if (!data.plans[category]) {
        throw new Error(`Danh mục gói "${category}" không hợp lệ (hỗ trợ: client, freelancer, addons)`);
    }

    const newId = planData.id ? planData.id.trim().toLowerCase().replace(/\s+/g, '_') : `${category}_plan_${Date.now()}`;
    const exists = data.plans[category].some(p => p.id === newId);
    if (exists) {
        throw new Error(`Mã gói "${newId}" đã tồn tại`);
    }

    const newPlan = {
        id: newId,
        name: planData.name || 'Gói Dịch Vụ Mới',
        badge: planData.badge || '',
        features: Array.isArray(planData.features) ? planData.features : (typeof planData.features === 'string' ? planData.features.split('\n').map(s => s.trim()).filter(Boolean) : []),
        created_at: new Date().toISOString()
    };

    if (category === 'addons') {
        newPlan.price = parseFloat(planData.price) || 0;
        newPlan.duration_hours = parseInt(planData.duration_hours) || 24;
        newPlan.for_role = planData.for_role || 'client';
        newPlan.desc = planData.desc || '';
    } else {
        newPlan.price_monthly = parseFloat(planData.price_monthly) || 0;
        newPlan.price_annual = parseFloat(planData.price_annual) || 0;
        newPlan.popular = !!planData.popular;
    }

    data.plans[category].push(newPlan);
    writeData(data);
    return newPlan;
}

function updatePlan(category, planId, updateData) {
    const data = readData();
    if (!data.plans[category]) {
        throw new Error(`Danh mục gói "${category}" không hợp lệ`);
    }
    const idx = data.plans[category].findIndex(p => p.id === planId);
    if (idx === -1) {
        throw new Error(`Không tìm thấy gói #${planId} trong danh mục ${category}`);
    }

    const target = data.plans[category][idx];
    if (updateData.name !== undefined) target.name = updateData.name;
    if (updateData.badge !== undefined) target.badge = updateData.badge;
    if (updateData.popular !== undefined) target.popular = !!updateData.popular;
    if (updateData.features !== undefined) {
        target.features = Array.isArray(updateData.features) ? updateData.features : (typeof updateData.features === 'string' ? updateData.features.split('\n').map(s => s.trim()).filter(Boolean) : target.features);
    }

    if (category === 'addons') {
        if (updateData.price !== undefined) target.price = parseFloat(updateData.price) || 0;
        if (updateData.duration_hours !== undefined) target.duration_hours = parseInt(updateData.duration_hours) || 24;
        if (updateData.for_role !== undefined) target.for_role = updateData.for_role;
        if (updateData.desc !== undefined) target.desc = updateData.desc;
    } else {
        if (updateData.price_monthly !== undefined) target.price_monthly = parseFloat(updateData.price_monthly) || 0;
        if (updateData.price_annual !== undefined) target.price_annual = parseFloat(updateData.price_annual) || 0;
    }

    target.updated_at = new Date().toISOString();
    data.plans[category][idx] = target;
    writeData(data);
    return target;
}

function deletePlan(category, planId) {
    const data = readData();
    if (!data.plans[category]) {
        throw new Error(`Danh mục gói "${category}" không hợp lệ`);
    }
    if (['starter', 'newbie'].includes(planId)) {
        throw new Error('Không thể xóa gói mặc định miễn phí của hệ thống!');
    }

    const initialLen = data.plans[category].length;
    data.plans[category] = data.plans[category].filter(p => p.id !== planId);
    if (data.plans[category].length === initialLen) {
        throw new Error(`Không tìm thấy gói #${planId} để xóa`);
    }

    writeData(data);
    return { success: true, message: `Đã xóa gói #${planId} thành công` };
}

// CÀI ĐẶT KHUYẾN MÃI (DISCOUNT CAMPAIGN)
function getDiscountCampaign() {
    const data = readData();
    return data.discount_campaign || { active: false, percent: 0, title: '', applies_to: 'all' };
}

function setDiscountCampaign(campaignData) {
    const data = readData();
    data.discount_campaign = {
        active: !!campaignData.active,
        percent: Math.min(100, Math.max(0, parseInt(campaignData.percent) || 0)),
        title: campaignData.title || '',
        applies_to: campaignData.applies_to || 'all',
        updated_at: new Date().toISOString()
    };
    writeData(data);
    return data.discount_campaign;
}

// ADMIN: LẤY DANH SÁCH HỘI VIÊN ĐANG SỬ DỤNG GÓI VIP (KÈM THÔNG TIN NGƯỜI DÙNG)
async function getAllSubscribersWithUserInfo(supabase) {
    const data = readData();
    const subs = data.user_subscriptions || {};
    const userIds = Object.keys(subs);
    if (userIds.length === 0) return [];

    let usersMap = {};
    if (supabase) {
        try {
            const { data: users, error } = await supabase
                .from('users')
                .select('id, full_name, email, role, phone_number, avatar_url')
                .in('id', userIds);
            if (!error && users) {
                users.forEach(u => { usersMap[u.id] = u; });
            }
        } catch (e) {
            console.warn('[getAllSubscribersWithUserInfo] Error querying users:', e.message);
        }
    }

    const now = new Date();
    const list = [];
    for (const [userId, sub] of Object.entries(subs)) {
        const expDate = new Date(sub.expires_at);
        const isExpired = expDate < now;
        const daysRemaining = Math.max(0, Math.ceil((expDate - now) / (1000 * 60 * 60 * 24)));
        const u = usersMap[userId] || {};

        list.push({
            user_id: userId,
            user_name: u.full_name || 'Người Dùng KGS',
            user_email: u.email || '',
            user_phone: u.phone_number || '',
            user_avatar: u.avatar_url || '',
            user_role: u.role || sub.role || 'client',
            plan_id: sub.plan_id,
            plan_name: sub.plan_name,
            role: sub.role,
            billing_cycle: sub.billing_cycle || 'monthly',
            started_at: sub.started_at,
            expires_at: sub.expires_at,
            days_remaining: daysRemaining,
            is_active: !isExpired,
            is_expired: isExpired,
            features: sub.features || []
        });
    }

    list.sort((a, b) => {
        if (a.is_active && !b.is_active) return -1;
        if (!a.is_active && b.is_active) return 1;
        return new Date(b.started_at) - new Date(a.started_at);
    });

    return list;
}

// ADMIN: LẤY TOÀN BỘ LỊCH SỬ ĐĂNG KÝ / MUA GÓI & TIỆN ÍCH
async function getAllSubscriptionHistoryWithUserInfo(supabase) {
    const data = readData();
    const rawTx = data.platform_revenue?.transactions || [];
    const historyList = [];

    const userIds = [...new Set(rawTx.map(t => t.user_id).filter(Boolean))];
    let usersMap = {};
    if (supabase && userIds.length > 0) {
        try {
            const { data: users } = await supabase
                .from('users')
                .select('id, full_name, email, role, avatar_url')
                .in('id', userIds);
            if (users) {
                users.forEach(u => { usersMap[u.id] = u; });
            }
        } catch (e) {}
    }

    rawTx.forEach(t => {
        const u = usersMap[t.user_id] || {};
        historyList.push({
            id: t.id,
            user_id: t.user_id,
            user_name: u.full_name || 'Khách hàng',
            user_email: u.email || '',
            user_avatar: u.avatar_url || '',
            user_role: u.role || 'client',
            service: t.service,
            amount: t.amount,
            created_at: t.created_at,
            details: t.details || {}
        });
    });

    return historyList;
}

// ADMIN: GIA HẠN THÊM NGÀY CHO HỘI VIÊN
function adminExtendSubscription(userId, extraDays = 30) {
    const data = readData();
    if (!data.user_subscriptions || !data.user_subscriptions[userId]) {
        throw new Error('Người dùng chưa có gói đăng ký để gia hạn');
    }
    const sub = data.user_subscriptions[userId];
    let baseTime = Date.now();
    if (sub.expires_at) {
        const existingExpires = new Date(sub.expires_at).getTime();
        if (existingExpires > baseTime) {
            baseTime = existingExpires;
        }
    }
    const newExpires = new Date(baseTime + extraDays * 24 * 60 * 60 * 1000).toISOString();
    sub.expires_at = newExpires;
    sub.is_active = true;
    sub.is_expired = false;
    sub.days_remaining = Math.max(1, Math.ceil((new Date(newExpires) - new Date()) / (1000 * 60 * 60 * 24)));
    
    writeData(data);
    return sub;
}

// ADMIN: HỦY KÍCH HOẠT GÓI CỦA NGƯỜI DÙNG
function adminCancelSubscription(userId) {
    const data = readData();
    if (!data.user_subscriptions || !data.user_subscriptions[userId]) {
        throw new Error('Người dùng không có gói hoạt động');
    }
    const sub = data.user_subscriptions[userId];
    sub.expires_at = new Date().toISOString();
    sub.is_active = false;
    sub.is_expired = true;
    sub.days_remaining = 0;
    
    writeData(data);
    return sub;
}

// ==========================================
// FREELANCER BID QUOTA MANAGEMENT (THỰC THI CHÀO THẦU HÀNG NGÀY & GÓI LẺ)
// ==========================================

/**
 * Lấy hạn mức chào thầu hôm nay của Freelancer:
 * - Gói Agency: Không giới hạn
 * - Gói Pro: 25 lượt/ngày (reset mỗi 00:00)
 * - Gói Tân Binh (Free): 5 lượt/ngày (reset mỗi 00:00)
 * - Gói lẻ (extra_bids): Số lượt dự phòng dùng khi hết hạn mức ngày
 */
async function getFreelancerBidQuota(freelancerId, supabase) {
    if (!freelancerId) {
        return {
            plan_id: 'newbie',
            plan_name: 'Tân Binh (Newbie)',
            daily_limit: 5,
            numeric_daily_limit: 5,
            used_today: 0,
            remaining_today: 5,
            numeric_remaining_today: 5,
            extra_bids: 0,
            total_available: 5,
            numeric_total_available: 5,
            unlimited: false
        };
    }

    const sub = getUserSubscription(freelancerId);
    const addons = getUserAddons(freelancerId);
    const extraBids = addons.extra_bids || 0;

    let dailyLimit = 5;
    let planId = 'newbie';
    let planName = 'Tân Binh (Newbie)';
    let isUnlimited = false;

    if (sub && sub.is_active) {
        if (sub.plan_id === 'freelancer_agency') {
            isUnlimited = true;
            dailyLimit = 999999;
            planId = sub.plan_id;
            planName = sub.plan_name;
        } else if (sub.plan_id === 'freelancer_pro') {
            dailyLimit = 25;
            planId = sub.plan_id;
            planName = sub.plan_name;
        }
    }

    // Đếm số đơn ứng tuyển đã nộp hôm nay (tính từ 00:00:00)
    let usedToday = 0;
    if (supabase) {
        try {
            const startOfDay = new Date();
            startOfDay.setHours(0, 0, 0, 0);

            const { count, error } = await supabase
                .from('job_applications')
                .select('*', { count: 'exact', head: true })
                .eq('freelancer_id', freelancerId)
                .gte('created_at', startOfDay.toISOString());

            if (!error && count !== null) {
                usedToday = count;
            }
        } catch (e) {
            console.warn('[getFreelancerBidQuota] Error querying today applications:', e.message);
        }
    }

    const remainingDaily = isUnlimited ? 999999 : Math.max(0, dailyLimit - usedToday);
    const totalAvailable = isUnlimited ? 999999 : (remainingDaily + extraBids);

    return {
        plan_id: planId,
        plan_name: planName,
        daily_limit: isUnlimited ? 'Không giới hạn' : dailyLimit,
        numeric_daily_limit: isUnlimited ? 999999 : dailyLimit,
        used_today: usedToday,
        remaining_today: isUnlimited ? 'Không giới hạn' : remainingDaily,
        numeric_remaining_today: remainingDaily,
        extra_bids: extraBids,
        total_available: isUnlimited ? 'Không giới hạn' : totalAvailable,
        numeric_total_available: totalAvailable,
        unlimited: isUnlimited
    };
}

/**
 * Kiểm tra và trừ lượt chào thầu khi nộp đơn ứng tuyển:
 * 1. Nếu Agency (Unlimited): Cho phép nộp
 * 2. Nếu còn lượt trong ngày (> 0): Cho phép nộp
 * 3. Nếu hết lượt ngày nhưng còn extra_bids: Trừ 1 extra_bids và cho phép nộp
 * 4. Nếu hết cả hai: Chặn và trả về thông báo lỗi
 */
async function checkAndConsumeFreelancerBid(freelancerId, supabase) {
    const quota = await getFreelancerBidQuota(freelancerId, supabase);

    if (quota.unlimited) {
        return { allowed: true, consumed_extra: false, quota };
    }

    if (quota.numeric_remaining_today > 0) {
        return { allowed: true, consumed_extra: false, quota };
    }

    // Đã hết lượt ngày, kiểm tra gói mua lẻ dự phòng
    if (quota.extra_bids > 0) {
        const data = readData();
        if (!data.user_addons) data.user_addons = {};
        if (!data.user_addons[freelancerId]) {
            data.user_addons[freelancerId] = { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
        }
        data.user_addons[freelancerId].extra_bids = Math.max(0, (data.user_addons[freelancerId].extra_bids || 0) - 1);
        writeData(data);

        return {
            allowed: true,
            consumed_extra: true,
            message: `Bạn đã sử dụng 1 lượt chào thầu dự phòng. Còn lại: ${data.user_addons[freelancerId].extra_bids} lượt.`,
            quota: {
                ...quota,
                extra_bids: data.user_addons[freelancerId].extra_bids,
                numeric_total_available: data.user_addons[freelancerId].extra_bids
            }
        };
    }

    // Hết lượt hoàn toàn
    return {
        allowed: false,
        error: `Bạn đã sử dụng hết ${quota.daily_limit} lượt chào thầu hôm nay. Lượt chào thầu sẽ tự động làm mới vào 00:00 ngày mai. Bạn có thể mua thêm "Gói 5 Lượt Chào Thầu" (20.000 Token) hoặc nâng cấp gói Chuyên Gia Pro (25 lượt/ngày) để tiếp tục ứng tuyển ngay!`,
        quota
    };
}

module.exports = {
    getAllPlans,
    getUserSubscription,
    getUserSubscriptionHistory,
    getUserAddons,
    subscribeUser,
    purchaseAddon,
    useAddonCredit,
    boostJob,
    isJobBoosted,
    getBoostedJobsMap,
    recordPlatformProfit,
    getPlatformProfitStats,
    createPlan,
    updatePlan,
    deletePlan,
    getDiscountCampaign,
    setDiscountCampaign,
    getAllSubscribersWithUserInfo,
    getAllSubscriptionHistoryWithUserInfo,
    adminExtendSubscription,
    adminCancelSubscription,
    getFreelancerBidQuota,
    checkAndConsumeFreelancerBid
};
