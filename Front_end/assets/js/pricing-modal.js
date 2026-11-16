/**
 * KGS Work - VIP Membership & Monetization Pricing Modal Framework (v2.0)
 * Tách biệt 100% vai trò Khách hàng (Client) và Freelancer:
 * - Trong Freelancer Hub: Chỉ hiển thị Gói Chuyên Gia IT & Tiện ích Dev (Ẩn hoàn toàn gói Client).
 * - Trong Client Hub: Chỉ hiển thị Gói Doanh Nghiệp & Tiện ích Bài Đăng (Ẩn hoàn toàn gói Freelancer).
 * - Trên Trang Khách vãng lai: Hiển thị đầy đủ cả 2 phân hệ.
 * - Tách biệt Doanh thu thuần của Sàn (Admin Profit) khỏi Tiền Ký Quỹ Escrow.
 */

(function() {
    if (window.KGS_PRICING_INITIALIZED) return;
    window.KGS_PRICING_INITIALIZED = true;

    const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5000'
        : 'https://project-internship-8z76.onrender.com';

    let currentBillingCycle = 'monthly';
    let currentTab = 'client'; // 'client' | 'freelancer' | 'addons'
    let plansData = null;

    // Phát hiện vai trò ngữ cảnh chuẩn xác
    function detectContextRole() {
        let user = null;
        try { user = JSON.parse(localStorage.getItem('user')); } catch (e) {}
        const path = window.location.pathname.toLowerCase();
        if (path.includes('/freelancer/')) return 'freelancer';
        if (path.includes('/user/')) return 'client';
        if (user && user.role === 'freelancer') return 'freelancer';
        if (user && user.role === 'client') return 'client';
        return 'guest';
    }

    // 1. Tạo CSS hiệu ứng cho Modal & Banner
    const styleEl = document.createElement('style');
    styleEl.innerHTML = `
        @keyframes kgsGlow {
            0%, 100% { box-shadow: 0 0 15px rgba(245, 158, 11, 0.4); }
            50% { box-shadow: 0 0 25px rgba(245, 158, 11, 0.7); }
        }
        .kgs-vip-glow { animation: kgsGlow 3s infinite ease-in-out; }
        .pricing-card-hover { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .pricing-card-hover:hover { transform: translateY(-6px); }
    `;
    document.head.appendChild(styleEl);

    // 2. HTML Cấu trúc Modal Bảng Giá VIP
    const modalHtml = `
    <div id="kgsPricingModalOverlay" class="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-md hidden flex items-center justify-center p-3 sm:p-4 md:p-6 transition-opacity duration-300">
        <div id="kgsPricingModalContent" class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-3xl shadow-2xl max-w-5xl w-full max-h-[92vh] flex flex-col overflow-hidden transform scale-95 transition-transform duration-300">
            
            <!-- Header Modal -->
            <div class="p-5 sm:p-6 bg-gradient-to-r from-indigo-900 via-purple-900 to-indigo-950 text-white relative shrink-0">
                <button onclick="window.closePricingModal()" class="absolute top-4 right-4 sm:top-5 sm:right-5 w-9 h-9 rounded-full bg-white/10 hover:bg-white/20 text-white flex items-center justify-center transition text-lg">
                    &times;
                </button>
                <div class="flex items-center space-x-2.5 mb-1.5">
                    <span id="modalHeaderBadge" class="bg-amber-400 text-gray-900 text-[10px] font-black uppercase px-2.5 py-0.5 rounded-full tracking-wider shadow">
                        👑 KGS Work VIP Hub
                    </span>
                    <span class="text-xs text-indigo-200" id="modalHeaderSubtitle">Gói Hội Viên & Dịch Vụ Tăng Tốc</span>
                </div>
                <h2 class="text-xl sm:text-2xl md:text-3xl font-black text-white leading-tight" id="modalMainTitle">
                    Nâng Tầm Trải Nghiệm & Đột Phá Doanh Thu
                </h2>
                <p class="text-xs sm:text-sm text-indigo-200 mt-1 max-w-2xl" id="modalDescription">
                    Tính năng cơ bản luôn <span class="font-bold text-emerald-400">100% Miễn Phí</span>. Nâng cấp để tiếp cận chuyên gia hàng đầu, đẩy tin Top 1 và tối đa hóa cơ hội hợp tác.
                </p>

                <!-- Tabs chọn đối tượng -->
                <div class="flex items-center justify-between flex-wrap gap-3 mt-4 pt-3 border-t border-white/10">
                    <div class="flex items-center bg-black/30 p-1 rounded-2xl border border-white/10" id="pricingTabSwitcher">
                        <button onclick="window.switchPricingTab('client')" id="btnTabClient" class="px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-indigo-200 hover:text-white">
                            <i class="fas fa-building text-amber-300"></i> <span id="labelTabClient">Gói Tuyển Dụng (Khách Hàng)</span>
                        </button>
                        <button onclick="window.switchPricingTab('freelancer')" id="btnTabFreelancer" class="px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-indigo-200 hover:text-white">
                            <i class="fas fa-laptop-code text-cyan-300"></i> <span id="labelTabFreelancer">Gói Chuyên Gia (Freelancer)</span>
                        </button>
                        <button onclick="window.switchPricingTab('addons')" id="btnTabAddons" class="px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-indigo-200 hover:text-white">
                            <i class="fas fa-bolt text-yellow-300"></i> <span id="labelTabAddons">Tiện Ích Mua Lẻ</span>
                        </button>
                    </div>

                    <!-- Chu kỳ thanh toán (Tháng / Năm) -->
                    <div class="flex items-center space-x-2 text-xs" id="billingCycleWrapper">
                        <span class="text-indigo-200 font-semibold">Theo Tháng</span>
                        <button type="button" onclick="window.toggleBillingCycle()" id="btnBillingCycleToggle" class="w-12 h-6 bg-indigo-700 rounded-full p-0.5 transition-colors relative flex items-center">
                            <span id="cycleToggleThumb" class="w-5 h-5 bg-amber-400 rounded-full shadow transform transition-transform"></span>
                        </button>
                        <span class="text-white font-bold flex items-center">
                            Theo Năm <span class="ml-1 bg-emerald-500 text-gray-900 text-[10px] font-black px-1.5 py-0.2 rounded-full uppercase">-20%</span>
                        </span>
                    </div>
                </div>
            </div>

            <!-- Body Modal (Cuộn nội dung gói) -->
            <div class="p-5 sm:p-6 md:p-8 overflow-y-auto flex-1 custom-scrollbar space-y-6">
                <!-- Vùng nạp thẻ gói -->
                <div id="pricingCardsContainer" class="grid grid-cols-1 md:grid-cols-3 gap-5">
                    <!-- Populated dynamically -->
                </div>

                <!-- Footer Ghi chú an toàn -->
                <div class="p-4 rounded-2xl bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-500 dark:text-gray-400">
                    <div class="flex items-center space-x-2">
                        <i class="fas fa-shield-halved text-emerald-500 text-base"></i>
                        <span>Thanh toán minh bạch qua <strong>Số dư ví Token</strong>. Tiền nạp gói được tách biệt vào Doanh thu dịch vụ của Nền tảng. Hủy gói bất cứ lúc nào.</span>
                    </div>
                    <div class="flex items-center space-x-2 shrink-0">
                        <span>Số dư ví của bạn:</span>
                        <span class="font-black text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded-lg border border-emerald-300 dark:border-emerald-800" id="pricingUserBalanceDisplay">-- Token</span>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <!-- Modal Xác Nhận Nâng Cấp / Mua Tiện Ích -->
    <div id="kgsConfirmPurchaseModal" class="fixed inset-0 z-[10000] bg-black/80 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-3xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div class="w-12 h-12 rounded-2xl bg-amber-100 dark:bg-amber-950/60 text-amber-500 flex items-center justify-center text-2xl mx-auto">
                <i class="fas fa-crown"></i>
            </div>
            <div class="text-center">
                <h3 class="text-lg font-black text-gray-900 dark:text-white" id="confirmPurchaseTitle">Xác Nhận Nâng Cấp Gói</h3>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-1" id="confirmPurchaseDesc">Xác nhận thanh toán gói dịch vụ bằng số dư ví Token.</p>
            </div>
            <div class="bg-gray-50 dark:bg-gray-750 p-4 rounded-2xl border border-gray-200 dark:border-gray-700 space-y-2 text-xs">
                <div class="flex justify-between text-gray-500 dark:text-gray-400">
                    <span>Gói đăng ký:</span>
                    <span class="font-bold text-gray-800 dark:text-white" id="confirmPlanName">--</span>
                </div>
                <div class="flex justify-between text-gray-500 dark:text-gray-400">
                    <span>Chi phí thanh toán:</span>
                    <span class="font-black text-amber-600 dark:text-amber-400 text-sm" id="confirmPlanPrice">-- Token</span>
                </div>
                <div class="flex justify-between text-gray-500 dark:text-gray-400 border-t border-gray-200 dark:border-gray-650 pt-2">
                    <span>Số dư hiện tại:</span>
                    <span class="font-semibold text-gray-700 dark:text-gray-300" id="confirmCurrentBalance">-- Token</span>
                </div>
                <div class="flex justify-between text-gray-500 dark:text-gray-400">
                    <span>Số dư sau khi thanh toán:</span>
                    <span class="font-black text-emerald-600 dark:text-emerald-400" id="confirmAfterBalance">-- Token</span>
                </div>
            </div>
            <!-- Dropdown chọn dự án khi mua tiện ích (Chỉ cho Client) -->
            <div id="confirmJobSelectorWrapper" class="hidden text-xs space-y-1">
                <label class="block font-bold text-gray-700 dark:text-gray-300">Áp dụng ngay cho dự án:</label>
                <select id="confirmJobSelect" class="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-650 rounded-xl px-3 py-2 text-xs font-semibold text-gray-800 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-amber-500">
                    <option value="">📦 Lưu vào Kho Tiện Ích để dùng sau (Khuyên dùng)</option>
                </select>
            </div>
            <div id="confirmErrorAlert" class="hidden p-3 rounded-xl bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 text-xs"></div>
            <div class="flex items-center space-x-3 pt-2">
                <button onclick="window.closeConfirmModal()" class="flex-1 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 font-bold text-xs hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    Đóng
                </button>
                <button id="btnProceedPurchase" onclick="window.executePurchase()" class="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-gray-900 font-black text-xs shadow-md transition transform hover:scale-[1.02]">
                    Xác Nhận Thanh Toán
                </button>
            </div>
        </div>
    </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // 3. Tải dữ liệu các gói từ Backend
    async function loadPlans() {
        if (plansData) return plansData;
        try {
            const res = await fetch(`${API_URL}/api/monetization/plans`);
            const json = await res.json();
            if (json.success) {
                plansData = json.plans;
                return plansData;
            }
        } catch (e) {
            console.warn('[Pricing] Fallback to local default plans:', e);
        }
        return null;
    }

    // 4. Lấy số dư ví hiện tại của người dùng
    async function fetchUserBalance() {
        let user = null;
        try { user = JSON.parse(localStorage.getItem('user')); } catch (e) {}
        if (!user || !user.id) return 0;
        try {
            const res = await fetch(`${API_URL}/api/wallet/${user.id}`);
            const data = await res.json();
            return parseFloat(data.balance) || 0;
        } catch (e) {
            return 0;
        }
    }

    // 4b. Lấy thông tin gói đang hoạt động của người dùng
    async function fetchUserSubscription() {
        let user = null;
        try { user = JSON.parse(localStorage.getItem('user')); } catch (e) {}
        if (!user || !user.id) return null;
        try {
            const res = await fetch(`${API_URL}/api/monetization/user-subscription/${user.id}`);
            const data = await res.json();
            if (data.success && data.subscription) {
                const sub = data.subscription;
                localStorage.setItem('kgs_user_sub', JSON.stringify(sub));
                localStorage.setItem('kgs_client_sub_cache', JSON.stringify(sub));
                localStorage.setItem('kgs_freelancer_sub_cache', JSON.stringify(sub));
                return sub;
            }
        } catch (e) {
            console.warn('[Pricing] Error fetching user subscription:', e);
        }
        try {
            return JSON.parse(localStorage.getItem('kgs_user_sub')) || null;
        } catch (e) {
            return null;
        }
    }

    // 5. Render danh sách các Card gói
    async function renderPricingCards() {
        const container = document.getElementById('pricingCardsContainer');
        if (!container) return;
        container.innerHTML = '<div class="col-span-3 text-center py-10 text-gray-400"><i class="fas fa-spinner fa-spin mr-2"></i>Đang tải thông tin gói...</div>';

        const data = await loadPlans();
        const balance = await fetchUserBalance();
        const userSub = await fetchUserSubscription();
        const balEl = document.getElementById('pricingUserBalanceDisplay');
        if (balEl) balEl.innerText = `${balance.toLocaleString('vi-VN')} Token`;

        let list = [];
        const isAnnual = currentBillingCycle === 'annual';
        const role = detectContextRole();

        if (currentTab === 'client') {
            list = data?.client || [];
            document.getElementById('billingCycleWrapper').classList.remove('hidden');
        } else if (currentTab === 'freelancer') {
            list = data?.freelancer || [];
            document.getElementById('billingCycleWrapper').classList.remove('hidden');
        } else {
            // Add-ons: Lọc đúng tiện ích theo vai trò
            document.getElementById('billingCycleWrapper').classList.add('hidden');
            let filteredAddons = data?.addons || [];
            if (role === 'freelancer') {
                filteredAddons = filteredAddons.filter(a => a.for_role === 'freelancer' || !a.for_role);
            } else if (role === 'client') {
                filteredAddons = filteredAddons.filter(a => a.for_role === 'client' || !a.for_role);
            }
            renderAddonCards(filteredAddons, balance);
            return;
        }

        const hasAnyPaidPlan = Boolean(userSub && userSub.is_active && !userSub.is_expired && userSub.plan_id && !userSub.plan_id.includes('starter') && !userSub.plan_id.includes('newbie') && !userSub.plan_id.includes('free'));
        const discount = data?.discount_campaign || { active: false, percent: 0 };
        const isDiscountActive = discount.active && discount.percent > 0;

        let cardsHtml = '';

        // Hiển thị Banner Khuyến Mãi toàn sàn nếu đang mở chiến dịch
        if (isDiscountActive) {
            cardsHtml += `
            <div class="col-span-1 md:col-span-3 p-4 rounded-3xl bg-gradient-to-r from-rose-600 via-amber-500 to-indigo-600 text-white shadow-xl flex flex-col sm:flex-row items-center justify-between gap-3 animate-pulse border border-white/20">
                <div class="flex items-center space-x-3.5">
                    <div class="w-10 h-10 rounded-2xl bg-white/20 flex items-center justify-center text-xl shrink-0">
                        <i class="fas fa-gift text-yellow-200"></i>
                    </div>
                    <div>
                        <div class="font-black text-sm uppercase tracking-wide flex items-center space-x-2">
                            <span>${discount.title || 'ĐẠI TIỆC KHUYẾN MÃI HỘI VIÊN TOÀN SÀN'}</span>
                            <span class="bg-yellow-400 text-gray-900 text-[10px] font-black px-2 py-0.2 rounded-full uppercase">Đang áp dụng</span>
                        </div>
                        <p class="text-xs text-white/90 mt-0.5">Giảm trực tiếp <strong>${discount.percent}%</strong> chi phí Token cho tất cả các gói dịch vụ!</p>
                    </div>
                </div>
                <div class="px-4 py-1.5 rounded-2xl bg-white text-rose-600 font-black text-sm shadow-md shrink-0 uppercase tracking-wider">
                    -${discount.percent}% GIẢM GIÁ
                </div>
            </div>`;
        }

        list.forEach(p => {
            const basePrice = isAnnual ? p.price_annual : p.price_monthly;
            let price = basePrice;
            let hasDiscount = false;

            if (basePrice > 0 && isDiscountActive && (discount.applies_to === 'all' || discount.applies_to === currentTab)) {
                price = Math.round(basePrice * (100 - discount.percent) / 100);
                hasDiscount = true;
            }

            const priceDisplay = price === 0 ? 'Miễn Phí' : `${price.toLocaleString('vi-VN')} Token`;
            const durationDisplay = price === 0 ? 'Mãi Mãi' : (isAnnual ? '/ năm' : '/ tháng');
            const isPopular = p.popular;
            const isCurrentActivePlan = Boolean(userSub && userSub.is_active && !userSub.is_expired && userSub.plan_id === p.id);

            cardsHtml += `
            <div class="pricing-card-hover rounded-3xl p-6 sm:p-7 flex flex-col justify-between border ${
                isCurrentActivePlan
                    ? 'border-2 border-emerald-500 dark:border-emerald-400 bg-gradient-to-b from-emerald-50/80 via-white to-white dark:from-emerald-950/40 dark:via-gray-800 dark:to-gray-800 shadow-xl relative'
                    : (isPopular ? 'border-amber-400 dark:border-amber-500 bg-gradient-to-b from-amber-50/50 via-white to-white dark:from-amber-950/20 dark:via-gray-800 dark:to-gray-800 kgs-vip-glow shadow-xl relative' : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm')
            }">
                ${isCurrentActivePlan ? `
                <div class="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-gradient-to-r from-emerald-600 to-teal-500 text-white text-[10px] font-black uppercase tracking-wider px-3.5 py-1 rounded-full shadow flex items-center space-x-1">
                    <i class="fas fa-check-circle"></i> <span>⭐ ĐÃ NÂNG CẤP (Còn ${userSub.days_remaining || 1} ngày)</span>
                </div>` : (isPopular ? `
                <div class="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-gradient-to-r from-amber-500 to-yellow-400 text-gray-900 text-[10px] font-black uppercase tracking-wider px-3.5 py-1 rounded-full shadow">
                    ⭐ ${p.badge || 'Khuyên Dùng'}
                </div>` : '')}

                <div>
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-lg font-black text-gray-900 dark:text-white">${p.name}</h3>
                        ${!isPopular && !isCurrentActivePlan && p.badge ? `<span class="text-[10px] font-black px-2.5 py-0.5 rounded-full ${p.id.includes('vip') || p.id.includes('agency') ? 'bg-purple-100 dark:bg-purple-900/60 text-purple-700 dark:text-purple-300 border border-purple-300 dark:border-purple-700' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'}">${p.badge}</span>` : ''}
                    </div>

                    <div class="mb-3">
                        ${hasDiscount ? `
                            <div class="flex items-baseline space-x-2">
                                <span class="text-xs text-gray-400 line-through">${basePrice.toLocaleString('vi-VN')} Token</span>
                                <span class="text-2xl sm:text-3xl font-black text-rose-600 dark:text-rose-400">${priceDisplay}</span>
                                <span class="text-xs text-gray-400">${durationDisplay}</span>
                                <span class="text-[10px] font-black bg-rose-100 dark:bg-rose-950 text-rose-600 dark:text-rose-400 px-1.5 py-0.2 rounded">- ${discount.percent}%</span>
                            </div>
                        ` : `
                            <span class="text-2xl sm:text-3xl font-black ${price === 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-900 dark:text-white'}">${priceDisplay}</span>
                            <span class="text-xs text-gray-400">${durationDisplay}</span>
                        `}
                    </div>

                    ${isCurrentActivePlan ? `
                    <div class="text-[11px] text-emerald-600 dark:text-emerald-400 font-bold mb-4 flex items-center bg-emerald-50/60 dark:bg-emerald-950/60 px-2.5 py-1 rounded-lg border border-emerald-200 dark:border-emerald-800">
                        <i class="fas fa-calendar-alt mr-1.5 text-emerald-500"></i> Hết hạn ngày: ${new Date(userSub.expires_at).toLocaleDateString('vi-VN')}
                    </div>` : ''}

                    <ul class="space-y-2.5 text-xs text-gray-600 dark:text-gray-300 mb-6">
                        ${p.features.map(f => `
                            <li class="flex items-start space-x-2">
                                <i class="fas fa-check-circle text-emerald-500 mt-0.5 shrink-0 text-sm"></i>
                                <span>${f}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>

                <div>
                    ${isCurrentActivePlan ? `
                        <button onclick="window.promptPurchase('${p.id}', '${p.name}', ${price}, '${currentTab}', true)" class="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 text-white font-black text-xs shadow-md transition transform hover:scale-[1.02] flex items-center justify-center space-x-1.5">
                            <i class="fas fa-sync-alt text-xs"></i> <span>Gia Hạn Thêm (${isAnnual ? '+1 Năm' : '+1 Tháng'}) - Cộng Dồn</span>
                        </button>
                    ` : (price === 0 ? `
                        <button disabled class="w-full py-2.5 rounded-xl ${hasAnyPaidPlan ? 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500' : 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800'} font-bold text-xs cursor-default">
                            ${hasAnyPaidPlan ? 'Gói Mặc Định Khi Hết Hạn' : '✓ Đang Hoạt Động (Mặc định)'}
                        </button>
                    ` : `
                        <button onclick="window.promptPurchase('${p.id}', '${p.name}', ${price}, '${currentTab}', false)" class="w-full py-2.5 rounded-xl ${isPopular ? 'bg-gradient-to-r from-amber-500 to-yellow-400 hover:from-amber-600 hover:to-yellow-500 text-gray-900' : 'bg-indigo-600 hover:bg-indigo-700 text-white'} font-black text-xs shadow-md transition transform hover:scale-[1.02] flex items-center justify-center space-x-1.5">
                            <i class="fas fa-crown text-xs"></i> <span>${hasAnyPaidPlan ? 'Chuyển Đổi Sang Gói Này' : 'Nâng Cấp Ngay'}</span>
                        </button>
                    `)}
                </div>
            </div>`;
        });

        container.innerHTML = cardsHtml;
    }

    // Render Tab Add-ons Mua Lẻ (Có hiển thị Kho Tiện Ích Đã Mua)
    function renderAddonCards(addons, balance) {
        const container = document.getElementById('pricingCardsContainer');
        if (!container) return;

        let userSub = null;
        try { userSub = JSON.parse(localStorage.getItem('kgs_user_sub')); } catch(e) {}
        const userAddons = userSub?.addons || { job_boost_credits: 0, urgent_tag_credits: 0, extra_bids: 0 };
        const role = detectContextRole();

        let html = '';

        // Hiển thị Kho Tiện Ích nếu có
        if (role === 'client') {
            html += `
            <div class="col-span-1 md:col-span-3 p-4 rounded-3xl bg-indigo-50/80 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs mb-2">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-amber-500 to-indigo-600 text-white flex items-center justify-center font-bold text-sm shadow">
                        <i class="fas fa-boxes-stacked"></i>
                    </div>
                    <div>
                        <span class="font-black text-gray-900 dark:text-white text-sm">Kho Tiện Ích Đang Sở Hữu:</span>
                        <p class="text-gray-500 dark:text-gray-400">Các lượt tiện ích trong kho có thể kích hoạt trực tiếp bất cứ lúc nào trên bài tuyển dụng của bạn.</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2 shrink-0">
                    <span class="px-3 py-1.5 rounded-2xl bg-amber-100 dark:bg-amber-900/60 text-amber-800 dark:text-amber-200 font-bold border border-amber-300 dark:border-amber-700">
                        ⚡ Đẩy Top: <strong>${userAddons.job_boost_credits || 0}</strong> lượt
                    </span>
                    <span class="px-3 py-1.5 rounded-2xl bg-rose-100 dark:bg-rose-900/60 text-rose-800 dark:text-rose-200 font-bold border border-rose-300 dark:border-rose-700">
                        🔥 Tuyển Gấp: <strong>${userAddons.urgent_tag_credits || 0}</strong> lượt
                    </span>
                </div>
            </div>`;
        } else if (role === 'freelancer') {
            html += `
            <div class="col-span-1 md:col-span-3 p-4 rounded-3xl bg-indigo-50/80 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 flex items-center justify-between text-xs mb-2">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-2xl bg-indigo-600 text-white flex items-center justify-center font-bold text-sm shadow">
                        <i class="fas fa-bullseye"></i>
                    </div>
                    <div>
                        <span class="font-black text-gray-900 dark:text-white text-sm">Lượt Chào Thầu Dự Án Dự Trữ:</span>
                        <p class="text-gray-500 dark:text-gray-400">Lượt bids dự trữ bổ sung vào hạn mức ứng tuyển dự án mới trên Sàn Việc Làm.</p>
                    </div>
                </div>
                <span class="px-3.5 py-1.5 rounded-2xl bg-emerald-100 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-200 font-black text-sm border border-emerald-300 dark:border-emerald-700">
                    🎯 +${userAddons.extra_bids || 0} Bids dự trữ
                </span>
            </div>`;
        }

        if (addons.length === 0) {
            html += '<div class="col-span-3 text-center py-10 text-gray-400 text-xs">Chưa có tiện ích mua lẻ nào cho vai trò này.</div>';
            container.innerHTML = html;
            return;
        }

        addons.forEach(a => {
            html += `
            <div class="pricing-card-hover rounded-3xl p-6 border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm flex flex-col justify-between">
                <div>
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-base font-black text-gray-900 dark:text-white">${a.name}</h3>
                        <span class="text-xs font-black text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 px-2.5 py-1 rounded-xl border border-amber-300 dark:border-amber-800">
                            ${a.price.toLocaleString('vi-VN')} Token
                        </span>
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-4 leading-relaxed">${a.desc}</p>
                </div>
                <button onclick="window.promptPurchase('${a.id}', '${a.name}', ${a.price}, 'addon')" class="w-full py-2.5 rounded-xl bg-gray-100 hover:bg-indigo-50 dark:bg-gray-700 dark:hover:bg-gray-650 text-indigo-600 dark:text-indigo-300 font-bold text-xs transition border border-indigo-200 dark:border-indigo-800 flex items-center justify-center space-x-1.5 cursor-pointer">
                    <i class="fas fa-bolt text-amber-400"></i> <span>Kích Hoạt Tiện Ích</span>
                </button>
            </div>`;
        });
        container.innerHTML = html;
    }

    // 6. Global Switchers & Handlers
    window.openPricingModal = function(defaultTab = null) {
        const role = detectContextRole();

        // 1. Phân quyền và Tách biệt tab theo Role
        const btnC = document.getElementById('btnTabClient');
        const btnF = document.getElementById('btnTabFreelancer');
        const titleEl = document.getElementById('modalMainTitle');
        const descEl = document.getElementById('modalDescription');
        const badgeEl = document.getElementById('modalHeaderBadge');

        if (role === 'freelancer') {
            // Trong Freelancer Hub: Ẩn hẳn tab Khách Hàng
            if (btnC) btnC.style.display = 'none';
            if (btnF) btnF.style.display = 'inline-flex';
            currentTab = (defaultTab === 'addons') ? 'addons' : 'freelancer';
            if (titleEl) titleEl.innerText = 'Nâng Tầm Chuyên Gia IT & Bứt Phá Thu Nhập';
            if (descEl) descEl.innerHTML = 'Mở khóa <span class="font-bold text-emerald-400">25 lượt chào thầu/ngày (làm mới mỗi ngày)</span>, gắn huy hiệu Tích Xanh uy tín và nhận thông báo dự án mới trước 15 phút.';
            if (badgeEl) badgeEl.innerText = '⚡ Gói Chuyên Gia IT';
        } else if (role === 'client') {
            // Trong Client Hub: Ẩn hẳn tab Freelancer
            if (btnF) btnF.style.display = 'none';
            if (btnC) btnC.style.display = 'inline-flex';
            currentTab = (defaultTab === 'addons') ? 'addons' : 'client';
            if (titleEl) titleEl.innerText = 'Tuyển Dụng Nhanh Chóng & Tiếp Cận Top 5% Senior Dev';
            if (descEl) descEl.innerHTML = 'Đăng tin không giới hạn, đẩy bài lên <span class="font-bold text-emerald-400">Top 1</span> và mở khóa liên hệ trực tiếp với chuyên gia IT hàng đầu.';
            if (badgeEl) badgeEl.innerText = '👑 Gói Doanh Nghiệp VIP';
        } else {
            // Khách vãng lai: Hiển thị cả 2 tab
            if (btnC) btnC.style.display = 'inline-flex';
            if (btnF) btnF.style.display = 'inline-flex';
            currentTab = defaultTab || 'client';
            if (titleEl) titleEl.innerText = 'Nâng Tầm Trải Nghiệm & Đột Phá Doanh Thu';
            if (descEl) descEl.innerHTML = 'Tính năng cơ bản luôn <span class="font-bold text-emerald-400">100% Miễn Phí</span>. Nâng cấp để bứt phá hiệu quả trên sàn KGS Work.';
            if (badgeEl) badgeEl.innerText = '👑 KGS Work VIP Hub';
        }

        updateTabButtons();
        const overlay = document.getElementById('kgsPricingModalOverlay');
        const content = document.getElementById('kgsPricingModalContent');
        if (overlay && content) {
            overlay.classList.remove('hidden');
            setTimeout(() => {
                content.classList.remove('scale-95');
                content.classList.add('scale-100');
            }, 10);
        }
        renderPricingCards();
    };

    window.closePricingModal = function() {
        const overlay = document.getElementById('kgsPricingModalOverlay');
        const content = document.getElementById('kgsPricingModalContent');
        if (overlay && content) {
            content.classList.remove('scale-100');
            content.classList.add('scale-95');
            setTimeout(() => overlay.classList.add('hidden'), 200);
        }
    };

    window.switchPricingTab = function(tab) {
        currentTab = tab;
        updateTabButtons();
        renderPricingCards();
    };

    function updateTabButtons() {
        const btnC = document.getElementById('btnTabClient');
        const btnF = document.getElementById('btnTabFreelancer');
        const btnA = document.getElementById('btnTabAddons');
        if (!btnC || !btnF || !btnA) return;

        [btnC, btnF, btnA].forEach(btn => {
            btn.className = 'px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-indigo-200 hover:text-white';
        });

        if (currentTab === 'client') {
            btnC.className = 'px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-white bg-indigo-600 shadow';
        } else if (currentTab === 'freelancer') {
            btnF.className = 'px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-white bg-indigo-600 shadow';
        } else {
            btnA.className = 'px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 text-white bg-indigo-600 shadow';
        }
    }

    window.toggleBillingCycle = function() {
        currentBillingCycle = currentBillingCycle === 'monthly' ? 'annual' : 'monthly';
        const thumb = document.getElementById('cycleToggleThumb');
        const btn = document.getElementById('btnBillingCycleToggle');
        if (currentBillingCycle === 'annual') {
            thumb.classList.add('translate-x-6');
            btn.classList.add('bg-emerald-600');
            btn.classList.remove('bg-indigo-700');
        } else {
            thumb.classList.remove('translate-x-6');
            btn.classList.remove('bg-emerald-600');
            btn.classList.add('bg-indigo-700');
        }
        renderPricingCards();
    };

    // 7. Mua gói & Xác nhận
    let pendingPurchase = null;

    window.promptPurchase = async function(planId, planName, price, category, isRenew = false) {
        let user = null;
        try { user = JSON.parse(localStorage.getItem('user')); } catch (e) {}
        if (!user || !user.id) {
            alert('Vui lòng đăng nhập để nâng cấp gói dịch vụ!');
            window.location.href = '../sharedFolder/login.html';
            return;
        }

        const balance = await fetchUserBalance();
        const role = detectContextRole();
        pendingPurchase = { planId, planName, price, category, cycle: currentBillingCycle, userId: user.id, role: user.role || role, isRenew };

        const titleEl = document.getElementById('confirmPurchaseTitle');
        const descEl = document.getElementById('confirmPurchaseDesc');
        const planNameEl = document.getElementById('confirmPlanName');

        if (isRenew) {
            if (titleEl) titleEl.innerText = 'Xác Nhận Gia Hạn Gói Dịch Vụ';
            if (descEl) descEl.innerHTML = 'Thời hạn gói sẽ được <span class="font-bold text-emerald-600 dark:text-emerald-400">CỘNG DỒN TIẾP TỤC</span> vào ngày hết hạn hiện tại của bạn.';
            if (planNameEl) planNameEl.innerText = `${planName} [GIA HẠN +${currentBillingCycle === 'annual' ? '365 Ngày' : '30 Ngày'}]`;
        } else {
            if (titleEl) titleEl.innerText = 'Xác Nhận Nâng Cấp Gói';
            if (descEl) descEl.innerText = 'Xác nhận thanh toán gói dịch vụ bằng số dư ví Token.';
            if (planNameEl) planNameEl.innerText = `${planName} (${category === 'addon' ? 'Dịch vụ lẻ' : (currentBillingCycle === 'annual' ? '1 Năm' : '1 Tháng')})`;
        }

        document.getElementById('confirmPlanPrice').innerText = `${price.toLocaleString('vi-VN')} Token`;
        document.getElementById('confirmCurrentBalance').innerText = `${balance.toLocaleString('vi-VN')} Token`;
        
        const afterBal = balance - price;
        const afterEl = document.getElementById('confirmAfterBalance');
        const errEl = document.getElementById('confirmErrorAlert');
        const proceedBtn = document.getElementById('btnProceedPurchase');

        if (afterBal < 0) {
            afterEl.innerText = 'Không đủ số dư';
            afterEl.className = 'font-bold text-red-500';
            errEl.classList.remove('hidden');
            errEl.innerHTML = `<i class="fas fa-exclamation-triangle mr-1"></i> Số dư còn thiếu ${(price - balance).toLocaleString('vi-VN')} Token. <a href="wallet.html" class="underline font-bold ml-1 text-red-700 dark:text-red-300">Nạp thêm Token ngay</a>`;
            proceedBtn.innerText = 'Nạp Thêm Token Vào Ví';
            proceedBtn.onclick = () => window.location.href = 'wallet.html';
        } else {
            afterEl.innerText = `${afterBal.toLocaleString('vi-VN')} Token`;
            afterEl.className = 'font-black text-emerald-600 dark:text-emerald-400';
            errEl.classList.add('hidden');
            proceedBtn.innerText = isRenew ? 'Xác Nhận Gia Hạn (Cộng Dồn)' : 'Xác Nhận Thanh Toán';
            proceedBtn.onclick = () => window.executePurchase();
        }

        // Xử lý chọn dự án khi mua tiện ích cho Client
        const jobSelectWrapper = document.getElementById('confirmJobSelectorWrapper');
        const jobSelect = document.getElementById('confirmJobSelect');
        if (category === 'addon' && role === 'client' && (planId === 'job_boost' || planId === 'urgent_tag')) {
            if (jobSelectWrapper && jobSelect) {
                jobSelectWrapper.classList.remove('hidden');
                jobSelect.innerHTML = '<option value="">📦 Lưu vào Kho Tiện Ích để dùng sau (Khuyên dùng)</option>';
                try {
                    const jobsRes = await fetch(`${API_URL}/api/jobs?client_id=${user.id}`);
                    const jobsJson = await jobsRes.json();
                    const myJobs = (jobsJson.jobs || []).filter(j => j.client_id === user.id && ['open', 'planning'].includes(j.status));
                    myJobs.forEach(j => {
                        const opt = document.createElement('option');
                        opt.value = j.id;
                        opt.innerText = `🎯 Áp dụng ngay cho: ${j.title.length > 35 ? j.title.substring(0, 35) + '...' : j.title}`;
                        jobSelect.appendChild(opt);
                    });
                } catch (jErr) {}
            }
        } else {
            if (jobSelectWrapper) jobSelectWrapper.classList.add('hidden');
        }

        document.getElementById('kgsConfirmPurchaseModal').classList.remove('hidden');
    };

    window.closeConfirmModal = function() {
        document.getElementById('kgsConfirmPurchaseModal').classList.add('hidden');
        pendingPurchase = null;
    };

    window.executePurchase = async function() {
        if (!pendingPurchase) return;
        const btn = document.getElementById('btnProceedPurchase');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang xử lý...';

        const targetJobId = document.getElementById('confirmJobSelect')?.value || null;

        try {
            const res = await fetch(`${API_URL}/api/monetization/subscribe`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: pendingPurchase.userId,
                    plan_id: pendingPurchase.planId,
                    billing_cycle: pendingPurchase.cycle,
                    role: pendingPurchase.role,
                    job_id: targetJobId
                })
            });

            let result = {};
            try {
                result = await res.json();
            } catch(jsonErr) {
                result = { error: `Máy chủ phản hồi mã ${res.status}. Vui lòng thử lại sau giây lát.` };
            }

            if (!res.ok || result.error) {
                throw new Error(result.error || 'Thanh toán thất bại');
            }

            if (result.subscription) {
                localStorage.setItem('kgs_user_sub', JSON.stringify(result.subscription));
                if (pendingPurchase.role === 'client') {
                    localStorage.setItem('kgs_client_sub_cache', JSON.stringify(result.subscription));
                } else {
                    localStorage.setItem('kgs_freelancer_sub_cache', JSON.stringify(result.subscription));
                }
            }

            if (result.user_addons) {
                localStorage.setItem('kgs_user_addons', JSON.stringify(result.user_addons));
                let cachedSub = null;
                try { cachedSub = JSON.parse(localStorage.getItem('kgs_user_sub')) || {}; } catch(e){}
                cachedSub.addons = result.user_addons;
                localStorage.setItem('kgs_user_sub', JSON.stringify(cachedSub));
            }

            alert(`🎉 ${result.message}`);
            window.closeConfirmModal();
            window.closePricingModal();

            // Cập nhật số dư & Header Badges & Profile
            if (window.loadUserWallet) window.loadUserWallet();
            if (window.loadFreelancerWallet) window.loadFreelancerWallet();
            if (window.syncVipHeaderBadges) window.syncVipHeaderBadges();
            if (window.loadProfile) window.loadProfile();
            if (window.loadUserProfile) window.loadUserProfile();
            if (window.loadMyJobs) window.loadMyJobs();
            if (window.loadUserJobs) window.loadUserJobs();

            const uiBal = document.getElementById('uiBalanceDisplay');
            if (uiBal && result.new_balance !== undefined) {
                uiBal.innerText = `${result.new_balance.toLocaleString('vi-VN')} Token`;
            }

            // Render lại các thẻ gói với thời hạn mới
            setTimeout(() => {
                renderPricingCards();
            }, 500);
        } catch (e) {
            console.error('Lỗi khi nâng cấp gói:', e);
            alert(`❌ Lỗi: ${e.message}`);
        } finally {
            btn.disabled = false;
            btn.innerText = 'Xác Nhận Thanh Toán';
        }
    };

    // 8. Đẩy Top Bài Tuyển Dụng & Gắn Nhãn Tuyển Gấp (Hỗ trợ Sử Dụng Credit Miễn Phí)
    window.boostJobPrompt = async function(jobId, jobTitle, boostType = 'job_boost') {
        let user = null;
        try { user = JSON.parse(localStorage.getItem('user')); } catch (e) {}
        if (!user || !user.id) return;

        let userSub = null;
        try { userSub = JSON.parse(localStorage.getItem('kgs_user_sub')); } catch(e) {}
        const userCredits = userSub?.addons || { job_boost_credits: 0, urgent_tag_credits: 0 };
        const creditCount = boostType === 'urgent_tag' ? (userCredits.urgent_tag_credits || 0) : (userCredits.job_boost_credits || 0);

        // Kiểm tra nếu người dùng đang có lượt miễn phí trong kho
        if (creditCount > 0) {
            const typeLabel = boostType === 'urgent_tag' ? '🔥 Gắn Nhãn Tuyển Gấp (72h)' : '⚡ Đẩy Top 1 (24h)';
            const useFree = confirm(
                `📦 BẠN ĐANG CÓ ${creditCount} LƯỢT TIỆN ÍCH TRONG KHO!\n\n` +
                `Dự án: "${jobTitle}"\n` +
                `Loại tiện ích: ${typeLabel}\n\n` +
                `Bạn có muốn sử dụng 1 lượt có sẵn này (0 Token) ngay bây giờ không?`
            );
            if (useFree) {
                try {
                    const res = await fetch(`${API_URL}/api/monetization/use-addon`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            user_id: user.id,
                            addon_id: boostType,
                            job_id: jobId
                        })
                    });
                    const result = await res.json();
                    if (!res.ok || result.error) throw new Error(result.error || 'Không thể sử dụng tiện ích');
                    alert(`🎉 ${result.message}`);
                    if (window.loadMyJobs) window.loadMyJobs();
                    if (window.loadUserJobs) window.loadUserJobs();
                    return;
                } catch (err) {
                    alert(`❌ Lỗi: ${err.message}`);
                    return;
                }
            }
        }

        const balance = await fetchUserBalance();
        const price = boostType === 'urgent_tag' ? 50000 : 25000;
        const typeLabel = boostType === 'urgent_tag' ? '🔥 GẮN NHÃN TUYỂN GẤP (72H)' : '⚡ ĐẨY TIN TUYỂN DỤNG LÊN TOP 1 (24H)';

        const confirmMsg = `${typeLabel}\n\n` +
            `Dự án: "${jobTitle}"\n` +
            `Thời gian ưu tiên: ${boostType === 'urgent_tag' ? '72 giờ' : '24 giờ'}\n` +
            `Chi phí: ${price.toLocaleString('vi-VN')} Token (Hiện có: ${balance.toLocaleString('vi-VN')} Token)\n\n` +
            `Bạn có chắc chắn muốn kích hoạt tiện ích này không?`;

        if (!confirm(confirmMsg)) return;

        if (balance < price) {
            if (confirm(`Số dư không đủ! Bạn còn thiếu ${(price - balance).toLocaleString('vi-VN')} Token. Bạn có muốn chuyển đến trang Nạp ví không?`)) {
                window.location.href = 'wallet.html';
            }
            return;
        }

        try {
            const res = await fetch(`${API_URL}/api/monetization/boost-job`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: user.id,
                    job_id: jobId,
                    boost_type: boostType
                })
            });

            let result = {};
            try {
                result = await res.json();
            } catch(jsonErr) {
                result = { error: `Máy chủ phản hồi mã ${res.status}. Vui lòng thử lại.` };
            }
            if (!res.ok || result.error) throw new Error(result.error || 'Không thể kích hoạt tiện ích');

            alert(`🚀 ${result.message}`);
            if (window.loadMyJobs) window.loadMyJobs();
            if (window.loadUserJobs) window.loadUserJobs();
            const uiBal = document.getElementById('uiBalanceDisplay');
            if (uiBal && result.new_balance !== undefined) {
                uiBal.innerText = `${result.new_balance.toLocaleString('vi-VN')} Token`;
            }
        } catch (e) {
            alert(`❌ Lỗi: ${e.message}`);
        }
    };

    // 9. Smart Promo Banner Tự Động
    window.renderSmartPromoBanner = function(role = 'client') {
        const bannerKey = `kgs_promo_dismissed_${role}_v1`;
        if (localStorage.getItem(bannerKey)) return;

        const mainEl = document.querySelector('main');
        if (!mainEl) return;

        const bannerId = 'kgsSmartPromoBanner';
        if (document.getElementById(bannerId)) return;

        let userSub = null;
        try { userSub = JSON.parse(localStorage.getItem('kgs_user_sub')); } catch(e) {}
        const isVip = Boolean(userSub && userSub.is_active && !userSub.is_expired && userSub.plan_id && !userSub.plan_id.includes('starter') && !userSub.plan_id.includes('newbie'));

        const isClient = role === 'client';
        const bannerHtml = document.createElement('div');
        bannerHtml.id = bannerId;
        bannerHtml.className = `rounded-2xl p-4 sm:p-5 mb-6 relative overflow-hidden shadow-lg border transition-all duration-300 ${
            isVip
                ? 'bg-gradient-to-r from-amber-950 via-purple-950 to-indigo-950 border-amber-500/40 text-white'
                : (isClient
                    ? 'bg-gradient-to-r from-purple-900 via-indigo-900 to-indigo-950 border-purple-500/30 text-white'
                    : 'bg-gradient-to-r from-amber-900 via-yellow-900 to-stone-900 border-amber-500/30 text-white')
        }`;

        if (isVip) {
            bannerHtml.innerHTML = `
                <button onclick="window.dismissPromoBanner('${role}')" class="absolute top-3 right-3 w-7 h-7 rounded-full bg-white/10 hover:bg-white/20 text-white flex items-center justify-center text-sm transition" title="Đóng thông báo">
                    &times;
                </button>
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pr-6">
                    <div class="flex items-center space-x-3.5">
                        <div class="w-11 h-11 rounded-2xl bg-amber-500/20 text-yellow-300 flex items-center justify-center text-xl shrink-0 shadow-sm border border-amber-400/30">
                            <i class="fas fa-crown"></i>
                        </div>
                        <div>
                            <div class="flex items-center space-x-2">
                                <span class="bg-amber-400 text-amber-950 text-[10px] font-black uppercase px-2 py-0.5 rounded-full">
                                    👑 HỘI VIÊN VIP ĐANG HOẠT ĐỘNG
                                </span>
                                <span class="text-xs text-emerald-300 font-bold flex items-center">
                                    <i class="fas fa-clock mr-1"></i> Còn ${userSub.days_remaining || 1} ngày sử dụng
                                </span>
                            </div>
                            <h4 class="text-sm sm:text-base font-extrabold mt-0.5">
                                Gói: <span class="text-amber-300 font-black">${userSub.plan_name}</span> - Đã kích hoạt đầy đủ đặc quyền ưu tiên cao cấp trên toàn hệ thống!
                            </h4>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2 shrink-0">
                        <button onclick="window.openPricingModal('${isClient ? 'client' : 'freelancer'}')" class="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-yellow-400 hover:from-amber-600 hover:to-yellow-500 text-gray-900 font-black text-xs shadow-md transition transform hover:scale-105 flex items-center">
                            <i class="fas fa-sync-alt mr-1.5 text-gray-900"></i> Gia Hạn / Quản Lý Gói
                        </button>
                    </div>
                </div>
            `;
        } else {
            bannerHtml.innerHTML = `
                <button onclick="window.dismissPromoBanner('${role}')" class="absolute top-3 right-3 w-7 h-7 rounded-full bg-white/10 hover:bg-white/20 text-white flex items-center justify-center text-sm transition" title="Đóng thông báo">
                    &times;
                </button>
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pr-6">
                    <div class="flex items-center space-x-3.5">
                        <div class="w-11 h-11 rounded-2xl ${isClient ? 'bg-purple-500/20 text-purple-300' : 'bg-amber-500/20 text-yellow-300'} flex items-center justify-center text-xl shrink-0">
                            ${isClient ? '<i class="fas fa-rocket"></i>' : '<i class="fas fa-crown"></i>'}
                        </div>
                        <div>
                            <div class="flex items-center space-x-2">
                                <span class="${isClient ? 'bg-purple-400 text-purple-950' : 'bg-yellow-400 text-yellow-950'} text-[10px] font-black uppercase px-2 py-0.5 rounded-full">
                                    ${isClient ? 'ĐẶC QUYỀN DOANH NGHIỆP' : 'DÀNH CHO CHUYÊN GIA IT'}
                                </span>
                                <span class="text-xs text-gray-300">Khởi chạy tính năng VIP</span>
                            </div>
                            <h4 class="text-sm sm:text-base font-extrabold mt-0.5">
                                ${isClient 
                                    ? 'Cần tuyển nhân sự gấp? Đẩy bài lên Top 1 và kết nối trực tiếp với 50+ Senior Dev' 
                                    : 'Tăng 300% tỷ lệ trúng thầu với Huy hiệu Tích Xanh & 50 lượt Bids dự án mỗi tháng'}
                            </h4>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2 shrink-0">
                        <button onclick="window.openPricingModal('${isClient ? 'client' : 'freelancer'}')" class="px-4 py-2 rounded-xl ${isClient ? 'bg-gradient-to-r from-purple-500 to-indigo-500 hover:from-purple-600 hover:to-indigo-600' : 'bg-gradient-to-r from-amber-500 to-yellow-400 hover:from-amber-600 hover:to-yellow-500 text-gray-900'} text-white font-extrabold text-xs shadow-md transition transform hover:scale-105 flex items-center">
                            <i class="fas fa-crown mr-1.5 ${isClient ? 'text-yellow-300' : 'text-gray-900'}"></i> ${isClient ? 'Nâng Cấp Pro Ngay' : 'Khám Phá Gói Pro'}
                        </button>
                    </div>
                </div>
            `;
        }

        mainEl.insertBefore(bannerHtml, mainEl.firstChild);
    };

    window.dismissPromoBanner = function(role) {
        const bannerKey = `kgs_promo_dismissed_${role}_v1`;
        localStorage.setItem(bannerKey, 'true');
        const b = document.getElementById('kgsSmartPromoBanner');
        if (b) {
            b.style.opacity = '0';
            b.style.transform = 'translateY(-10px)';
            setTimeout(() => b.remove(), 300);
        }
    };
})();
