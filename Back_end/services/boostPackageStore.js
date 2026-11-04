const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '../data/boost_settings.json');

// Danh mục gói đẩy tin mặc định theo ngày
const DEFAULT_PACKAGES = [
    {
        id: 'boost_starter',
        name: 'Gói Cơ Bản (Starter)',
        days: 4,
        price: 20000,
        badge: '⚡ [ƯU TIÊN]',
        description: 'Đẩy bài viết lên trang 1 trong 4 ngày đầu',
        is_popular: false
    },
    {
        id: 'boost_standard',
        name: 'Gói Tiêu Chuẩn (Popular)',
        days: 12,
        price: 50000,
        badge: '🔥 [TUYỂN GẤP]',
        description: 'Ghim nhãn Tuyển Gấp nổi bật thu hút Freelancer trong 12 ngày',
        is_popular: true
    },
    {
        id: 'boost_pro',
        name: 'Gói Chuyên Nghiệp (Pro)',
        days: 25,
        price: 100000,
        badge: '💎 [VIP PRO]',
        description: 'Vị trí VIP Pro 25 ngày + Gợi ý cho các lập trình viên hàng đầu',
        is_popular: false
    },
    {
        id: 'boost_vip',
        name: 'Gói Toàn Diện (Diamond VIP)',
        days: 60,
        price: 200000,
        badge: '👑 [DIAMOND VIP]',
        description: 'Ghim tối cao 60 ngày + Hỗ trợ xét duyệt ứng viên 1-1',
        is_popular: false
    }
];

// Danh sách mã giảm giá Voucher mặc định
const DEFAULT_VOUCHERS = [
    {
        code: 'HTWORKNEW',
        type: 'PERCENT', // Giảm theo %
        value: 30, // 30%
        max_discount: 60000,
        min_order: 0,
        description: 'Giảm 30% tối đa 60,000 Token cho khách hàng mới',
        active: true
    },
    {
        code: 'HOTDEAL',
        type: 'FIXED', // Giảm số tiền cố định
        value: 20000, // 20,000 Token
        max_discount: 20000,
        min_order: 50000,
        description: 'Giảm ngay 20,000 Token cho các gói từ 50,000 Token trở lên',
        active: true
    },
    {
        code: 'FREESHIP',
        type: 'FIXED',
        value: 20000,
        max_discount: 20000,
        min_order: 20000,
        description: 'Miễn phí đẩy tin gói Cơ Bản (Giảm 20,000 Token)',
        active: true
    }
];

class BoostPackageStore {
    constructor() {
        this.packages = [...DEFAULT_PACKAGES];
        this.vouchers = [...DEFAULT_VOUCHERS];
        this.firstTimeDiscountPercent = 30; // Mặc định giảm 30% cho khách hàng mua đẩy tin lần đầu
        this.purchasedUsers = new Set(); // Lưu user đã từng mua gói
        this.loadSettings();
    }

    loadSettings() {
        try {
            if (fs.existsSync(DATA_FILE)) {
                const raw = fs.readFileSync(DATA_FILE, 'utf8');
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed.packages) && parsed.packages.length > 0) {
                    this.packages = parsed.packages;
                }
                if (Array.isArray(parsed.vouchers)) {
                    this.vouchers = parsed.vouchers;
                }
                if (typeof parsed.firstTimeDiscountPercent === 'number') {
                    this.firstTimeDiscountPercent = parsed.firstTimeDiscountPercent;
                }
                if (Array.isArray(parsed.purchasedUserIds)) {
                    this.purchasedUsers = new Set(parsed.purchasedUserIds);
                }
            }
        } catch (e) {
            console.warn('[BoostPackageStore] Dùng cấu hình mặc định:', e.message);
        }
    }

    saveSettings() {
        try {
            const data = {
                packages: this.packages,
                vouchers: this.vouchers,
                firstTimeDiscountPercent: this.firstTimeDiscountPercent,
                purchasedUserIds: Array.from(this.purchasedUsers)
            };
            fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
        } catch (e) {
            console.error('[BoostPackageStore] Lỗi lưu cấu hình:', e.message);
        }
    }

    // 1. Kiểm tra xem người dùng có phải là người mua lần đầu không
    isFirstTimeBuyer(userId) {
        if (!userId) return false;
        return !this.purchasedUsers.has(String(userId));
    }

    // 2. Ghi nhận đã mua gói để không áp dụng giảm giá lần đầu nữa
    recordPurchase(userId) {
        if (userId) {
            this.purchasedUsers.add(String(userId));
            this.saveSettings();
        }
    }

    // 3. Lấy danh sách gói đẩy tin (Có tính toán giá ưu đãi cho user)
    getPackagesForUser(userId) {
        const isFirstTime = this.isFirstTimeBuyer(userId);
        return this.packages.map(pkg => {
            let discount = 0;
            if (isFirstTime && this.firstTimeDiscountPercent > 0) {
                discount = Math.round(pkg.price * (this.firstTimeDiscountPercent / 100));
            }
            return {
                ...pkg,
                is_first_time: isFirstTime,
                discount_percent: isFirstTime ? this.firstTimeDiscountPercent : 0,
                discount_amount: discount,
                final_price: Math.max(0, pkg.price - discount)
            };
        });
    }

    // 4. Lấy thông tin một gói theo ID
    getPackageById(packageId) {
        return this.packages.find(p => p.id === packageId) || null;
    }

    // 5. Kiểm tra và áp dụng mã Voucher
    verifyVoucher(voucherCode, packagePrice = 0) {
        if (!voucherCode || typeof voucherCode !== 'string') return null;
        const code = voucherCode.trim().toUpperCase();
        const voucher = this.vouchers.find(v => v.code === code && v.active);

        if (!voucher) {
            return { valid: false, error: 'Mã giảm giá không tồn tại hoặc đã hết hạn.' };
        }

        if (packagePrice < voucher.min_order) {
            return {
                valid: false,
                error: `Mã này chỉ áp dụng cho gói có giá trị từ ${voucher.min_order.toLocaleString()} Token trở lên.`
            };
        }

        let discount = 0;
        if (voucher.type === 'PERCENT') {
            discount = Math.round(packagePrice * (voucher.value / 100));
            if (voucher.max_discount && discount > voucher.max_discount) {
                discount = voucher.max_discount;
            }
        } else {
            discount = voucher.value;
        }

        discount = Math.min(discount, packagePrice);

        return {
            valid: true,
            code: voucher.code,
            type: voucher.type,
            value: voucher.value,
            discount_amount: discount,
            final_price: Math.max(0, packagePrice - discount),
            description: voucher.description
        };
    }

    // 6. Tính toán giá cuối cùng khi đăng Job với Boost Package + Voucher
    calculateFinalPrice(userId, packageId, voucherCode = '') {
        const pkg = this.getPackageById(packageId);
        if (!pkg) {
            return { success: false, error: 'Gói đẩy tin không hợp lệ.' };
        }

        const isFirstTime = this.isFirstTimeBuyer(userId);
        let basePrice = pkg.price;
        let firstTimeDiscount = 0;

        if (isFirstTime && this.firstTimeDiscountPercent > 0) {
            firstTimeDiscount = Math.round(basePrice * (this.firstTimeDiscountPercent / 100));
        }

        let priceAfterFirstTime = basePrice - firstTimeDiscount;
        let voucherDiscount = 0;
        let voucherInfo = null;

        if (voucherCode && voucherCode.trim()) {
            const vRes = this.verifyVoucher(voucherCode, priceAfterFirstTime);
            if (vRes && vRes.valid) {
                voucherDiscount = vRes.discount_amount;
                voucherInfo = vRes;
            }
        }

        const totalDiscount = firstTimeDiscount + voucherDiscount;
        const finalPrice = Math.max(0, basePrice - totalDiscount);

        return {
            success: true,
            package: pkg,
            base_price: basePrice,
            is_first_time: isFirstTime,
            first_time_discount: firstTimeDiscount,
            voucher_discount: voucherDiscount,
            voucher_info: voucherInfo,
            total_discount: totalDiscount,
            final_price: finalPrice,
            days: pkg.days,
            badge: pkg.badge
        };
    }

    // 7. Quyền Admin: Cập nhật gói và danh sách Voucher
    updatePackages(newPackages) {
        if (Array.isArray(newPackages) && newPackages.length > 0) {
            this.packages = newPackages;
            this.saveSettings();
            return true;
        }
        return false;
    }

    updateVouchers(newVouchers) {
        if (Array.isArray(newVouchers)) {
            this.vouchers = newVouchers;
            this.saveSettings();
            return true;
        }
        return false;
    }

    setFirstTimeDiscountPercent(percent) {
        const p = Number(percent);
        if (!isNaN(p) && p >= 0 && p <= 100) {
            this.firstTimeDiscountPercent = p;
            this.saveSettings();
            return true;
        }
        return false;
    }

    getAdminConfig() {
        return {
            packages: this.packages,
            vouchers: this.vouchers,
            firstTimeDiscountPercent: this.firstTimeDiscountPercent,
            totalBoostBuyers: this.purchasedUsers.size
        };
    }
}

const boostPackageStore = new BoostPackageStore();
module.exports = boostPackageStore;
