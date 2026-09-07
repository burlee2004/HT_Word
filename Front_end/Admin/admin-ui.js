// JavaScript framework to build Responsive Sidebar, Header, Mobile Drawer, Bottom Nav, Dark Mode, and Live KPI alerts for Admin Portal

document.addEventListener('DOMContentLoaded', () => {
    // 0. Kiểm tra quyền Admin
    let user = null;
    try {
        user = JSON.parse(localStorage.getItem('user'));
    } catch(e){}

    if (!user || user.role !== 'admin') {
        alert('CẢNH BÁO: Khu vực chỉ dành cho Quản Trị Viên (Admin)! Vui lòng đăng nhập với tài khoản Admin.');
        window.location.href = '../sharedFolder/login.html';
        return;
    }

    const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
        ? 'http://localhost:5000' 
        : 'https://htwork-backend.onrender.com';

    // 1. Khởi tạo Desktop Sidebar & Mobile Drawer
    const sidebarHtml = 
    `<!-- Desktop Sidebar -->
    <aside class="w-64 bg-gray-900 text-white shadow-2xl h-full flex flex-col transition-colors border-r border-gray-800 hidden md:flex z-40 shrink-0">
        <div class="p-5 border-b border-gray-800 flex items-center space-x-3">
            <div class="w-10 h-10 rounded-full flex items-center justify-center shadow-lg overflow-hidden bg-red-600 border border-red-400 shrink-0 text-white font-black text-sm">
                <img src="../assets/logo.png" onerror="this.src='../user/logo.png'" alt="Admin" class="w-full h-full object-cover">
            </div>
            <div>
                <span class="font-black text-lg text-white tracking-wide block leading-tight">HT Work ADMIN</span>
                <span class="text-[10px] font-bold text-red-400 uppercase tracking-widest">Supreme Overseer</span>
            </div>
        </div>
        
        <nav class="flex-1 p-3 space-y-1 overflow-y-auto">
            <a href="dashboard.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-chart-pie w-5 text-indigo-400"></i> <span>Tổng quan & Sổ cái</span>
            </a>
            <a href="users.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-users-cog w-5 text-blue-400"></i> <span>Quản lý Người dùng</span>
            </a>
            <a href="withdrawals.html" class="nav-item flex items-center justify-between px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <div class="flex items-center space-x-3">
                    <i class="fas fa-qrcode w-5 text-emerald-400"></i> <span>Rút tiền VietQR</span>
                </div>
                <span id="navWithdrawBadge" class="hidden bg-emerald-500 text-white text-[10px] px-2 py-0.5 rounded-full font-black">0</span>
            </a>
            <a href="deposits.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-hand-holding-usd w-5 text-teal-400"></i> <span>Duyệt nạp Token</span>
            </a>
            <a href="projects-monitor.html" class="nav-item flex items-center justify-between px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <div class="flex items-center space-x-3">
                    <i class="fas fa-balance-scale w-5 text-red-400"></i> <span>Tòa án Tranh chấp</span>
                </div>
                <span id="navDisputeBadge" class="hidden bg-red-500 text-white text-[10px] px-2 py-0.5 rounded-full font-black animate-pulse">0</span>
            </a>
            <a href="audit-logs.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-clipboard-list w-5 text-amber-400"></i> <span>Nhật ký Log A-Z</span>
            </a>
            <a href="categories.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-folder-tree w-5 text-purple-400"></i> <span>Quản lý Danh mục</span>
            </a>
            <a href="blockchain-audit.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-shield-alt w-5 text-cyan-400"></i> <span>Kiểm toán Blockchain</span>
            </a>
            <a href="escrow-security-test.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                <i class="fas fa-vial w-5 text-pink-400"></i> <span>Test Bảo Mật Escrow</span>
            </a>
        </nav>
        
        <div class="p-4 border-t border-gray-800">
            <button id="uiLogoutBtn" class="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-red-950/60 text-red-400 hover:bg-red-900/80 rounded-xl transition font-bold text-xs">
                <i class="fas fa-sign-out-alt"></i> <span>Đăng xuất Quản trị</span>
            </button>
        </div>
    </aside>

    <!-- Mobile Drawer Overlay -->
    <div id="mobileDrawerOverlay" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden transition-opacity duration-300 md:hidden">
        <div id="mobileDrawerContent" class="fixed inset-y-0 left-0 w-72 max-w-[85vw] bg-gray-900 text-white shadow-2xl flex flex-col transform -translate-x-full transition-transform duration-300 ease-in-out border-r border-gray-800">
            <div class="p-5 border-b border-gray-800 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-9 h-9 rounded-full flex items-center justify-center bg-red-600 text-white font-black text-xs">
                        HT
                    </div>
                    <div>
                        <span class="font-black text-base text-white block">HT Work ADMIN</span>
                        <span class="text-[9px] font-bold text-red-400 uppercase">Supreme Overseer</span>
                    </div>
                </div>
                <button id="closeDrawerBtn" class="w-8 h-8 rounded-full bg-gray-800 text-gray-300 flex items-center justify-center hover:bg-gray-700 text-lg">
                    &times;
                </button>
            </div>
            
            <nav class="flex-1 p-3 space-y-1 overflow-y-auto text-xs">
                <a href="dashboard.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-chart-pie w-5 text-indigo-400"></i> <span>Tổng quan & Sổ cái</span>
                </a>
                <a href="users.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-users-cog w-5 text-blue-400"></i> <span>Quản lý Người dùng</span>
                </a>
                <a href="withdrawals.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-qrcode w-5 text-emerald-400"></i> <span>Rút tiền VietQR</span>
                </a>
                <a href="deposits.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-hand-holding-usd w-5 text-teal-400"></i> <span>Duyệt nạp Token</span>
                </a>
                <a href="projects-monitor.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-balance-scale w-5 text-red-400"></i> <span>Tòa án Tranh chấp</span>
                </a>
                <a href="audit-logs.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-clipboard-list w-5 text-amber-400"></i> <span>Nhật ký Log A-Z</span>
                </a>
                <a href="categories.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-folder-tree w-5 text-purple-400"></i> <span>Quản lý Danh mục</span>
                </a>
                <a href="blockchain-audit.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-shield-alt w-5 text-cyan-400"></i> <span>Kiểm toán Blockchain</span>
                </a>
                <a href="escrow-security-test.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold">
                    <i class="fas fa-vial w-5 text-pink-400"></i> <span>Test Bảo Mật Escrow</span>
                </a>
            </nav>
            
            <div class="p-4 border-t border-gray-800">
                <button id="uiDrawerLogoutBtn" class="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-red-950/60 text-red-400 hover:bg-red-900 rounded-xl transition font-bold text-xs">
                    <i class="fas fa-sign-out-alt"></i> <span>Đăng xuất</span>
                </button>
            </div>
        </div>
    </div>`;
    
    const sidebarContainer = document.getElementById('sidebar-container');
    if (sidebarContainer) sidebarContainer.innerHTML = sidebarHtml;

    // 2. Khởi tạo Header
    const headerHtml = 
    `<header class="h-14 sm:h-16 md:h-20 bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 flex items-center justify-between px-3 sm:px-4 md:px-6 transition-colors z-30 relative shrink-0">
        <div class="flex items-center space-x-2 sm:space-x-3 shrink-0">
            <!-- Nút Hamburger Menu trên Mobile -->
            <button id="mobileMenuToggle" class="md:hidden text-gray-700 dark:text-gray-200 hover:text-red-500 w-8 h-8 sm:w-9 sm:h-9 flex items-center justify-center rounded-xl bg-gray-100 dark:bg-gray-700 transition shrink-0">
                <i class="fas fa-bars text-sm sm:text-base"></i>
            </button>
            <div>
                <h1 class="text-sm sm:text-base md:text-xl font-black text-gray-800 dark:text-white truncate max-w-[140px] sm:max-w-[220px] md:max-w-none" id="pageTitle">Admin Dashboard</h1>
            </div>
        </div>
        
        <div class="flex items-center space-x-2 sm:space-x-3 md:space-x-4 shrink-0">
            <!-- Alert Badge Tranh chấp -->
            <a href="projects-monitor.html" id="headerDisputeAlert" class="hidden items-center space-x-1.5 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-900 text-red-600 dark:text-red-400 px-2.5 py-1.5 rounded-full text-xs font-black shadow-sm hover:bg-red-100 transition">
                <i class="fas fa-exclamation-circle text-red-500 animate-pulse"></i>
                <span id="headerDisputeCount">0 Tranh chấp</span>
            </a>

            <!-- Alert Badge Rút tiền -->
            <a href="withdrawals.html" id="headerWithdrawAlert" class="hidden items-center space-x-1.5 bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-900 text-amber-600 dark:text-amber-400 px-2.5 py-1.5 rounded-full text-xs font-black shadow-sm hover:bg-amber-100 transition">
                <i class="fas fa-money-bill-wave text-amber-500"></i>
                <span id="headerWithdrawCount">0 Lệnh rút</span>
            </a>

            <!-- Dark Mode Toggle -->
            <button id="themeToggle" class="text-gray-500 hover:text-red-600 dark:text-gray-400 dark:hover:text-red-400 transition-colors w-8 h-8 sm:w-9 sm:h-9 md:w-10 md:h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700 shrink-0" title="Chuyển chế độ sáng/tối">
                <i class="fas fa-moon dark:hidden text-xs sm:text-sm md:text-base"></i>
                <i class="fas fa-sun hidden dark:block text-xs sm:text-sm md:text-base text-yellow-400"></i>
            </button>

            <!-- Admin Info -->
            <div class="flex items-center space-x-2 pl-2 border-l border-gray-200 dark:border-gray-700">
                <div class="w-8 h-8 sm:w-9 sm:h-9 md:w-10 md:h-10 rounded-full border-2 border-red-400 overflow-hidden shadow-sm flex items-center justify-center bg-red-600 text-white font-black text-xs shrink-0">
                    AD
                </div>
                <div class="hidden lg:block text-left">
                    <span class="text-xs font-black text-gray-800 dark:text-white block truncate max-w-[120px]">${user.full_name || 'Admin'}</span>
                    <span class="text-[10px] text-red-500 font-bold uppercase block">Super Admin</span>
                </div>
            </div>
        </div>
    </header>`;
    const headerContainer = document.getElementById('header-container') || document.getElementById('topbar-container');
    if (headerContainer) headerContainer.innerHTML = headerHtml;

    // 3. Highlight current page
    const currentPage = window.location.pathname.split('/').pop() || 'dashboard.html';
    
    document.querySelectorAll('.nav-item').forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('bg-red-600', 'text-white', 'font-black', 'shadow-md');
            link.classList.remove('text-gray-300');
            const titleEl = document.getElementById('pageTitle');
            if (titleEl) {
                titleEl.innerText = link.querySelector('span')?.innerText || 'Admin Dashboard';
            }
        }
    });

    document.querySelectorAll('.drawer-item').forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('bg-red-600', 'text-white', 'font-black');
            link.classList.remove('text-gray-300');
        }
    });

    // 4. Drawer Toggle Logic
    const toggleBtn = document.getElementById('mobileMenuToggle');
    const overlay = document.getElementById('mobileDrawerOverlay');
    const drawerContent = document.getElementById('mobileDrawerContent');
    const closeBtn = document.getElementById('closeDrawerBtn');

    function openDrawer() {
        if (!overlay || !drawerContent) return;
        overlay.classList.remove('hidden');
        setTimeout(() => drawerContent.classList.remove('-translate-x-full'), 10);
    }

    function closeDrawer() {
        if (!overlay || !drawerContent) return;
        drawerContent.classList.add('-translate-x-full');
        setTimeout(() => overlay.classList.add('hidden'), 300);
    }

    if (toggleBtn) toggleBtn.addEventListener('click', openDrawer);
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeDrawer();
        });
    }

    // 5. Dark Mode Logic
    const themeToggle = document.getElementById('themeToggle');
    const htmlEl = document.documentElement;
    
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        htmlEl.classList.add('dark');
    } else {
        htmlEl.classList.remove('dark');
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            if (htmlEl.classList.contains('dark')) {
                htmlEl.classList.remove('dark');
                localStorage.setItem('theme', 'light');
            } else {
                htmlEl.classList.add('dark');
                localStorage.setItem('theme', 'dark');
            }
        });
    }

    // 6. Logout
    const handleLogout = () => {
        localStorage.removeItem('user');
        window.location.href = '../sharedFolder/login.html';
    };

    const logoutBtn = document.getElementById('uiLogoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

    const drawerLogoutBtn = document.getElementById('uiDrawerLogoutBtn');
    if (drawerLogoutBtn) drawerLogoutBtn.addEventListener('click', handleLogout);

    // 7. Fetch Live Admin Alerts
    async function loadAdminAlerts() {
        try {
            const res = await fetch(`${API_URL}/api/admin/stats`);
            const data = await res.json();
            if (res.ok && data.stats) {
                const s = data.stats;
                
                // Dispute alert
                const dAlert = document.getElementById('headerDisputeAlert');
                const dCount = document.getElementById('headerDisputeCount');
                const navDBadge = document.getElementById('navDisputeBadge');
                if (s.disputed_jobs > 0) {
                    if (dAlert) { dAlert.classList.remove('hidden'); dAlert.classList.add('flex'); }
                    if (dCount) dCount.innerText = `${s.disputed_jobs} Tranh chấp`;
                    if (navDBadge) { navDBadge.classList.remove('hidden'); navDBadge.innerText = s.disputed_jobs; }
                } else {
                    if (dAlert) { dAlert.classList.add('hidden'); dAlert.classList.remove('flex'); }
                    if (navDBadge) navDBadge.classList.add('hidden');
                }

                // Withdraw alert
                const wAlert = document.getElementById('headerWithdrawAlert');
                const wCount = document.getElementById('headerWithdrawCount');
                const navWBadge = document.getElementById('navWithdrawBadge');
                if (s.pending_withdraw_count > 0) {
                    if (wAlert) { wAlert.classList.remove('hidden'); wAlert.classList.add('flex'); }
                    if (wCount) wCount.innerText = `${s.pending_withdraw_count} Lệnh rút (${(s.pending_withdraw_amount/1000).toFixed(0)}k)`;
                    if (navWBadge) { navWBadge.classList.remove('hidden'); navWBadge.innerText = s.pending_withdraw_count; }
                } else {
                    if (wAlert) { wAlert.classList.add('hidden'); wAlert.classList.remove('flex'); }
                    if (navWBadge) navWBadge.classList.add('hidden');
                }
            }
        } catch (e) {
            console.error('Lỗi load admin alerts:', e);
        }
    }

    // 8. Global Modern Typography & Sleek Scrollbar Style
    if (!document.getElementById('htwork-global-style')) {
        const fontLink = document.createElement('link');
        fontLink.rel = 'stylesheet';
        fontLink.href = 'https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800;900&display=swap';
        document.head.appendChild(fontLink);

        const style = document.createElement('style');
        style.id = 'htwork-global-style';
        style.innerHTML = `
            * {
                font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }
            ::-webkit-scrollbar { width: 6px; height: 6px; }
            ::-webkit-scrollbar-track { background: transparent; }
            ::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, 0.35); border-radius: 9999px; }
            ::-webkit-scrollbar-thumb:hover { background: rgba(239, 68, 68, 0.6); }
        `;
        document.head.appendChild(style);
    }

    loadAdminAlerts();
    window.loadAdminAlerts = loadAdminAlerts;
});
