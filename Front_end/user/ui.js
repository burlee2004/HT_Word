// JavaScript logic to build Responsive Sidebar, Header, Mobile Drawer, Bottom Nav, Dark Mode, and Balance globally

document.addEventListener('DOMContentLoaded', () => {
    // 1. Khởi tạo Sidebar (Desktop Sidebar + Mobile Drawer Slide-over)
    const sidebarHtml = 
    `<!-- Desktop Sidebar -->
    <aside class="w-64 bg-white dark:bg-gray-800 shadow-xl h-full flex flex-col transition-colors border-r border-gray-200 dark:border-gray-700 hidden md:flex z-40 shrink-0">
        <div class="p-6 border-b border-gray-100 dark:border-gray-700 flex items-center space-x-3">
            <div class="w-10 h-10 rounded-full flex items-center justify-center shadow-lg overflow-hidden bg-black border border-gray-100 shrink-0">
                <img src="../assets/logo.png" onerror="this.src='logo.png'" alt="HT" class="w-full h-full object-cover">
            </div>
            <span class="font-bold text-xl text-gray-800 dark:text-white tracking-wide">HT Work</span>
        </div>
        
        <nav class="flex-1 p-4 space-y-2 overflow-y-auto">
            <a href="home.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-home w-5"></i> <span>Bảng điều khiển</span>
            </a>
            <a href="wallet.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-wallet w-5"></i> <span>Quản lý Ví</span>
            </a>
            <a href="post-job.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-plus-circle w-5"></i> <span>Đăng Dự Án</span>
            </a>
            <a href="my-requests.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-tasks w-5"></i> <span>Dự án đang mở</span>
            </a>
            <a href="review-work.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-check-double w-5"></i> <span>Quản lý Tiến độ</span>
            </a>
            <a href="direct-chat.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-comments w-5 text-emerald-500"></i> <span>Tin Nhắn 1-1</span>
            </a>
            <a href="profile.html" class="nav-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 hover:text-indigo-600 dark:hover:text-indigo-400 font-medium transition-colors">
                <i class="fas fa-user-circle w-5"></i> <span>Hồ sơ cá nhân</span>
            </a>
        </nav>
        
        <div class="p-4 border-t border-gray-200 dark:border-gray-700">
            <button id="uiLogoutBtn" class="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-red-50 text-red-600 dark:bg-gray-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-gray-600 rounded-xl transition-colors font-medium">
                <i class="fas fa-sign-out-alt"></i> <span>Đăng xuất</span>
            </button>
        </div>
    </aside>

    <!-- Mobile Drawer Sidebar (Trượt êm ái trên màn hình di động) -->
    <div id="mobileDrawerOverlay" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 hidden transition-opacity duration-300 md:hidden">
        <div id="mobileDrawerContent" class="fixed inset-y-0 left-0 w-72 max-w-[85vw] bg-white dark:bg-gray-800 shadow-2xl flex flex-col transform -translate-x-full transition-transform duration-300 ease-in-out border-r border-gray-200 dark:border-gray-700">
            <div class="p-5 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-9 h-9 rounded-full flex items-center justify-center shadow overflow-hidden bg-black shrink-0">
                        <img src="../assets/logo.png" onerror="this.src='logo.png'" alt="HT" class="w-full h-full object-cover">
                    </div>
                    <span class="font-extrabold text-lg text-gray-900 dark:text-white">HT Work</span>
                </div>
                <button id="closeDrawerBtn" class="w-8 h-8 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 flex items-center justify-center hover:bg-gray-200 text-lg">
                    &times;
                </button>
            </div>
            
            <nav class="flex-1 p-4 space-y-1.5 overflow-y-auto">
                <a href="home.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-home w-5 text-indigo-500"></i> <span>Bảng điều khiển</span>
                </a>
                <a href="wallet.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-wallet w-5 text-green-500"></i> <span>Quản lý Ví</span>
                </a>
                <a href="post-job.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-plus-circle w-5 text-blue-500"></i> <span>Đăng Dự Án</span>
                </a>
                <a href="my-requests.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-tasks w-5 text-purple-500"></i> <span>Dự án đang mở</span>
                </a>
                <a href="review-work.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-check-double w-5 text-emerald-500"></i> <span>Quản lý Tiến độ</span>
                </a>
                <a href="direct-chat.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-comments w-5 text-emerald-500"></i> <span>Tin Nhắn 1-1</span>
                </a>
                <a href="profile.html" class="drawer-item flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-gray-700 font-medium">
                    <i class="fas fa-user-circle w-5 text-yellow-500"></i> <span>Hồ sơ cá nhân</span>
                </a>
            </nav>
            
            <div class="p-4 border-t border-gray-100 dark:border-gray-700">
                <button id="uiDrawerLogoutBtn" class="w-full flex items-center justify-center space-x-2 px-4 py-2.5 bg-red-50 text-red-600 dark:bg-gray-700 dark:text-red-400 hover:bg-red-100 rounded-xl transition font-medium">
                    <i class="fas fa-sign-out-alt"></i> <span>Đăng xuất</span>
                </button>
            </div>
        </div>
    </div>`;
    
    const sidebarContainer = document.getElementById('sidebar-container');
    if (sidebarContainer) sidebarContainer.innerHTML = sidebarHtml;

    // 2. Khởi tạo Header (Responsive Header with Mobile Hamburger & Notification)
    const headerHtml = 
    `<header class="h-14 sm:h-16 md:h-20 bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 flex items-center justify-between px-2.5 sm:px-4 md:px-6 transition-colors z-30 relative shrink-0">
        <div class="flex items-center space-x-1.5 sm:space-x-2.5 shrink-0">
            <!-- Nút Hamburger Menu trên Mobile -->
            <button id="mobileMenuToggle" class="md:hidden text-gray-700 dark:text-gray-200 hover:text-indigo-600 w-8 h-8 sm:w-9 sm:h-9 flex items-center justify-center rounded-xl bg-gray-100 dark:bg-gray-700 transition shrink-0">
                <i class="fas fa-bars text-sm sm:text-base"></i>
            </button>
            <h1 class="text-xs sm:text-sm md:text-xl font-bold text-gray-800 dark:text-white truncate max-w-[85px] sm:max-w-[130px] md:max-w-none" id="pageTitle">Dashboard</h1>
        </div>
        
        <div class="flex items-center space-x-1.5 sm:space-x-2 md:space-x-4 shrink-0">
            <!-- Số dư Token -->
            <a href="wallet.html" class="flex items-center space-x-1 bg-indigo-50 dark:bg-gray-700 px-2 py-1 sm:px-3 sm:py-1.5 md:px-4 md:py-2 rounded-full border border-indigo-100 dark:border-gray-600 shadow-sm hover:bg-indigo-100 transition shrink-0">
                <i class="fas fa-gem text-indigo-500 text-[10px] sm:text-xs md:text-sm"></i>
                <span class="font-black text-indigo-700 dark:text-indigo-300 text-[10px] sm:text-xs md:text-sm whitespace-nowrap" id="uiBalanceDisplay">-- Token</span>
            </a>

            <!-- Dark Mode Toggle -->
            <button id="themeToggle" class="text-gray-500 hover:text-indigo-600 dark:text-gray-400 dark:hover:text-indigo-400 transition-colors w-7 h-7 sm:w-8 sm:h-8 md:w-10 md:h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700 shrink-0">
                <i class="fas fa-moon dark:hidden text-xs sm:text-sm md:text-base"></i>
                <i class="fas fa-sun hidden dark:block text-xs sm:text-sm md:text-base"></i>
            </button>

            <!-- Notification Bell -->
            <div class="relative shrink-0">
                <button id="uiBellBtn" onclick="document.getElementById('notiDropdown').classList.toggle('hidden')" class="text-gray-500 hover:text-indigo-600 dark:text-gray-400 dark:hover:text-indigo-400 transition-colors relative w-7 h-7 sm:w-8 sm:h-8 md:w-10 md:h-10 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
                    <i class="fas fa-bell text-xs sm:text-sm md:text-base"></i>
                    <span id="notiBadge" class="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[9px] w-3.5 h-3.5 rounded-full flex items-center justify-center hidden border border-white dark:border-gray-800 font-bold">!</span>
                </button>
                <div id="notiDropdown" class="hidden absolute right-0 mt-3 w-72 sm:w-80 bg-white dark:bg-gray-800 rounded-2xl shadow-2xl border border-gray-100 dark:border-gray-700 z-50 overflow-hidden">
                    <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 border-b dark:border-gray-600 flex justify-between items-center text-gray-800 dark:text-gray-200">
                        <span class="font-bold text-sm"><i class="fas fa-bell text-indigo-500 mr-2"></i>Thông báo</span>
                    </div>
                    <div id="notificationsList" class="max-h-80 overflow-y-auto bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 divide-y divide-gray-100 dark:divide-gray-700">
                        <p class="text-gray-500 text-xs text-center py-4">Đang tải...</p>
                    </div>
                </div>
            </div>
            
            <!-- User Avatar (Icon Profile) -->
            <a href="profile.html" class="w-7 h-7 sm:w-8 sm:h-8 md:w-10 md:h-10 rounded-full border-2 border-indigo-200 dark:border-indigo-500 overflow-hidden shadow-sm hover:border-indigo-400 transition-colors shrink-0 flex items-center justify-center bg-indigo-50">
                <img id="uiAvatar" src="https://ui-avatars.com/api/?name=User&background=4f46e5&color=fff" alt="Avatar" class="w-full h-full object-cover">
            </a>
        </div>
    </header>`;
    const headerContainer = document.getElementById('header-container');
    if (headerContainer) headerContainer.innerHTML = headerHtml;

    // 3. Mobile Bottom Navigation Bar (Thanh điều hướng dưới đáy màn hình phong cách Mobile App)
    const bottomNavHtml = 
    `<nav class="fixed bottom-0 left-0 right-0 z-40 bg-white/95 dark:bg-gray-800/95 backdrop-blur-md border-t border-gray-200 dark:border-gray-700 md:hidden flex justify-around items-center py-1.5 px-2 shadow-lg">
        <a href="home.html" class="bottom-nav-item flex flex-col items-center justify-center py-1 px-2 text-gray-500 dark:text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition">
            <i class="fas fa-home text-lg"></i>
            <span class="text-[10px] font-bold mt-0.5">Trang chủ</span>
        </a>
        <a href="wallet.html" class="bottom-nav-item flex flex-col items-center justify-center py-1 px-2 text-gray-500 dark:text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition">
            <i class="fas fa-wallet text-lg"></i>
            <span class="text-[10px] font-bold mt-0.5">Ví tiền</span>
        </a>
        <a href="post-job.html" class="bottom-nav-item flex flex-col items-center justify-center -mt-4 bg-indigo-600 text-white w-12 h-12 rounded-full shadow-lg hover:bg-indigo-700 transition">
            <i class="fas fa-plus text-lg"></i>
        </a>
        <a href="my-requests.html" class="bottom-nav-item flex flex-col items-center justify-center py-1 px-2 text-gray-500 dark:text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition">
            <i class="fas fa-tasks text-lg"></i>
            <span class="text-[10px] font-bold mt-0.5">Dự án</span>
        </a>
        <a href="profile.html" class="bottom-nav-item flex flex-col items-center justify-center py-1 px-2 text-gray-500 dark:text-gray-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition">
            <i class="fas fa-user text-lg"></i>
            <span class="text-[10px] font-bold mt-0.5">Hồ sơ</span>
        </a>
    </nav>`;

    // Append bottom navigation bar to body
    const existingBottomNav = document.getElementById('mobileBottomNav');
    if (!existingBottomNav) {
        const bottomNavWrapper = document.createElement('div');
        bottomNavWrapper.id = 'mobileBottomNav';
        bottomNavWrapper.innerHTML = bottomNavHtml;
        document.body.appendChild(bottomNavWrapper);
    }

    // 4. Highlight current page across Desktop Sidebar, Mobile Drawer & Bottom Nav
    const currentPage = window.location.pathname.split('/').pop() || 'home.html';
    
    // Desktop Nav
    document.querySelectorAll('.nav-item').forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('bg-indigo-50', 'dark:bg-gray-700', 'text-indigo-600', 'dark:text-indigo-400', 'font-bold');
            link.classList.remove('text-gray-600', 'dark:text-gray-300');
            const titleEl = document.getElementById('pageTitle');
            if (titleEl) {
                titleEl.innerText = link.querySelector('span')?.innerText || 'Dashboard';
            }
        }
    });

    // Mobile Drawer Nav
    document.querySelectorAll('.drawer-item').forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('bg-indigo-50', 'dark:bg-gray-700', 'text-indigo-600', 'dark:text-indigo-400', 'font-bold');
            link.classList.remove('text-gray-700', 'dark:text-gray-300');
        }
    });

    // Mobile Bottom Nav
    document.querySelectorAll('.bottom-nav-item').forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('text-indigo-600', 'dark:text-indigo-400');
            link.classList.remove('text-gray-500', 'dark:text-gray-400');
        }
    });

    // 5. Drawer Toggle Logic (Trượt mở và đóng trên Mobile)
    const toggleBtn = document.getElementById('mobileMenuToggle');
    const overlay = document.getElementById('mobileDrawerOverlay');
    const drawerContent = document.getElementById('mobileDrawerContent');
    const closeBtn = document.getElementById('closeDrawerBtn');

    function openDrawer() {
        if (!overlay || !drawerContent) return;
        overlay.classList.remove('hidden');
        setTimeout(() => {
            drawerContent.classList.remove('-translate-x-full');
        }, 10);
    }

    function closeDrawer() {
        if (!overlay || !drawerContent) return;
        drawerContent.classList.add('-translate-x-full');
        setTimeout(() => {
            overlay.classList.add('hidden');
        }, 300);
    }

    if (toggleBtn) toggleBtn.addEventListener('click', openDrawer);
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeDrawer();
        });
    }

    // 6. Dark Mode Logic
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

    // 7. User Data & Logout
    let user = null;
    try {
        user = JSON.parse(localStorage.getItem('user'));
    } catch(e){}
    if (!user || user.role !== 'client') {
        window.location.href = '../sharedFolder/login.html';
        return;
    }
    
    const uiAvatar = document.getElementById('uiAvatar');
    if (uiAvatar && user.avatar_url) uiAvatar.src = user.avatar_url;
    else if (uiAvatar) uiAvatar.src = 'https://ui-avatars.com/api/?name=' + encodeURIComponent(user.full_name || 'U') + '&background=4f46e5&color=fff';

    const handleLogout = () => {
        localStorage.removeItem('user');
        window.location.href = '../sharedFolder/login.html';
    };

    const logoutBtn = document.getElementById('uiLogoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

    const drawerLogoutBtn = document.getElementById('uiDrawerLogoutBtn');
    if (drawerLogoutBtn) drawerLogoutBtn.addEventListener('click', handleLogout);

    // 8. Fetch Global Balance
    async function loadGlobalBalance() {
        const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
            ? 'http://localhost:5000' 
            : 'https://htwork-backend.onrender.com';
        try {
            const response = await fetch(API_URL + '/api/wallet/' + user.id);
            const balanceElement = document.getElementById('uiBalanceDisplay');
            if (response.ok) {
                const data = await response.json();
                if (balanceElement) {
                    balanceElement.innerText = (data.balance || 0).toLocaleString() + ' Token';
                }
            } else {
                if (balanceElement) balanceElement.innerText = '0 Token';
            }
        } catch (error) {
            console.error('Lỗi lấy số dư:', error);
        }
    }

    // 9. Global Modern Typography & Sleek Scrollbar Style
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
            ::-webkit-scrollbar-thumb:hover { background: rgba(99, 102, 241, 0.6); }
        `;
        document.head.appendChild(style);
    }
    
    loadGlobalBalance();
});
