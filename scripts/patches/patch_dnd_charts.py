import re

# Update chart-builder.html
builder_html = """<!DOCTYPE html>
<html lang="vi" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KGS Work Admin - Quản Lý Biểu Đồ (Charts Builder)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: { 50: '#eef2ff', 100: '#e0e7ff', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca', 900: '#312e81' },
                        dark: { 800: '#1e293b', 850: '#172033', 900: '#0f172a', 950: '#020617' }
                    }
                }
            }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
    <script src="../assets/js/token-formatter.js"></script>
</head>
<body class="bg-slate-50 dark:bg-dark-950 text-slate-800 dark:text-slate-100 font-sans transition-colors duration-200">

    <div class="flex h-screen overflow-hidden">
        <aside id="sidebar-container" class="shrink-0"></aside>

        <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
            <header id="topbar-container" class="shrink-0"></header>

            <main class="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6">
                
                <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-white dark:bg-dark-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                    <div>
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400 flex items-center justify-center font-bold text-lg">
                                <i class="fas fa-sliders-h"></i>
                            </div>
                            <div>
                                <h1 class="text-xl font-bold text-slate-900 dark:text-white leading-tight">Tùy Chỉnh Dashboard</h1>
                                <p class="text-sm text-slate-500 dark:text-slate-400 mt-0.5">Kéo thả để sắp xếp các biểu đồ trên trang chủ</p>
                            </div>
                        </div>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="previewLayout()" class="px-4 py-2 bg-slate-100 dark:bg-dark-800 hover:bg-slate-200 dark:hover:bg-dark-700 text-slate-700 dark:text-slate-300 rounded-xl font-medium text-sm transition-colors flex items-center gap-2">
                            <i class="fas fa-eye"></i> Xem trước
                        </button>
                        <button onclick="saveLayout()" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl font-medium text-sm transition-colors flex items-center gap-2 shadow-lg shadow-brand-500/30">
                            <i class="fas fa-save"></i> Lưu Cấu Hình
                        </button>
                    </div>
                </div>

                <!-- Drag & Drop Container -->
                <div class="bg-white dark:bg-dark-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                    <h2 class="text-lg font-bold mb-4">Thứ tự hiển thị biểu đồ</h2>
                    <ul id="chart-list" class="space-y-3">
                        <li data-id="cashflow" class="p-4 bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-slate-700 rounded-xl flex justify-between items-center cursor-move hover:border-brand-500 transition-colors">
                            <div class="flex items-center gap-3"><i class="fas fa-chart-line text-green-500 text-xl"></i> <span class="font-bold">Biểu đồ Dòng tiền (Cashflow)</span></div>
                            <i class="fas fa-grip-lines text-slate-400"></i>
                        </li>
                        <li data-id="jobs" class="p-4 bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-slate-700 rounded-xl flex justify-between items-center cursor-move hover:border-brand-500 transition-colors">
                            <div class="flex items-center gap-3"><i class="fas fa-project-diagram text-blue-500 text-xl"></i> <span class="font-bold">Biểu đồ Tỷ lệ Dự án</span></div>
                            <i class="fas fa-grip-lines text-slate-400"></i>
                        </li>
                        <li data-id="users" class="p-4 bg-slate-50 dark:bg-dark-800 border border-slate-200 dark:border-slate-700 rounded-xl flex justify-between items-center cursor-move hover:border-brand-500 transition-colors">
                            <div class="flex items-center gap-3"><i class="fas fa-users text-amber-500 text-xl"></i> <span class="font-bold">Biểu đồ Người dùng mới</span></div>
                            <i class="fas fa-grip-lines text-slate-400"></i>
                        </li>
                    </ul>
                </div>

                <!-- Preview Modal -->
                <div id="previewModal" class="hidden fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
                    <div class="bg-white dark:bg-dark-900 w-full max-w-4xl rounded-2xl shadow-2xl overflow-hidden flex flex-col">
                        <div class="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
                            <h2 class="font-bold text-lg"><i class="fas fa-eye text-brand-500 mr-2"></i>Chế độ xem trước (Preview)</h2>
                            <button onclick="document.getElementById('previewModal').classList.add('hidden')" class="text-slate-400 hover:text-red-500"><i class="fas fa-times text-xl"></i></button>
                        </div>
                        <div class="p-6 bg-slate-100 dark:bg-dark-950 flex-1 overflow-y-auto">
                            <div id="previewContainer" class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                <!-- Chỗ này sẽ inject mockup -->
                            </div>
                        </div>
                    </div>
                </div>

            </main>
        </div>
    </div>
    
    <script src="admin-ui.js"></script>
    <script>
        // Init Drag & Drop
        new Sortable(document.getElementById('chart-list'), {
            animation: 150,
            ghostClass: 'opacity-50'
        });

        // Load current config
        async function loadConfig() {
            try {
                const res = await fetch(`${API_URL}/api/admin/dashboard-config`);
                const config = await res.json();
                
                if (config && config.chartsOrder) {
                    const list = document.getElementById('chart-list');
                    config.chartsOrder.forEach(id => {
                        const item = list.querySelector(`[data-id="${id}"]`);
                        if(item) list.appendChild(item); // move to end
                    });
                }
            } catch (e) { console.error("Error loading config", e); }
        }

        function previewLayout() {
            const order = Array.from(document.getElementById('chart-list').children).map(li => li.getAttribute('data-id'));
            const container = document.getElementById('previewContainer');
            container.innerHTML = ''; // clear

            const chartHTML = {
                'cashflow': `<div class="bg-white dark:bg-dark-800 p-4 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm col-span-1"><div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/2 mb-4"></div><div class="h-32 bg-green-100 dark:bg-green-900/30 rounded w-full flex items-center justify-center text-green-500 font-bold"><i class="fas fa-chart-line text-3xl"></i></div></div>`,
                'jobs': `<div class="bg-white dark:bg-dark-800 p-4 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm col-span-1"><div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/2 mb-4"></div><div class="h-32 bg-blue-100 dark:bg-blue-900/30 rounded w-full flex items-center justify-center text-blue-500 font-bold"><i class="fas fa-project-diagram text-3xl"></i></div></div>`,
                'users': `<div class="bg-white dark:bg-dark-800 p-4 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm lg:col-span-2"><div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/4 mb-4"></div><div class="h-40 bg-amber-100 dark:bg-amber-900/30 rounded w-full flex items-center justify-center text-amber-500 font-bold"><i class="fas fa-users text-3xl"></i></div></div>`
            };

            order.forEach(id => {
                container.innerHTML += chartHTML[id];
            });

            document.getElementById('previewModal').classList.remove('hidden');
        }

        async function saveLayout() {
            const order = Array.from(document.getElementById('chart-list').children).map(li => li.getAttribute('data-id'));
            
            try {
                const res = await fetch(`${API_URL}/api/admin/dashboard-config`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ chartsOrder: order })
                });
                
                if (res.ok) {
                    alert('Lưu cấu hình thành công! Dashboard sẽ hiển thị theo thứ tự này.');
                }
            } catch (e) {
                alert('Lỗi khi lưu cấu hình.');
            }
        }

        document.addEventListener('DOMContentLoaded', loadConfig);
    </script>
</body>
</html>
"""

with open(r'd:\Project_internship\New_code\code\Front_end\Admin\chart-builder.html', 'w', encoding='utf-8') as f:
    f.write(builder_html)

# Update dashboard.html logic to respect config
dash_path = r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html'
with open(dash_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the hardcoded charts grid with a dynamic container
content = re.sub(r'<!-- Charts Section \(Mini\) -->.*?</div>\s*<!-- Biểu đồ Trạng thái Dự án -->.*?</div>\s*</div>', 
'''<!-- Dynamic Charts Container -->
            <div id="dynamicChartsContainer" class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6"></div>''', content, flags=re.DOTALL)

# Update JS logic in dashboard
js_logic = """
        let chartsInstances = {};

        async function loadMiniCharts() {
            try {
                const isDark = document.documentElement.classList.contains('dark');
                const theme = {
                    textColor: isDark ? '#9ca3af' : '#6b7280',
                    gridColor: isDark ? '#374151' : '#f3f4f6'
                };

                // Get layout config
                let order = ['cashflow', 'jobs', 'users']; // default
                try {
                    const cfgRes = await fetch(`${API_URL}/api/admin/dashboard-config`);
                    const cfg = await cfgRes.json();
                    if(cfg && cfg.chartsOrder) order = cfg.chartsOrder;
                } catch(e) {}

                const container = document.getElementById('dynamicChartsContainer');
                container.innerHTML = ''; // clear

                // HTML templates for charts
                const templates = {
                    'cashflow': `<div class="bg-white dark:bg-gray-800 p-5 rounded-3xl border border-gray-100 dark:border-gray-700 shadow-sm col-span-1"><div class="flex justify-between items-center mb-4"><h2 class="text-sm font-black text-gray-900 dark:text-white uppercase"><i class="fas fa-chart-line text-green-500 mr-2"></i>Dòng tiền (7 Ngày)</h2></div><div class="relative h-48 w-full"><canvas id="c_cashflow"></canvas></div></div>`,
                    'jobs': `<div class="bg-white dark:bg-gray-800 p-5 rounded-3xl border border-gray-100 dark:border-gray-700 shadow-sm col-span-1"><div class="flex justify-between items-center mb-4"><h2 class="text-sm font-black text-gray-900 dark:text-white uppercase"><i class="fas fa-project-diagram text-blue-500 mr-2"></i>Tỷ lệ Dự án</h2></div><div class="relative h-48 w-full flex justify-center"><canvas id="c_jobs"></canvas></div></div>`,
                    'users': `<div class="bg-white dark:bg-gray-800 p-5 rounded-3xl border border-gray-100 dark:border-gray-700 shadow-sm lg:col-span-2"><div class="flex justify-between items-center mb-4"><h2 class="text-sm font-black text-gray-900 dark:text-white uppercase"><i class="fas fa-users text-amber-500 mr-2"></i>Tăng trưởng Người dùng</h2></div><div class="relative h-56 w-full"><canvas id="c_users"></canvas></div></div>`
                };

                // Render DOM
                order.forEach(id => {
                    if(templates[id]) container.innerHTML += templates[id];
                });

                // Fetch and Render Data for each
                if(order.includes('cashflow')) {
                    fetch(`${API_URL}/api/admin/charts/cashflow`).then(r=>r.json()).then(cashData => {
                        if(cashData.success) {
                            const ctx = document.getElementById('c_cashflow').getContext('2d');
                            new Chart(ctx, {
                                type: 'line',
                                data: {
                                    labels: cashData.data.map(d => new Date(d.date).getDate() + '/' + (new Date(d.date).getMonth()+1)),
                                    datasets: [
                                        { label: 'Nạp', data: cashData.data.map(d=>d.deposit), borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', fill: true, tension: 0.4 },
                                        { label: 'Rút', data: cashData.data.map(d=>d.withdraw), borderColor: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', fill: true, tension: 0.4 }
                                    ]
                                },
                                options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor } }, y: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor } } }, plugins: { legend: { labels: { color: theme.textColor } } } }
                            });
                        }
                    });
                }

                if(order.includes('jobs')) {
                    fetch(`${API_URL}/api/admin/charts/jobs`).then(r=>r.json()).then(jobsData => {
                        if(jobsData.success) {
                            const ctx = document.getElementById('c_jobs').getContext('2d');
                            new Chart(ctx, {
                                type: 'doughnut',
                                data: {
                                    labels: ['Đang làm', 'Hoàn thành', 'Tranh chấp'],
                                    datasets: [{
                                        data: [jobsData.data.in_progress + jobsData.data.planning, jobsData.data.completed, jobsData.data.disputed],
                                        backgroundColor: ['#3b82f6', '#10b981', '#ef4444'], borderWidth: 0
                                    }]
                                },
                                options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { position: 'right', labels: { color: theme.textColor } } } }
                            });
                        }
                    });
                }

                if(order.includes('users')) {
                    fetch(`${API_URL}/api/admin/charts/users`).then(r=>r.json()).then(usersData => {
                        if(usersData.success) {
                            const ctx = document.getElementById('c_users').getContext('2d');
                            new Chart(ctx, {
                                type: 'bar',
                                data: {
                                    labels: usersData.data.map(d => new Date(d.date).getDate() + '/' + (new Date(d.date).getMonth()+1)),
                                    datasets: [
                                        { label: 'KH mới', data: usersData.data.map(d=>d.clients), backgroundColor: '#8b5cf6', borderRadius: 4 },
                                        { label: 'FL mới', data: usersData.data.map(d=>d.freelancers), backgroundColor: '#0ea5e9', borderRadius: 4 }
                                    ]
                                },
                                options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor } }, y: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor, stepSize:1 } } }, plugins: { legend: { labels: { color: theme.textColor } } } }
                            });
                        }
                    });
                }

            } catch (e) {
                console.error("Lỗi tải charts", e);
            }
        }
"""

content = re.sub(r'let miniCashflowChart = null;[\s\S]*?}\s*\}', js_logic, content)

with open(dash_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Updated dashboard and builder")
