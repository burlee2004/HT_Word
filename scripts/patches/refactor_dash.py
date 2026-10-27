import re

content = open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', encoding='utf-8').read()

# 1. Add GridStack CSS/JS to dashboard.html
if 'gridstack' not in content:
    content = content.replace('</head>', '    <!-- GridStack.js -->\n    <link href="https://cdn.jsdelivr.net/npm/gridstack@8.2.1/dist/gridstack.min.css" rel="stylesheet"/>\n    <script src="https://cdn.jsdelivr.net/npm/gridstack@8.2.1/dist/gridstack-all.js"></script>\n</head>')

# 2. Add style for widgets
if '.grid-stack-item-content' not in content:
    style = '''
    <style>
        .grid-stack-item-content {
            background-color: white;
            border-radius: 1.5rem;
            box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            border: 1px solid #f3f4f6;
        }
        .dark .grid-stack-item-content {
            background-color: #1f2937;
            border-color: #374151;
            color: white;
        }
        .chart-container {
            position: relative;
            flex-grow: 1;
            width: 100%;
            height: 100%;
            min-height: 200px;
        }
    </style>
'''
    content = content.replace('</head>', style + '</head>')

# 3. Replace static chart HTML with dynamic GridStack container
old_html_start = '<!-- Nút Ẩn/Hiện Biểu Đồ -->'
old_html_end = '<!-- Main Content Grid -->'

idx_start = content.find(old_html_start)
idx_end = content.find(old_html_end)

new_html = '''
            <!-- Biểu Đồ Kéo Thả (GridStack) -->
            <div class="flex justify-between items-center mb-4">
                <a href="chart-builder.html" class="bg-indigo-50 text-indigo-600 hover:bg-indigo-100 dark:bg-gray-800 dark:text-indigo-400 px-4 py-2 rounded-xl text-sm font-bold transition flex items-center shadow-sm border border-indigo-100 dark:border-gray-700">
                    <i class="fas fa-magic mr-2"></i> Trạm Tạo Biểu Đồ (Builder)
                </a>
                
                <button onclick="toggleCharts()" class="text-gray-500 hover:text-gray-700 text-sm font-bold">
                    <i id="toggleChartIcon" class="fas fa-eye-slash"></i> <span id="toggleChartText">Ẩn Biểu Đồ</span>
                </button>
            </div>

            <div id="chartContainerWrapper" class="transition-all duration-300 origin-top mb-6">
                <!-- Vùng lưới chứa biểu đồ -->
                <div class="grid-stack"></div>
            </div>
'''
if idx_start != -1 and idx_end != -1:
    content = content[:idx_start] + new_html + '\n            ' + content[idx_end:]


# 4. Remove old renderCharts() and inject dynamic render logic
js_logic = '''
        let dashboardGrid;
        let dynamicChartInstances = {};
        let dashboardConfig = [];

        async function initDynamicDashboard() {
            dashboardGrid = GridStack.init({
                cellHeight: 80,
                margin: 10,
                staticGrid: true // Khóa lưới, không cho kéo thả ở trang chủ
            });

            try {
                const res = await fetch(`${API_URL}/api/admin/dashboard-config`);
                const configData = await res.json();
                dashboardConfig = configData.widgets || [];
                
                dashboardConfig.forEach(w => {
                    const el = document.createElement('div');
                    el.setAttribute('gs-id', w.id);
                    el.setAttribute('gs-w', w.w);
                    el.setAttribute('gs-h', w.h);
                    el.setAttribute('gs-x', w.x);
                    el.setAttribute('gs-y', w.y);
                    
                    el.innerHTML = `
                        <div class="grid-stack-item-content">
                            <h2 class="text-sm font-bold text-gray-900 dark:text-white mb-4"><i class="fas fa-chart-pie text-indigo-500 mr-2"></i>${w.title}</h2>
                            <div class="chart-container">
                                <canvas id="canvas-${w.id}"></canvas>
                            </div>
                        </div>
                    `;
                    dashboardGrid.addWidget(el);
                });
            } catch(e) {
                console.error("Lỗi tải config biểu đồ:", e);
            }
        }

        function renderDynamicCharts() {
            // Chạy qua từng widget và vẽ lại dựa trên allTransactions (hoặc data table tương ứng)
            dashboardConfig.forEach(w => {
                const ctx = document.getElementById(`canvas-${w.id}`);
                if(!ctx) return;
                
                // Ở trang chủ hiện tại chỉ fetch allTransactions. 
                // Nếu w.source_table == 'wallet_ledger', ta dùng allTransactions
                // Các bảng khác cần fetch thêm API nếu mở rộng. Ở đây demo dùng allTransactions
                const rawData = w.source_table === 'wallet_ledger' ? allTransactions : [];
                
                const grouped = {};
                rawData.forEach(row => {
                    let key = row[w.group_by] || 'Khác';
                    if (w.group_by === 'created_at' && key !== 'Khác') {
                        key = new Date(key).toLocaleDateString('vi-VN');
                    }
                    if (!grouped[key]) grouped[key] = 0;
                    
                    if (w.metric === 'count') {
                        grouped[key] += 1;
                    } else if (w.metric === 'sum' && w.metric_column) {
                        grouped[key] += Math.abs(parseFloat(row[w.metric_column]) || 0);
                    }
                });

                let labels = Object.keys(grouped);
                let dataArr = Object.values(grouped);
                if (w.group_by === 'created_at') {
                    labels.reverse();
                    dataArr.reverse();
                }

                if(dynamicChartInstances[w.id]) dynamicChartInstances[w.id].destroy();

                dynamicChartInstances[w.id] = new Chart(ctx, {
                    type: w.type,
                    data: {
                        labels: labels.length ? labels : ['Chưa có DL'],
                        datasets: [{
                            label: w.title,
                            data: dataArr.length ? dataArr : [0],
                            backgroundColor: w.type === 'line' || w.type === 'bar' ? '#6366f1' : ['#10b981', '#f43f5e', '#8b5cf6', '#f59e0b', '#3b82f6'],
                            borderColor: w.type === 'line' ? '#6366f1' : 'transparent',
                            borderWidth: 2,
                            tension: 0.3,
                            fill: w.type === 'line' ? {target: 'origin', above: 'rgba(99, 102, 241, 0.1)'} : false
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: w.type === 'pie' || w.type === 'doughnut', position: 'right' } }
                    }
                });
            });
        }
'''

content = content.replace('let cashflowChartInstance = null;', '')
content = content.replace('let txTypeChartInstance = null;', '')

idx_render_start = content.find('function renderCharts() {')
if idx_render_start != -1:
    idx_render_end = content.find('function toggleCharts() {')
    content = content[:idx_render_start] + js_logic + content[idx_render_end:]

# Replace calls to renderCharts with renderDynamicCharts
content = content.replace('renderCharts()', 'renderDynamicCharts()')

# Add initDynamicDashboard call
idx_setup = content.find('document.addEventListener(\'DOMContentLoaded\', () => {')
if idx_setup != -1:
    content = content.replace('document.addEventListener(\'DOMContentLoaded\', () => {', 'document.addEventListener(\'DOMContentLoaded\', async () => {\n            await initDynamicDashboard();')

open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', 'w', encoding='utf-8').write(content)
print("Dashboard.html refactored successfully for dynamic charts.")
