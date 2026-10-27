import re
content = open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', encoding='utf-8').read()

# Add Chart.js
if 'chart.js' not in content:
    content = content.replace('</head>', '    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n</head>')

# Add Chart HTML
chart_html = '''
            <!-- Biểu đồ thống kê -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl shadow-sm border border-gray-100 dark:border-gray-700">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-sm font-bold text-gray-900 dark:text-white"><i class="fas fa-chart-line text-blue-500 mr-2"></i>Dòng Tiền Lưu Thông (Token)</h2>
                        <div class="flex items-center space-x-2">
                            <span class="text-xs text-gray-500">Lọc ngày:</span>
                            <input type="date" id="chartDateFilter" onchange="renderCharts()" class="text-xs border border-gray-200 dark:border-gray-700 rounded-lg px-2 py-1 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-white outline-none cursor-pointer">
                            <button onclick="document.getElementById('chartDateFilter').value=''; renderCharts()" class="text-xs text-gray-400 hover:text-red-500"><i class="fas fa-times"></i></button>
                        </div>
                    </div>
                    <canvas id="cashflowChart" height="200"></canvas>
                </div>
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl shadow-sm border border-gray-100 dark:border-gray-700">
                    <h2 class="text-sm font-bold text-gray-900 dark:text-white mb-4"><i class="fas fa-chart-pie text-purple-500 mr-2"></i>Tỷ Trọng Giao Dịch</h2>
                    <canvas id="txTypeChart" height="200"></canvas>
                </div>
            </div>
'''
if 'id="cashflowChart"' not in content:
    content = content.replace('<!-- Main Content Grid -->', chart_html + '\n            <!-- Main Content Grid -->')

# Add real-time polling and chart rendering logic
js_additions = '''
        let cashflowChartInstance = null;
        let txTypeChartInstance = null;

        function renderCharts() {
            const dateFilter = document.getElementById('chartDateFilter').value;
            
            // Lọc dữ liệu theo ngày nếu có
            let filteredTx = allTransactions;
            if (dateFilter) {
                filteredTx = allTransactions.filter(tx => tx.created_at && tx.created_at.startsWith(dateFilter));
            }

            // Group by date cho Line chart
            const dateGroups = {};
            filteredTx.forEach(tx => {
                const d = new Date(tx.created_at).toLocaleDateString('vi-VN');
                if (!dateGroups[d]) dateGroups[d] = 0;
                dateGroups[d] += Math.abs(tx.amount || 0);
            });
            const labels = Object.keys(dateGroups).reverse();
            const dataLine = Object.values(dateGroups).reverse();

            // Group by type cho Doughnut chart
            const typeGroups = { 'Nạp (Deposit)': 0, 'Rút (Withdraw)': 0, 'Thanh toán (Payment)': 0, 'Khác': 0 };
            filteredTx.forEach(tx => {
                const t = tx.transaction_type;
                const amt = Math.abs(tx.amount || 0);
                if (t === 'deposit') typeGroups['Nạp (Deposit)'] += amt;
                else if (t === 'withdraw') typeGroups['Rút (Withdraw)'] += amt;
                else if (t === 'milestone_payment' || t === 'milestone_refund') typeGroups['Thanh toán (Payment)'] += amt;
                else typeGroups['Khác'] += amt;
            });

            // Vẽ Line Chart
            const ctx1 = document.getElementById('cashflowChart');
            if (cashflowChartInstance) cashflowChartInstance.destroy();
            cashflowChartInstance = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: labels.length ? labels : ['Chưa có dữ liệu'],
                    datasets: [{
                        label: 'Lưu lượng Token',
                        data: dataLine.length ? dataLine : [0],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            // Vẽ Doughnut Chart
            const ctx2 = document.getElementById('txTypeChart');
            if (txTypeChartInstance) txTypeChartInstance.destroy();
            txTypeChartInstance = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(typeGroups),
                    datasets: [{
                        data: Object.values(typeGroups),
                        backgroundColor: ['#10b981', '#f43f5e', '#8b5cf6', '#9ca3af'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } } } }
            });
        }

        // Bật Polling thời gian thực (3 giây cập nhật 1 lần)
        setInterval(async () => {
            // Lưu lại thanh cuộn
            const ledgerContainer = document.querySelector('.overflow-x-auto');
            const scrollPos = ledgerContainer ? ledgerContainer.scrollTop : 0;
            
            await loadDashboardAll(); // Load ngầm
            
            // Render lại biểu đồ
            renderCharts();

            if (ledgerContainer) ledgerContainer.scrollTop = scrollPos;
        }, 3000);

        // Gọi renderCharts lần đầu sau khi data tải xong
        const originalLoadDashboardAll = loadDashboardAll;
        loadDashboardAll = async function() {
            await originalLoadDashboardAll();
            if(!cashflowChartInstance) renderCharts(); // Chỉ render lần đầu, các lần sau setInterval tự render
        };
'''
if 'cashflowChartInstance = null' not in content:
    content = content.replace('async function loadDashboardAll() {', js_additions + '\n        async function loadDashboardAll() {')

open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', 'w', encoding='utf-8').write(content)
print("Updated dashboard.html successfully.")
