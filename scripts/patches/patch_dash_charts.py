import re

filepath = r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Add Chart.js to <head>
if 'chart.js' not in content:
    content = content.replace('</head>', '    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n</head>')

# HTML for charts
charts_html = """
            <!-- Charts Section (Mini) -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <!-- Biểu đồ Dòng tiền -->
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl border border-gray-100 dark:border-gray-700 shadow-sm">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-sm font-black text-gray-900 dark:text-white uppercase"><i class="fas fa-chart-line text-green-500 mr-2"></i>Dòng tiền Token (7 Ngày)</h2>
                        <a href="chart-builder.html" class="text-xs text-blue-500 hover:underline">Xem chi tiết</a>
                    </div>
                    <div class="relative h-48 w-full">
                        <canvas id="miniCashflowChart"></canvas>
                    </div>
                </div>

                <!-- Biểu đồ Trạng thái Dự án -->
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl border border-gray-100 dark:border-gray-700 shadow-sm">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-sm font-black text-gray-900 dark:text-white uppercase"><i class="fas fa-project-diagram text-blue-500 mr-2"></i>Tỷ lệ Dự án</h2>
                        <a href="chart-builder.html" class="text-xs text-blue-500 hover:underline">Quản lý</a>
                    </div>
                    <div class="relative h-48 w-full flex justify-center">
                        <canvas id="miniJobsChart"></canvas>
                    </div>
                </div>
            </div>
"""

# Insert before "Main Content Grid"
if 'miniCashflowChart' not in content:
    content = content.replace('<!-- Main Content Grid -->', charts_html + '\n            <!-- Main Content Grid -->')

# Add JS logic
js_logic = """
        let miniCashflowChart = null;
        let miniJobsChart = null;

        async function loadMiniCharts() {
            try {
                const isDark = document.documentElement.classList.contains('dark');
                const theme = {
                    textColor: isDark ? '#9ca3af' : '#6b7280',
                    gridColor: isDark ? '#374151' : '#f3f4f6'
                };

                // Cashflow
                const resCash = await fetch('/api/admin/charts/cashflow');
                const cashData = await resCash.json();
                if(cashData.success && cashData.data) {
                    const ctx = document.getElementById('miniCashflowChart').getContext('2d');
                    if(miniCashflowChart) miniCashflowChart.destroy();
                    
                    const labels = cashData.data.map(d => {
                        const date = new Date(d.date);
                        return date.getDate() + '/' + (date.getMonth()+1);
                    });
                    const deposits = cashData.data.map(d => d.deposit);
                    const withdraws = cashData.data.map(d => d.withdraw);
                    
                    miniCashflowChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [
                                { label: 'Nạp', data: deposits, borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', fill: true, tension: 0.4, pointRadius: 2 },
                                { label: 'Rút', data: withdraws, borderColor: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', fill: true, tension: 0.4, pointRadius: 2 }
                            ]
                        },
                        options: {
                            responsive: true, maintainAspectRatio: false,
                            scales: {
                                x: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor, font: {size: 10} } },
                                y: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor, font: {size: 10} } }
                            },
                            plugins: {
                                legend: { labels: { color: theme.textColor, font: {size: 11}, boxWidth: 12 } }
                            }
                        }
                    });
                }

                // Jobs
                const resJobs = await fetch('/api/admin/charts/jobs');
                const jobsData = await resJobs.json();
                if(jobsData.success && jobsData.data) {
                    const ctx = document.getElementById('miniJobsChart').getContext('2d');
                    if(miniJobsChart) miniJobsChart.destroy();
                    
                    miniJobsChart = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: ['Đang làm', 'Hoàn thành', 'Tranh chấp'],
                            datasets: [{
                                data: [jobsData.data.in_progress + jobsData.data.planning, jobsData.data.completed, jobsData.data.disputed],
                                backgroundColor: ['#3b82f6', '#10b981', '#ef4444'],
                                borderWidth: 0
                            }]
                        },
                        options: {
                            responsive: true, maintainAspectRatio: false,
                            plugins: {
                                legend: { position: 'right', labels: { color: theme.textColor, font: {size: 11}, boxWidth: 12 } }
                            },
                            cutout: '75%'
                        }
                    });
                }
            } catch (e) {
                console.error("Lỗi tải mini charts", e);
            }
        }
"""

if 'loadMiniCharts' not in content:
    content = content.replace('loadDashboardAll();', 'loadDashboardAll();\n            loadMiniCharts();')
    content = content.replace('function loadDashboardAll()', js_logic + '\n        function loadDashboardAll()')

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print("Added charts to dashboard.html")
