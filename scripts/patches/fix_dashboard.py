import re
content = open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', encoding='utf-8').read()

# 1. Add Supabase CDN if not exists
if 'supabase-js' not in content:
    content = content.replace('</head>', '    <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>\n</head>')

# 2. Fix Chart HTML (Add toggle button, add relative wrapper)
old_chart_html_start = '<!-- Biểu đồ thống kê -->'
old_chart_html_end = '<!-- Main Content Grid -->'

# Extract the part to replace
idx_start = content.find(old_chart_html_start)
idx_end = content.find(old_chart_html_end)

if idx_start != -1 and idx_end != -1:
    new_chart_html = '''
            <!-- Nút Ẩn/Hiện Biểu Đồ -->
            <div class="flex justify-end mb-4">
                <button onclick="toggleCharts()" class="bg-indigo-50 text-indigo-600 hover:bg-indigo-100 dark:bg-gray-800 dark:text-indigo-400 px-4 py-2 rounded-xl text-sm font-bold transition flex items-center shadow-sm border border-indigo-100 dark:border-gray-700">
                    <i id="toggleChartIcon" class="fas fa-eye-slash mr-2"></i> <span id="toggleChartText">Ẩn Biểu Đồ</span>
                </button>
            </div>

            <!-- Biểu đồ thống kê -->
            <div id="chartContainerWrapper" class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6 transition-all duration-300 origin-top">
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl shadow-sm border border-gray-100 dark:border-gray-700 flex flex-col">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-sm font-bold text-gray-900 dark:text-white"><i class="fas fa-chart-line text-blue-500 mr-2"></i>Dòng Tiền Lưu Thông</h2>
                        <div class="flex items-center space-x-2">
                            <input type="date" id="chartDateFilter" onchange="renderCharts(); renderLedgerTable();" class="text-xs border border-gray-200 dark:border-gray-700 rounded-lg px-2 py-1 bg-gray-50 dark:bg-gray-700 text-gray-800 dark:text-white outline-none cursor-pointer">
                            <button onclick="document.getElementById('chartDateFilter').value=''; renderCharts(); renderLedgerTable();" class="text-xs text-gray-400 hover:text-red-500"><i class="fas fa-times"></i></button>
                        </div>
                    </div>
                    <div style="position: relative; height: 250px; width: 100%;">
                        <canvas id="cashflowChart"></canvas>
                    </div>
                </div>
                <div class="bg-white dark:bg-gray-800 p-5 rounded-3xl shadow-sm border border-gray-100 dark:border-gray-700 flex flex-col">
                    <h2 class="text-sm font-bold text-gray-900 dark:text-white mb-4"><i class="fas fa-chart-pie text-purple-500 mr-2"></i>Tỷ Trọng Giao Dịch</h2>
                    <div style="position: relative; height: 250px; width: 100%;">
                        <canvas id="txTypeChart"></canvas>
                    </div>
                </div>
            </div>
            '''
    content = content[:idx_start] + new_chart_html + '\n            ' + content[idx_end:]


# 3. Replace the setInterval with Supabase Realtime logic + toggle logic
js_to_replace_start = '// Bật Polling thời gian thực'
js_to_replace_end = 'loadDashboardAll = async function() {'

idx_js_start = content.find(js_to_replace_start)
idx_js_end = content.find(js_to_replace_end)

if idx_js_start != -1 and idx_js_end != -1:
    new_js = '''
        // Logic Ẩn/Hiện biểu đồ
        function toggleCharts() {
            const wrapper = document.getElementById('chartContainerWrapper');
            const icon = document.getElementById('toggleChartIcon');
            const text = document.getElementById('toggleChartText');
            if (wrapper.classList.contains('hidden')) {
                wrapper.classList.remove('hidden');
                icon.className = 'fas fa-eye-slash mr-2';
                text.innerText = 'Ẩn Biểu Đồ';
            } else {
                wrapper.classList.add('hidden');
                icon.className = 'fas fa-eye mr-2';
                text.innerText = 'Hiện Biểu Đồ';
            }
        }

        // Lắng nghe Real-time từ Database bằng Supabase WebSockets (Không dùng setInterval gây lag)
        async function setupRealtimeListeners() {
            try {
                const res = await fetch(`${API_URL}/api/admin/supabase-config`);
                const config = await res.json();
                
                if (config.url && config.key) {
                    const supabase = window.supabase.createClient(config.url, config.key);
                    
                    // Lắng nghe thay đổi trên tất cả các bảng quan trọng
                    supabase.channel('admin-dashboard-changes')
                        .on('postgres_changes', { event: '*', schema: 'public', table: 'wallet_ledger' }, payload => {
                            console.log('Realtime Update: wallet_ledger', payload);
                            loadDashboardAll();
                        })
                        .on('postgres_changes', { event: '*', schema: 'public', table: 'users' }, payload => {
                            loadDashboardAll();
                        })
                        .on('postgres_changes', { event: '*', schema: 'public', table: 'jobs' }, payload => {
                            loadDashboardAll();
                        })
                        .on('postgres_changes', { event: '*', schema: 'public', table: 'withdraw_requests' }, payload => {
                            loadDashboardAll();
                        })
                        .subscribe();
                    
                    console.log('✅ Đã kết nối Supabase Realtime thành công. Giao diện sẽ tự động cập nhật khi có dữ liệu mới.');
                }
            } catch (err) {
                console.error('Không thể thiết lập Realtime:', err);
            }
        }

        // Gọi setup khi khởi động
        document.addEventListener('DOMContentLoaded', () => {
            setupRealtimeListeners();
        });

        '''
    content = content[:idx_js_start] + new_js + content[idx_js_end:]

open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', 'w', encoding='utf-8').write(content)
print("Updated dashboard.html successfully for layout and realtime.")
