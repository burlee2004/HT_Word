import re

# ==========================================
# 1. FIX DASHBOARD.HTML
# ==========================================
dash_path = r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html'
dash_content = open(dash_path, encoding='utf-8').read()

# Fix the load order
setup_code_old = '''        document.addEventListener('DOMContentLoaded', async () => {
            await initDynamicDashboard();
            setupRealtimeListeners();
        });'''
        
setup_code_new = '''        document.addEventListener('DOMContentLoaded', async () => {
            await initDynamicDashboard();
            await loadDashboardAll(); // Load data AFTER widgets are created
            setupRealtimeListeners();
        });'''

dash_content = dash_content.replace(setup_code_old, setup_code_new)

# Remove the loose loadDashboardAll() at the end of script
lines = dash_content.split('\n')
for i in range(len(lines)-1, -1, -1):
    if 'loadDashboardAll();' in lines[i] and 'function' not in lines[i] and 'await' not in lines[i]:
        lines[i] = '// ' + lines[i] # comment it out
        break
dash_content = '\n'.join(lines)

open(dash_path, 'w', encoding='utf-8').write(dash_content)


# ==========================================
# 2. FIX CHART-BUILDER.HTML
# ==========================================
builder_path = r'd:\Project_internship\New_code\code\Front_end\Admin\chart-builder.html'
b_content = open(builder_path, encoding='utf-8').read()

# Modify Modal UI to clarify labels, add chart types, and color picker
old_modal_html = '''                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1">Loại Biểu Đồ</label>
                        <select id="wType" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                            <option value="line">Đường (Line)</option>
                            <option value="bar">Cột (Bar)</option>
                            <option value="doughnut">Tròn Trống (Doughnut)</option>
                            <option value="pie">Tròn Đặc (Pie)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1">Nguồn Dữ Liệu (Bảng)</label>
                        <select id="wTable" onchange="updateColumns()" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                            <option value="wallet_ledger">Sổ Cái Giao Dịch</option>
                            <option value="jobs">Dự Án (Jobs)</option>
                            <option value="users">Người Dùng</option>
                        </select>
                    </div>
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1">Nhóm Theo (Trục X)</label>
                        <select id="wGroupBy" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                            <!-- Populated by JS -->
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1">Phép Tính (Trục Y)</label>
                        <div class="flex gap-2">
                            <select id="wMetric" onchange="updateMetricColState()" class="w-1/3 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-2 py-2 text-sm outline-none">
                                <option value="count">Đếm</option>
                                <option value="sum">Tổng</option>
                            </select>
                            <select id="wMetricCol" class="w-2/3 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-2 py-2 text-sm outline-none" disabled>
                                <!-- Populated by JS -->
                            </select>
                        </div>
                    </div>
                </div>'''

new_modal_html = '''                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1" title="Kiểu hiển thị của biểu đồ">Loại Biểu Đồ</label>
                        <select id="wType" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                            <option value="line">Đường (Line) - Xu hướng</option>
                            <option value="bar">Cột (Bar) - So sánh</option>
                            <option value="doughnut">Tròn Trống (Doughnut)</option>
                            <option value="pie">Tròn Đặc (Pie)</option>
                            <option value="polarArea">Quạt Cực (Polar Area)</option>
                            <option value="radar">Mạng Nhện (Radar)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1">Nguồn Dữ Liệu</label>
                        <select id="wTable" onchange="updateColumns()" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                            <option value="wallet_ledger">Giao dịch / Tiền tệ</option>
                            <option value="jobs">Dự Án (Jobs)</option>
                            <option value="users">Người Dùng</option>
                        </select>
                    </div>
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1" title="Dữ liệu sẽ được nhóm lại theo cột này (VD: Nhóm theo Ngày, nhóm theo Trạng Thái)">Gom nhóm theo (Trục X)</label>
                        <select id="wGroupBy" class="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm outline-none">
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-gray-500 mb-1" title="Tính toán giá trị (VD: Đếm số lượng, Tính tổng tiền)">Phép Tính (Trục Y)</label>
                        <div class="flex gap-2">
                            <select id="wMetric" onchange="updateMetricColState()" class="w-1/3 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-2 py-2 text-sm outline-none">
                                <option value="count">Đếm</option>
                                <option value="sum">Tính Tổng</option>
                            </select>
                            <select id="wMetricCol" class="w-2/3 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg px-2 py-2 text-sm outline-none" disabled>
                            </select>
                        </div>
                    </div>
                </div>

                <div>
                    <label class="block text-xs font-bold text-gray-500 mb-1">Màu Sắc Chủ Đạo</label>
                    <div class="flex items-center gap-3">
                        <input type="color" id="wColor" value="#6366f1" class="w-10 h-10 rounded cursor-pointer border-0 p-0">
                        <span class="text-xs text-gray-400 italic">Áp dụng cho biểu đồ Cột, Đường, Radar.</span>
                    </div>
                </div>'''

b_content = b_content.replace(old_modal_html, new_modal_html)

# Update confirmAddWidget to include color
b_content = b_content.replace(
    "metric_column: document.getElementById('wMetricCol').value,",
    "metric_column: document.getElementById('wMetricCol').value,\n                color: document.getElementById('wColor').value,"
)

# Fix Mock Data injection in renderChartInWidget
old_render_logic = '''        function renderChartInWidget(w) {
            const ctx = document.getElementById(`canvas-${w.id}`);
            const rawData = mockDataCache[w.source_table] || [];
            
            // Xử lý dữ liệu (Mô phỏng)
            const grouped = {};
            rawData.forEach(row => {'''

new_render_logic = '''        function renderChartInWidget(w) {
            const ctx = document.getElementById(`canvas-${w.id}`);
            let rawData = mockDataCache[w.source_table] || [];
            
            // NẾU DATABASE TRỐNG (Vừa Wipe Data), TẠO MOCK DATA ĐỂ PREVIEW BIỂU ĐỒ!
            if (rawData.length === 0) {
                if (w.source_table === 'wallet_ledger') {
                    rawData = [
                        { created_at: '2023-10-01', transaction_type: 'deposit', amount: 5000 },
                        { created_at: '2023-10-02', transaction_type: 'withdraw', amount: -2000 },
                        { created_at: '2023-10-03', transaction_type: 'deposit', amount: 8000 },
                        { created_at: '2023-10-03', transaction_type: 'milestone_payment', amount: -1500 }
                    ];
                } else if (w.source_table === 'jobs') {
                    rawData = [ { status: 'completed' }, { status: 'completed' }, { status: 'in_progress' }, { status: 'disputed' } ];
                } else {
                    rawData = [ { role: 'client' }, { role: 'freelancer' }, { role: 'freelancer' } ];
                }
            }
            
            // Xử lý dữ liệu
            const grouped = {};
            rawData.forEach(row => {'''

b_content = b_content.replace(old_render_logic, new_render_logic)


# Update Chart JS config to use custom colors
old_chart_config = '''                        backgroundColor: w.type === 'line' || w.type === 'bar' ? '#6366f1' : ['#10b981', '#f43f5e', '#8b5cf6', '#f59e0b', '#3b82f6'],
                        borderColor: w.type === 'line' ? '#6366f1' : 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: w.type === 'line' ? {target: 'origin', above: 'rgba(99, 102, 241, 0.1)'} : false'''

new_chart_config = '''                        backgroundColor: (w.type === 'line' || w.type === 'bar' || w.type === 'radar') ? (w.color || '#6366f1') : ['#10b981', '#f43f5e', '#8b5cf6', '#f59e0b', '#3b82f6', '#0ea5e9'],
                        borderColor: (w.type === 'line' || w.type === 'radar') ? (w.color || '#6366f1') : 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: (w.type === 'line' || w.type === 'radar') ? true : false'''

b_content = b_content.replace(old_chart_config, new_chart_config)

open(builder_path, 'w', encoding='utf-8').write(b_content)


# ==========================================
# 3. FIX DASHBOARD.HTML CHART COLOR RENDERING
# ==========================================
dash_content = open(dash_path, encoding='utf-8').read()
dash_content = dash_content.replace(old_chart_config, new_chart_config)
open(dash_path, 'w', encoding='utf-8').write(dash_content)

print("Dashboard & Builder patched successfully.")
