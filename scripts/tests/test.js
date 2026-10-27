
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#ef4444',
                        darkBg: '#111827',
                        darkCard: '#1f2937'
                    }
                }
            }
        }
    

        const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
            ? 'http://localhost:5000' 
            : 'https://kgs work-backend.onrender.com';

        let allTransactions = [];

        
        
        

        
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
                const dateFilter = document.getElementById('chartDateFilter') ? document.getElementById('chartDateFilter').value : '';
                let rawData = w.source_table === 'wallet_ledger' ? allTransactions : [];
                if (dateFilter) { rawData = rawData.filter(tx => tx.created_at && tx.created_at.startsWith(dateFilter)); }
                
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
        document.addEventListener('DOMContentLoaded', async () => {
            await initDynamicDashboard();
            await loadDashboardAll(); // Load data AFTER widgets are created
            setupRealtimeListeners();
        });

        loadDashboardAll = async function() {
            await originalLoadDashboardAll();
            if(!cashflowChartInstance) renderDynamicCharts(); // Chỉ render lần đầu, các lần sau setInterval tự render
        };

        async function loadDashboardAll() {
            await loadStats();
            await loadTransactions();
            await loadRecentAuditLogs();
        }

        async function loadStats() {
            try {
                const res = await fetch(`${API_URL}/api/admin/stats`);
                const data = await res.json();
                if (res.ok && data.stats) {
                    const s = data.stats;
                    document.getElementById('statTotalUsers').innerText = s.total_users;
                    document.getElementById('statUserRatio').innerText = `${s.total_clients} Khách • ${s.total_freelancers} Thợ`;
                    document.getElementById('statActiveJobs').innerText = s.active_jobs;
                    document.getElementById('statTotalJobs').innerText = `Tổng: ${s.total_jobs} dự án`;
                    document.getElementById('statEscrowLocked').innerHTML = formatTokenHTML(s.total_escrow_locked);
                    document.getElementById('statPendingWithdrawCount').innerText = s.pending_withdraw_count;
                    document.getElementById('statPendingWithdrawAmount').innerHTML = `${formatTokenHTML(s.pending_withdraw_amount)} <span class="text-[10px]">chờ duyệt</span>`;
                    document.getElementById('statDisputedJobs').innerText = s.disputed_jobs;
                }
            } catch(e) {
                console.error(e);
            }
        }

        async function loadTransactions() {
            try {
                const res = await fetch(`${API_URL}/api/admin/transactions`);
                const data = await res.json();
                if (res.ok && data.transactions) {
                    allTransactions = data.transactions;
                    renderLedgerTable();
                }
            } catch(e) {
                console.error(e);
            }
        }

        function renderLedgerTable() {
            const tbody = document.getElementById('ledgerTableBody');
            const filterType = document.getElementById('ledgerTypeFilter').value;

            let filtered = allTransactions;
            if (filterType !== 'ALL') {
                filtered = filtered.filter(t => (t.type || '').toUpperCase().includes(filterType));
            }

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-gray-400">Không có giao dịch nào phù hợp.</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.slice(0, 20).map(t => {
                const date = new Date(t.created_at).toLocaleString('vi-VN');
                const relatedUser = t.receiver ? t.receiver.full_name : (t.sender ? t.sender.full_name : 'Hệ thống');
                const tType = (t.type || '').toUpperCase();

                let badge = '<span class="bg-gray-100 text-gray-700 px-2 py-0.5 rounded-full text-[10px] font-bold">GD</span>';
                let amountColor = 'text-gray-800 dark:text-white';
                let sign = '';

                if (tType.includes('DEPOSIT')) {
                    badge = '<span class="bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 px-2 py-0.5 rounded-full text-[10px] font-bold">Nạp Tiền</span>';
                    amountColor = 'text-emerald-600 dark:text-emerald-400 font-black';
                    sign = '+';
                } else if (tType.includes('WITHDRAW')) {
                    badge = '<span class="bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300 px-2 py-0.5 rounded-full text-[10px] font-bold">Rút Tiền</span>';
                    amountColor = 'text-red-600 dark:text-red-400 font-black';
                    sign = '-';
                } else if (tType.includes('LOCK')) {
                    badge = '<span class="bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 px-2 py-0.5 rounded-full text-[10px] font-bold">Khóa Escrow</span>';
                } else if (tType.includes('RELEASE')) {
                    badge = '<span class="bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 px-2 py-0.5 rounded-full text-[10px] font-bold">Giải Ngân</span>';
                }

                return `
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-750 transition">
                        <td class="py-2.5 px-3 text-gray-400 whitespace-nowrap text-[11px]">${date}</td>
                        <td class="py-2.5 px-3 font-bold">${relatedUser}</td>
                        <td class="py-2.5 px-3">${badge}</td>
                        <td class="py-2.5 px-3 text-right ${amountColor}">${sign}${formatTokenHTML(t.amount, false)}</td>
                        <td class="py-2.5 px-3 text-gray-500 dark:text-gray-400 truncate max-w-xs" title="${t.note || ''}">${t.note || 'Thành công'}</td>
                    </tr>
                `;
            }).join('');
        }

        async function loadRecentAuditLogs() {
            try {
                const res = await fetch(`${API_URL}/api/admin/audit-logs?limit=6`);
                const data = await res.json();
                const container = document.getElementById('recentAuditLogsList');
                if (res.ok && data.logs && data.logs.length > 0) {
                    container.innerHTML = data.logs.map(log => {
                        let levelBg = 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300';
                        if (log.level === 'WARN') levelBg = 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300';
                        else if (log.level === 'SECURITY' || log.level === 'CRITICAL') levelBg = 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300';

                        return `
                            <div class="p-3 bg-gray-50 dark:bg-gray-750 rounded-2xl border border-gray-100 dark:border-gray-700 text-xs">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="${levelBg} px-2 py-0.5 rounded-md font-black text-[10px]">${log.module} • ${log.action}</span>
                                    <span class="text-[9px] text-gray-400">${new Date(log.timestamp).toLocaleTimeString('vi-VN')}</span>
                                </div>
                                <p class="text-gray-700 dark:text-gray-300 text-[11px] leading-relaxed">${log.details}</p>
                            </div>
                        `;
                    }).join('');
                } else {
                    container.innerHTML = '<p class="text-gray-400 text-xs py-4 text-center">Chưa có sự kiện log nào.</p>';
                }
            } catch(e) {
                console.error(e);
            }
        }

//         loadDashboardAll();
    

        // Global Drag and Drop protection
        window.addEventListener('dragover', function(e) {
            e.preventDefault();
        }, false);
        window.addEventListener('drop', function(e) {
            e.preventDefault();
        }, false);
    