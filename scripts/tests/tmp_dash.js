
        const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
            ? 'http://localhost:5000' 
            : 'https://htwork-backend.onrender.com';

        let allTransactions = [];

        async 
        
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
 },
                                y: { grid: { color: theme.gridColor }, ticks: { color: theme.textColor, font: {size: 10} } }
                            },
                            plugins: {
                                legend: { labels: { color: theme.textColor, font: {size: 11}, boxWidth: 12 } }
                            }
                        }
                    });
                }

                // Jobs
                const resJobs = await fetch(\'http://localhost:5000/api/admin/charts/jobs\');
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

        function loadDashboardAll() {
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
                    document.getElementById('statEscrowLocked').innerText = s.total_escrow_locked.toLocaleString();
                    document.getElementById('statPendingWithdrawCount').innerText = s.pending_withdraw_count;
                    document.getElementById('statPendingWithdrawAmount').innerText = `${s.pending_withdraw_amount.toLocaleString()} Token chờ duyệt`;
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
                        <td class="py-2.5 px-3 text-right ${amountColor}">${sign}${parseInt(t.amount).toLocaleString()} Token</td>
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

        loadDashboardAll();
            loadMiniCharts();
    