DOMContentLoaded', async () => {
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
            