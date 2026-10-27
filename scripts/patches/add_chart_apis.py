import os

filepath = r'd:\Project_internship\New_code\code\Back_end\routes\adminRoutes.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

api_code = """
// --- CHART APIs ---

router.get('/api/admin/charts/cashflow', async (req, res) => {
    try {
        const { data, error } = await supabase.from('wallet_ledger').select('amount, type, created_at');
        if (error) throw error;
        
        // Group by day for the last 7 days
        const last7Days = [...Array(7)].map((_, i) => {
            const d = new Date();
            d.setDate(d.getDate() - i);
            return d.toISOString().split('T')[0];
        }).reverse();

        const result = last7Days.map(date => {
            const dayData = data.filter(r => r.created_at.startsWith(date));
            const deposit = dayData.filter(r => r.type === 'DEPOSIT' || r.type === 'ADMIN_CREDIT').reduce((sum, r) => sum + parseFloat(r.amount || 0), 0);
            const withdraw = dayData.filter(r => r.type === 'WITHDRAW' || r.type === 'ADMIN_DEBIT').reduce((sum, r) => sum + parseFloat(r.amount || 0), 0);
            const escrow = dayData.filter(r => r.type === 'ESCROW_LOCK').reduce((sum, r) => sum + parseFloat(r.amount || 0), 0);
            return { date, deposit, withdraw, escrow };
        });

        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/api/admin/charts/jobs', async (req, res) => {
    try {
        const { data, error } = await supabase.from('jobs').select('status');
        if (error) throw error;
        
        const stats = {
            'planning': 0, 'in_progress': 0, 'completed': 0, 'disputed': 0, 'cancelled': 0
        };
        data.forEach(job => {
            if (stats[job.status] !== undefined) stats[job.status]++;
            else stats['planning']++; // fallback
        });
        
        res.json({ success: true, data: stats });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/api/admin/charts/users', async (req, res) => {
    try {
        const { data, error } = await supabase.from('users').select('role, created_at');
        if (error) throw error;
        
        const last7Days = [...Array(7)].map((_, i) => {
            const d = new Date();
            d.setDate(d.getDate() - i);
            return d.toISOString().split('T')[0];
        }).reverse();

        const result = last7Days.map(date => {
            const dayData = data.filter(r => r.created_at && r.created_at.startsWith(date));
            const clients = dayData.filter(r => r.role === 'client').length;
            const freelancers = dayData.filter(r => r.role === 'freelancer').length;
            return { date, clients, freelancers };
        });

        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// --- END CHART APIs ---
module.exports = router;
"""

if '// --- CHART APIs ---' not in content:
    content = content.replace('module.exports = router;', api_code)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Added chart APIs")
else:
    print("Chart APIs already exist")
