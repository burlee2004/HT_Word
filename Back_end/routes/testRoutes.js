const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');

// Lấy danh sách milestones đang PENDING_REVIEW để test
router.get('/api/test/milestones', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('milestones')
            .select('id, title, amount, status, job_id, created_at')
            .in('status', ['PENDING_REVIEW', 'FUNDED', 'PAID', 'IN_PROGRESS', 'approved'])
            .order('created_at', { ascending: false })
            .limit(10);
        if (error) throw error;
        res.status(200).json({ milestones: data });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy thông tin ví của 1 user
router.get('/api/test/wallet/:user_id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallets')
            .select('balance, locked_balance, created_at')
            .eq('user_id', req.params.user_id)
            .single();
        if (error) throw error;
        res.status(200).json({ wallet: data });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy lịch sử sổ cái của 1 milestone
router.get('/api/test/ledger/:milestone_id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('type, amount, sender_id, receiver_id, idempotency_key, created_at')
            .eq('milestone_id', req.params.milestone_id)
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ ledger: data || [] });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Lấy thông tin đầy đủ 1 milestone (kèm client_id + freelancer_id)
router.get('/api/test/milestone-detail/:milestone_id', async (req, res) => {
    try {
        const { data: ms, error: mErr } = await supabase
            .from('milestones')
            .select('id, title, amount, status, job_id, paid_at')
            .eq('id', req.params.milestone_id)
            .single();
        if (mErr) throw mErr;

        const { data: job } = await supabase.from('jobs').select('client_id').eq('id', ms.job_id).single();
        const { data: appl } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', ms.job_id).eq('status', 'accepted').single();

        res.status(200).json({
            milestone: ms,
            client_id: job ? job.client_id : null,
            freelancer_id: appl ? appl.freelancer_id : null
        });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// Gọi fn_release_milestone trực tiếp với idempotency_key tùy chỉnh (cho mục đích demo)
router.post('/api/test/simulate-release', async (req, res) => {
    const { milestone_id, client_id, freelancer_id, custom_key } = req.body;
    try {
        const { data: rpc, error } = await supabase.rpc('fn_release_milestone', {
            p_milestone_id:    milestone_id,
            p_client_id:       client_id,
            p_freelancer_id:   freelancer_id,
            p_idempotency_key: custom_key || ('SIM_' + milestone_id + '_' + Date.now())
        });
        if (error) throw error;
        res.status(200).json({ result: rpc });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

module.exports = router;
