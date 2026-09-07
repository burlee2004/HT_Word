const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');

// 6. API: Admin xem toàn bộ Sổ cái (Ledger)
router.get('/api/admin/transactions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('*, sender:sender_id(full_name, email), receiver:receiver_id(full_name, email)')
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.status(200).json({ transactions: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15. API: Lấy thông tin ví của user
router.get('/api/wallet/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase.from('wallets').select('*').eq('user_id', user_id).single();
        if (error && error.code !== 'PGRST116') throw error; // PGRST116 = no rows returned
        
        let dbBalance = data ? data.balance : 0;
        let dbLocked = data ? data.locked_balance : 0;

        // BẢO MẬT WEB2.5: ĐỐI CHIẾU BLOCKCHAIN (SOURCE OF TRUTH)
        if (blockchain.isConfigured() && data) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance !== null) {
                const expectedTotal = dbBalance + dbLocked;
                
                if (bcBalance !== expectedTotal) {
                    console.error(`[CẢNH BÁO HACK] User ${user_id} bị lệch số dư! DB: ${expectedTotal} != Blockchain: ${bcBalance}`);
                }
            }
        }

        res.status(200).json({ 
            balance: dbBalance, 
            locked_balance: dbLocked,
            wallet: { ...data, balance: dbBalance, locked_balance: dbLocked } || { balance: 0, locked_balance: 0 }
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 15.1 API: Lấy lịch sử giao dịch (Sổ cái) của user
router.get('/api/wallet/:user_id/transactions', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('wallet_ledger')
            .select('*')
            .or(`sender_id.eq.${user_id},receiver_id.eq.${user_id}`)
            .order('created_at', { ascending: false })
            .limit(50);
            
        if (error) throw error;
        res.status(200).json({ transactions: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Admin Audit Users
router.get('/api/admin/audit/users', async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select(`
                id, email, 
                wallets (balance, locked_balance)
            `);
            
        if (error) throw error;
        
        const formatData = users.map(u => ({
            id: u.id,
            email: u.email,
            balance: u.wallets?.[0]?.balance || 0,
            locked_balance: u.wallets?.[0]?.locked_balance || 0
        }));
        
        res.status(200).json(formatData);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API DEV / TESTER (DỌN DẸP VÍ)
const ALLOWED_TESTERS = ['admin@htwork.com', 'hoanglubo2004@gmail.com', 'burlee2004@gmail.com'];

router.post('/api/test/reset-wallet', async (req, res) => {
    const { user_id, email } = req.body;
    try {
        if (!ALLOWED_TESTERS.includes(email)) {
            return res.status(403).json({ error: 'Truy cập bị từ chối! Bạn không nằm trong danh sách Tester.' });
        }

        // 1. Reset Database
        await supabase.from('wallets').update({ balance: 0, locked_balance: 0 }).eq('user_id', user_id);
        
        // 2. Xóa các giao dịch đang treo và Job (Escrow)
        await supabase.from('wallet_ledger').delete().or(`sender_id.eq.${user_id},receiver_id.eq.${user_id}`);
        await supabase.from('withdraw_requests').delete().eq('user_id', user_id);
        await supabase.from('jobs').delete().or(`client_id.eq.${user_id},freelancer_id.eq.${user_id}`);
        
        // 3. Reset Blockchain
        if (blockchain.isConfigured()) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance > 0) {
                await blockchain.deductBalance(user_id, bcBalance);
            }
        }

        res.status(200).json({ message: 'Đã reset toàn bộ Ví và Blockchain về 0 thành công!' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
