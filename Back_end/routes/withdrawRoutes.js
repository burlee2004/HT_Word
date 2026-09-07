const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const blockchain = require('../blockchain');
const { logEvent } = require('../services/auditLogger');

// 1. Tạo lệnh rút tiền (Web2.5)
router.post('/api/withdraw', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        if (!user_id || !amount || amount <= 0) throw new Error('Dữ liệu không hợp lệ');

        // Kiểm tra thông tin ngân hàng
        const { data: user } = await supabase.from('users').select('bank_name, bank_account, bank_owner').eq('id', user_id).single();
        if (!user || !user.bank_account) {
            return res.status(400).json({ error: 'Vui lòng cập nhật tài khoản ngân hàng trong Profile trước khi rút tiền.' });
        }

        // Kiểm tra ví DB
        const { data: wallet } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', user_id).single();
        if (!wallet || wallet.balance < amount) {
            return res.status(400).json({ error: 'Không đủ số dư khả dụng để rút tiền.' });
        }

        // BẢO MẬT WEB2.5: ĐỐI CHIẾU BLOCKCHAIN
        if (blockchain.isConfigured()) {
            const bcBalance = await blockchain.getBalance(user_id);
            if (bcBalance !== null) {
                const expectedTotal = wallet.balance + wallet.locked_balance;
                if (bcBalance < expectedTotal || bcBalance < amount) {
                    return res.status(400).json({ error: '[BẢO MẬT] Lệch số dư với Blockchain. Giao dịch bị từ chối.' });
                }
            }
        }

        // Xử lý logic DB: Trừ balance, cộng locked_balance, tạo lệnh
        await supabase.from('wallets').update({ 
            balance: wallet.balance - amount,
            locked_balance: wallet.locked_balance + amount 
        }).eq('user_id', user_id);

        const { data: request, error: reqErr } = await supabase.from('withdraw_requests').insert([{
            user_id, amount, status: 'pending'
        }]).select().single();

        if (reqErr) throw reqErr;

        logEvent({
            module: 'WALLET',
            action: 'WITHDRAW_CREATE',
            actor_id: user_id,
            actor_email: user.bank_owner || 'User',
            level: 'INFO',
            details: `Yêu cầu rút ${amount.toLocaleString()} Token về ngân hàng ${user.bank_name || ''} - STK ${user.bank_account || ''}`,
            metadata: { request_id: request.id, amount, bank: user.bank_name, account: user.bank_account }
        });

        res.status(200).json({ message: 'Tạo lệnh rút tiền thành công. Vui lòng chờ Admin duyệt.', request });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 2. Admin lấy danh sách rút tiền
router.get('/api/admin/withdrawals', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('withdraw_requests')
            .select('*, user:users(full_name, email, bank_name, bank_account, bank_owner)')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json(data);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 3. Admin duyệt lô (Bulk Approve)
router.post('/api/admin/withdrawals/bulk-approve', async (req, res) => {
    const { request_ids } = req.body;
    try {
        if (!request_ids || request_ids.length === 0) throw new Error('Không có lệnh nào được chọn');

        // Lấy danh sách lệnh
        const { data: requests } = await supabase.from('withdraw_requests').select('*').in('id', request_ids).eq('status', 'pending');
        
        for (let reqData of requests) {
            const user_id = reqData.user_id;
            const amount = reqData.amount;

            // Lấy ví
            const { data: wallet } = await supabase.from('wallets').select('locked_balance').eq('user_id', user_id).single();
            if (wallet) {
                // Trừ tiền tạm giữ trong DB
                await supabase.from('wallets').update({ locked_balance: wallet.locked_balance - amount }).eq('user_id', user_id);
                
                // Đồng bộ trừ Blockchain
                if (blockchain.isConfigured()) {
                    await blockchain.deductBalance(user_id, amount);
                }

                // Đổi trạng thái lệnh
                await supabase.from('withdraw_requests').update({ status: 'approved' }).eq('id', reqData.id);

                // Ghi transaction vào wallet_ledger
                await supabase.from('wallet_ledger').insert([{
                    sender_id: user_id, 
                    receiver_id: '11111111-1111-1111-1111-111111111111', 
                    amount: amount, 
                    type: 'WITHDRAW', 
                    idempotency_key: `WITHDRAW_${reqData.id}`,
                    note: 'Giải ngân rút tiền (Chuyển khoản lô)'
                }]);

                // Báo notification
                await supabase.from('notifications').insert([{
                    user_id: user_id, title: 'Tiền đã về ví!', content: `Lệnh rút ${amount} Token của bạn đã được Admin giải ngân thành công.`
                }]);

                logEvent({
                    module: 'WALLET',
                    action: 'WITHDRAW_APPROVE',
                    actor_id: 'ADMIN',
                    actor_email: 'admin@htwork.vn',
                    target_id: user_id,
                    level: 'INFO',
                    details: `Admin đã phê duyệt lệnh rút tiền #${reqData.id} số tiền ${amount.toLocaleString()} Token (Napas/Chi Hộ/Completed)`,
                    metadata: { request_id: reqData.id, user_id, amount }
                });
            }
        }
        res.status(200).json({ message: `Đã duyệt thành công ${requests ? requests.length : 0} lệnh rút tiền.` });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 4. Admin từ chối rút tiền (Hoàn tiền)
router.post('/api/admin/withdrawals/reject', async (req, res) => {
    const { request_id } = req.body;
    try {
        const { data: reqData } = await supabase.from('withdraw_requests').select('*').eq('id', request_id).eq('status', 'pending').single();
        if (!reqData) throw new Error('Lệnh không tồn tại hoặc đã xử lý');

        const user_id = reqData.user_id;
        const amount = reqData.amount;

        const { data: wallet } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', user_id).single();
        if (wallet) {
            // Hoàn lại tiền tạm giữ về khả dụng
            await supabase.from('wallets').update({ 
                locked_balance: wallet.locked_balance - amount,
                balance: wallet.balance + amount 
            }).eq('user_id', user_id);

            await supabase.from('withdraw_requests').update({ status: 'rejected' }).eq('id', request_id);

            await supabase.from('notifications').insert([{
                user_id: user_id, title: 'Lệnh rút tiền bị từ chối', content: `Lệnh rút ${amount} Token bị từ chối. Tiền đã được hoàn lại vào ví.`
            }]);

            logEvent({
                module: 'WALLET',
                action: 'WITHDRAW_REJECT',
                actor_id: 'ADMIN',
                actor_email: 'admin@htwork.vn',
                target_id: user_id,
                level: 'WARN',
                details: `Admin đã từ chối lệnh rút tiền #${request_id} số tiền ${amount.toLocaleString()} Token và hoàn tiền về ví người dùng`,
                metadata: { request_id, user_id, amount }
            });
        }
        res.status(200).json({ message: 'Đã từ chối lệnh và hoàn tiền thành công.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 5. User hủy lệnh rút tiền đang chờ (Pending) - Hoàn trả Token về số dư khả dụng ngay lập tức
router.post('/api/withdraw/cancel', async (req, res) => {
    const { user_id, request_id } = req.body;
    console.log(`\n🛑 [API POST /api/withdraw/cancel] User ${user_id} hủy lệnh rút: ${request_id}`);
    try {
        if (!user_id || !request_id) throw new Error('Thiếu thông tin người dùng hoặc mã lệnh rút');

        const { data: reqData, error: reqErr } = await supabase
            .from('withdraw_requests')
            .select('*')
            .eq('id', request_id)
            .eq('user_id', user_id)
            .eq('status', 'pending')
            .single();

        if (reqErr || !reqData) throw new Error('Lệnh rút tiền không tồn tại hoặc đã được xử lý trước đó');

        const amount = parseFloat(reqData.amount);

        // Hoàn lại tiền từ locked_balance về balance
        const { data: wallet, error: wErr } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', user_id).single();
        if (wErr || !wallet) throw new Error('Không tìm thấy ví của người dùng');

        const newLocked = Math.max(0, (parseFloat(wallet.locked_balance) || 0) - amount);
        const newBalance = (parseFloat(wallet.balance) || 0) + amount;

        await supabase.from('wallets').update({
            locked_balance: newLocked,
            balance: newBalance
        }).eq('user_id', user_id);

        // Đổi trạng thái lệnh rút thành 'cancelled'
        await supabase.from('withdraw_requests').update({ status: 'cancelled' }).eq('id', request_id);

        // Ghi log ví
        await supabase.from('wallet_ledger').insert([{
            sender_id: '11111111-1111-1111-1111-111111111111',
            receiver_id: user_id,
            amount: amount,
            type: 'REFUND',
            idempotency_key: `CANCEL_WITHDRAW_${request_id}`,
            note: 'Hoàn Token do hủy lệnh rút tiền'
        }]);

        // Gửi thông báo
        await supabase.from('notifications').insert([{
            user_id: user_id,
            title: 'Đã hủy lệnh rút tiền',
            content: `Bạn đã hủy lệnh rút ${amount.toLocaleString()} Token thành công. Số tiền đã được hoàn trả lại vào số dư khả dụng ngay lập tức.`
        }]);

        console.log(`✅ [API POST /api/withdraw/cancel] Hủy lệnh rút thành công! Hoàn ${amount} Token.`);
        res.status(200).json({ success: true, message: 'Đã hủy lệnh rút tiền thành công. Token đã được hoàn lại vào ví của bạn!' });
    } catch (error) {
        console.error(`❌ [API POST /api/withdraw/cancel] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 6. User lấy danh sách lịch sử lệnh rút tiền của chính mình
router.get('/api/withdraw/my-requests/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('withdraw_requests')
            .select('*')
            .eq('user_id', user_id)
            .order('created_at', { ascending: false });
            
        if (error) throw error;
        res.status(200).json({ requests: data || [] });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
