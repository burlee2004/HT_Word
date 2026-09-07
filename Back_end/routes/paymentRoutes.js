const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');
const payos = require('../config/payos');
const blockchain = require('../blockchain');
const settingsStore = require('../services/settingsStore');
const { logEvent } = require('../services/auditLogger');

// API PayOS: Tạo Link Thanh Toán & Lệnh nạp tiền
router.post('/api/payment/create-deposit', async (req, res) => {
    const { user_id, amount, method } = req.body;
    console.log(`
💳 [API POST /api/payment/create-deposit] User: ${user_id} | Amount: ${amount} | Method: ${method || 'default'}`);
    try {
        const orderCode = Number(String(Date.now()).slice(-6) + Math.floor(Math.random() * 1000));
        
        // Lưu vào bảng deposit_requests
        const { data, error } = await supabase.from('deposit_requests').insert([{
            user_id,
            amount: Number(amount),
            status: 'pending',
            payos_order_code: orderCode
        }]).select('id').single();
        if (error) throw error;

        // Nếu chỉ định method === 'payos' hoặc admin bật tự động (và không chọn manual)
        const usePayOS = method === 'payos' || (method !== 'manual' && settingsStore.getAutoApprovePayOS());

        if (usePayOS) {
            let origin = 'http://127.0.0.1:5500';
            if (req.headers.referer) {
                try {
                    origin = new URL(req.headers.referer).origin;
                } catch (e) {}
            }
            const returnBaseUrl = `${origin}/Front_end/user/wallet.html`;

            // Tạo body cho PayOS
            const requestData = {
                orderCode: orderCode,
                amount: Number(amount),
                description: `Nap Token ${orderCode}`,
                cancelUrl: `${returnBaseUrl}?status=cancel&orderCode=${orderCode}`,
                returnUrl: `${returnBaseUrl}?status=success&orderCode=${orderCode}`,
                expiredAt: Math.floor(Date.now() / 1000) + 300 // 5 phút (300 giây)
            };

            const paymentLink = await payos.paymentRequests.create(requestData);
            console.log(`✅ [PayOS Link Created] OrderCode: ${orderCode} | CheckoutUrl: ${paymentLink.checkoutUrl}`);
            res.json({ 
                type: 'payos', 
                checkoutUrl: paymentLink.checkoutUrl, 
                orderCode: orderCode,
                qrCode: paymentLink.qrCode,
                request_id: data.id
            });
        } else {
            // DUYỆT THỦ CÔNG -> Trả về mã nạp thủ công
            const transferCode = `HTword ${data.id.substring(0, 6).toUpperCase()}`;
            console.log(`✅ [Manual Deposit Created] TransferCode: ${transferCode} | Request ID: ${data.id}`);
            res.json({ type: 'manual', transferCode: transferCode, request_id: data.id });
        }
    } catch (error) {
        console.error('❌ Lỗi tạo lệnh nạp tiền:', error.message);
        res.status(500).json({ error: error.message || 'Không thể tạo lệnh nạp tiền' });
    }
});

// API PayOS: Webhook nhận tín hiệu thanh toán thành công
router.post('/api/payment/payos-webhook', async (req, res) => {
    try {
        const webhookData = await payos.webhooks.verify(req.body);
        if (webhookData && webhookData.orderCode) {
            const orderCode = webhookData.orderCode;
            const amount = Number(webhookData.amount);
            console.log(`
🔔 [PayOS Webhook] Nhận tín hiệu thanh toán: OrderCode ${orderCode} - Số tiền: ${amount}`);
            
            // Tìm lệnh nạp tiền
            const { data: request, error: reqErr } = await supabase.from('deposit_requests').select('*').eq('payos_order_code', orderCode).single();
            if (reqErr || !request || request.status === 'approved') {
                return res.json({ success: true });
            }

            // 1. Cập nhật trạng thái
            await supabase.from('deposit_requests').update({ status: 'approved' }).eq('id', request.id);
            
            // 2. Cộng tiền cho User
            const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', request.user_id).single();
            const newBalance = wallet ? wallet.balance + amount : amount;
            
            if (wallet) {
                await supabase.from('wallets').update({ balance: newBalance }).eq('user_id', request.user_id);
            } else {
                await supabase.from('wallets').insert([{ user_id: request.user_id, balance: newBalance, locked_balance: 0 }]);
            }
            
            // 3. Ghi log transactions
            await supabase.from('transactions').insert([{
                user_id: request.user_id,
                amount: amount,
                type: 'deposit',
                status: 'success',
                note: 'Nạp tiền tự động qua PayOS'
            }]);

            if (blockchain.isConfigured()) {
                blockchain.addBalance(request.user_id, amount).catch(console.error);
            }
            
            // 4. Gửi thông báo
            await supabase.from('notifications').insert([{
                user_id: request.user_id,
                title: 'Nạp tiền tự động thành công!',
                content: `Bạn vừa nạp thành công ${amount.toLocaleString()} Token thông qua Cổng thanh toán PayOS.`
            }]);
            
            console.log(`✅ [PayOS Webhook] Đã tự động cộng tiền cho user ${request.user_id}!`);
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Webhook error:', error.message);
        res.json({ success: false, error: error.message });
    }
});

// API Xác thực & Tự động cộng tiền (Polling hoặc sau khi Redirect)
router.post('/api/payment/verify-deposit', async (req, res) => {
    const { orderCode } = req.body;
    try {
        if (!orderCode) return res.status(400).json({ error: 'Missing orderCode' });
        
        // 1. Kiểm tra CSDL xem đã xử lý chưa
        const { data: request, error: reqErr } = await supabase.from('deposit_requests').select('*').eq('payos_order_code', orderCode).single();
        if (reqErr || !request) return res.status(404).json({ error: 'Order not found' });
        
        if (request.status === 'approved') {
            return res.json({ success: true, already_processed: true, amount: request.amount });
        }

        // 2. Lấy trạng thái thực tế từ PayOS Server
        const paymentData = await payos.paymentRequests.getPaymentLinkInformation(orderCode);
        
        if (paymentData && paymentData.status === 'PAID') {
            const amount = Number(paymentData.amount);
            console.log(`
🎉 [PayOS Verify API] Đơn hàng ${orderCode} ĐÃ THANH TOÁN (PAID)! Tiến hành cộng +${amount} Token`);
            
            // Xử lý CỘNG TIỀN
            await supabase.from('deposit_requests').update({ status: 'approved' }).eq('id', request.id);
            const { data: wallet } = await supabase.from('wallets').select('balance').eq('user_id', request.user_id).single();
            const newBalance = wallet ? wallet.balance + amount : amount;
            
            if (wallet) {
                await supabase.from('wallets').update({ balance: newBalance }).eq('user_id', request.user_id);
            } else {
                await supabase.from('wallets').insert([{ user_id: request.user_id, balance: newBalance, locked_balance: 0 }]);
            }
            
            await supabase.from('transactions').insert([{
                user_id: request.user_id,
                amount: amount,
                type: 'deposit',
                status: 'success',
                note: 'Nạp tiền tự động qua PayOS'
            }]);
            
            if (blockchain.isConfigured()) {
                blockchain.addBalance(request.user_id, amount).catch(console.error);
            }
            
            await supabase.from('notifications').insert([{
                user_id: request.user_id,
                title: 'Nạp tiền tự động thành công!',
                content: `Bạn vừa nạp thành công ${amount.toLocaleString()} Token thông qua Cổng thanh toán PayOS.`
            }]);

            return res.json({ success: true, processed_now: true, amount: amount, new_balance: newBalance });
        }
        
        res.json({ success: false, status: paymentData ? paymentData.status : 'PENDING' });
    } catch (error) {
        console.error('Verify error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// 11. API: Khách hàng tạo lệnh nạp Token (Có chống Spam)
router.post('/api/deposit', async (req, res) => {
    const { user_id, amount } = req.body;
    try {
        // Kiểm tra xem user có lệnh pending nào không
        const { data: existing } = await supabase
            .from('deposit_requests')
            .select('*')
            .eq('user_id', user_id)
            .eq('status', 'pending');
            
        if (existing && existing.length > 0) {
            return res.status(400).json({ error: 'Bạn đang có một lệnh nạp tiền chờ xử lý. Vui lòng thanh toán hoặc chờ lệnh cũ hết hạn.' });
        }

        const { data, error } = await supabase.from('deposit_requests').insert([{ user_id, amount }]).select('id, created_at').single();
        if (error) throw error;
        
        // Tạo mã chuyển khoản từ 6 ký tự đầu của ID
        const transferCode = 'HTword ' + data.id.substring(0, 6).toUpperCase();

        res.status(200).json({ 
            message: 'Đã gửi lệnh nạp tiền. Vui lòng chờ Admin duyệt.',
            transferCode: transferCode,
            request: data
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Lấy lệnh nạp đang Pending của User
router.get('/api/deposit/pending/:user_id', async (req, res) => {
    const { user_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('id, amount, created_at, status')
            .eq('user_id', user_id)
            .eq('status', 'pending')
            .order('created_at', { ascending: false })
            .limit(1);

        if (error) throw error;
        
        let activeRequest = null;
        if (data && data.length > 0) {
            const reqData = data[0];
            const ageMinutes = (new Date() - new Date(reqData.created_at)) / 60000;
            
            // Nếu lệnh pending quá 15 phút, tự động bỏ qua (coi như hết hạn)
            if (reqData.status === 'pending' && ageMinutes > 15) {
                await supabase.from('deposit_requests').update({ status: 'expired' }).eq('id', reqData.id);
            } else if (reqData.status === 'pending') {
                activeRequest = reqData;
            }
        }

        res.status(200).json({ request: activeRequest });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Kiểm tra trạng thái của một lệnh nạp cụ thể
router.get('/api/deposit/check/:request_id', async (req, res) => {
    const { request_id } = req.params;
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('status')
            .eq('id', request_id)
            .single();

        if (error) throw error;
        res.status(200).json({ status: data.status });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 12. API: Admin lấy danh sách lệnh nạp tiền chờ duyệt
router.get('/api/admin/deposits', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .select('*, users(full_name, email)')
            .in('status', ['pending', 'paid_waiting_approval'])
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.status(200).json({ deposits: data });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// 13. API: Admin duyệt nạp tiền (Chuẩn Core Banking)
router.post('/api/admin/deposits/approve', async (req, res) => {
    const { request_id, admin_id } = req.body;
    try {
        const admin_id_to_use = admin_id || '11111111-1111-1111-1111-111111111111';
        // Gọi Stored Function xử lý ACID
        const { data: rpcResult, error: rpcError } = await supabase.rpc('fn_approve_deposit', {
            p_request_id: request_id,
            p_admin_id: admin_id_to_use
        });

        if (rpcError) throw rpcError;

        if (!rpcResult.success) {
            return res.status(400).json({ error: rpcResult.error });
        }

        // Lấy thông tin user_id để gửi thông báo
        const { data: reqData } = await supabase.from('deposit_requests').select('user_id, amount').eq('id', request_id).single();

        if (reqData) {
            // ĐỒNG BỘ LÊN BLOCKCHAIN (WEB2.5)
            if (blockchain.isConfigured()) {
                await blockchain.addBalance(reqData.user_id, reqData.amount);
            }

            await supabase.from('notifications').insert([{
                user_id: reqData.user_id,
                title: '💰 Nạp Token Thành Công',
                content: `Lệnh nạp ${reqData.amount} Token của bạn đã được duyệt và cộng vào ví khả dụng.`
            }]);

            logEvent({
                module: 'WALLET',
                action: 'DEPOSIT_APPROVE',
                actor_id: admin_id_to_use,
                target_id: reqData.user_id,
                level: 'INFO',
                details: `Admin đã phê duyệt nạp ${reqData.amount.toLocaleString()} Token cho User ID: ${reqData.user_id}`,
                metadata: { request_id, amount: reqData.amount, admin_id: admin_id_to_use }
            });
        }

        res.status(200).json({ message: rpcResult.message });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// API: Admin duyệt nạp tiền HÀNG LOẠT
router.post('/api/admin/deposits/approve-batch', async (req, res) => {
    const { request_ids, admin_id } = req.body;
    try {
        if (!request_ids || !Array.isArray(request_ids) || request_ids.length === 0) {
            return res.status(400).json({ error: 'Không có giao dịch nào được chọn.' });
        }
        
        const admin_id_to_use = admin_id || '11111111-1111-1111-1111-111111111111';
        let successCount = 0;
        let errors = [];

        // Duyệt qua từng ID và xử lý
        for (const req_id of request_ids) {
            try {
                const { data: rpcResult, error: rpcError } = await supabase.rpc('fn_approve_deposit', {
                    p_request_id: req_id,
                    p_admin_id: admin_id_to_use
                });

                if (rpcError) throw rpcError;
                if (!rpcResult.success) throw new Error(rpcResult.error);

                // Gửi thông báo và đồng bộ Blockchain
                const { data: reqData } = await supabase.from('deposit_requests').select('user_id, amount').eq('id', req_id).single();
                
                if (reqData) {
                    if (blockchain.isConfigured()) {
                        blockchain.addBalance(reqData.user_id, reqData.amount).catch(console.error); // Gọi không đợi để duyệt nhanh
                    }

                    await supabase.from('notifications').insert([{
                        user_id: reqData.user_id,
                        title: '💰 Nạp Token Thành Công',
                        content: `Lệnh nạp ${reqData.amount} Token của bạn đã được duyệt.`
                    }]);
                }
                successCount++;
            } catch (err) {
                errors.push(`Lỗi ID ${req_id}: ${err.message}`);
            }
        }

        if (successCount === 0) {
            return res.status(400).json({ error: 'Không thể duyệt bất kỳ giao dịch nào. ' + errors.join(', ') });
        }

        res.status(200).json({ message: `Đã duyệt thành công ${successCount}/${request_ids.length} giao dịch.` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API: Admin từ chối lệnh nạp tiền
router.post('/api/admin/deposits/reject', async (req, res) => {
    const { request_id } = req.body;
    try {
        const { data, error } = await supabase
            .from('deposit_requests')
            .update({ status: 'rejected' })
            .eq('id', request_id)
            .select('user_id, amount')
            .single();

        if (error) throw error;

        if (data) {
            await supabase.from('notifications').insert([{
                user_id: data.user_id,
                title: '❌ Lệnh Nạp Tiền Bị Từ Chối',
                content: `Lệnh nạp ${data.amount} Token của bạn đã bị từ chối. Vui lòng kiểm tra lại thông tin giao dịch.`
            }]);
        }

        res.status(200).json({ message: 'Đã từ chối lệnh nạp tiền.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
