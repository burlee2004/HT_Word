require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const G = '\x1b[32m', R = '\x1b[31m', Y = '\x1b[33m', C = '\x1b[36m', B = '\x1b[1m', Z = '\x1b[0m';
const COLORS = {
    green:  '\x1b[32m',
    red:    '\x1b[31m',
    yellow: '\x1b[33m',
    cyan:   '\x1b[36m',
    bold:   '\x1b[1m',
    reset:  '\x1b[0m'
};
const log = (color, msg) => console.log(COLORS[color] + msg + COLORS.reset);

async function runTests() {
    log('bold', '\n==========================================');
    log('bold', '   🏦 HTWORK CORE BANKING - SECURITY TEST');
    log('bold', '==========================================\n');

    // === BƯỚC 1: Lấy 1 Milestone đang PENDING_REVIEW ===
    log('cyan', '🔍 Đang tìm Milestone đang PENDING_REVIEW...');
    const { data: milestones, error: mErr } = await supabase
        .from('milestones')
        .select('id, title, price, status, job_id')
        .eq('status', 'PENDING_REVIEW')
        .limit(1);

    if (mErr || !milestones || milestones.length === 0) {
        log('yellow', '⚠️  Không tìm thấy Milestone nào ở trạng thái PENDING_REVIEW.');
        log('yellow', '   Hãy vào web app: Freelancer nộp bài trước, rồi chạy lại test này.');
        
        // Thử tìm bất kỳ milestone nào để show trạng thái hiện tại
        const { data: allM } = await supabase.from('milestones').select('id, title, status').limit(5);
        if (allM && allM.length > 0) {
            log('cyan', '\n📋 Các Milestone hiện có trong DB:');
            allM.forEach(m => console.log(   - [] ));
        }
        return;
    }

    const milestone = milestones[0];
    log('green', ✅ Tìm thấy: "" | Price:  Token | Status: );

    // === BƯỚC 2: Lấy Client_id từ Jobs ===
    const { data: job } = await supabase.from('jobs').select('client_id').eq('id', milestone.job_id).single();
    const { data: app } = await supabase.from('job_applications').select('freelancer_id').eq('job_id', milestone.job_id).eq('status', 'accepted').single();
    
    if (!job || !app) {
        log('red', '❌ Không tìm được Client/Freelancer cho milestone này.');
        return;
    }

    const client_id = job.client_id;
    const freelancer_id = app.freelancer_id;
    log('cyan',    Client: ... | Freelancer: ...);

    // === BƯỚC 3: Ghi lại số dư TRƯỚC khi giải ngân ===
    const { data: clientWalletBefore } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', client_id).single();
    const { data: freeWalletBefore } = await supabase.from('wallets').select('balance').eq('user_id', freelancer_id).single();

    log('bold', '\n📊 SỐ DƯ TRƯỚC KHI GIẢI NGÂN:');
    if (clientWalletBefore) log('cyan',    Client   → Balance:  | Locked: );
    else log('yellow', '   Client   → Chưa có ví (cần chạy SQL migration trước)');
    if (freeWalletBefore) log('cyan',    Freelancer → Balance: );
    else log('yellow', '   Freelancer → Chưa có ví');

    // === TEST 1: Giải ngân lần 1 (phải PASS) ===
    log('bold', '\n-------------------------------------------');
    log('bold', '🧪 TEST 1: Giải ngân bình thường (Lần 1)');
    log('bold', '   Kỳ vọng: ✅ PASS');
    
    const idempotency_key = 'TEST_RELEASE_' + milestone.id;
    const { data: result1, error: err1 } = await supabase.rpc('fn_release_milestone', {
        p_milestone_id: milestone.id,
        p_client_id: client_id,
        p_freelancer_id: freelancer_id,
        p_idempotency_key: idempotency_key
    });

    if (err1) {
        log('yellow', ⚠️  RPC Error (có thể chưa chạy SQL migration): );
        log('yellow', '   → Hãy chạy file database_escrow_corebanking.sql trên Supabase SQL Editor trước!');
    } else if (result1 && result1.success) {
        log('green', ✅ PASS - );
    } else {
        log('red', ❌ FAIL (unexpected) - );
    }

    // === TEST 2: Giải ngân lần 2 CÙNG KEY (phải FAIL - chống duplicate) ===
    log('bold', '\n-------------------------------------------');
    log('bold', '🧪 TEST 2: Giải ngân lần 2 - CÙNG KEY (chống Duplicate Request)');
    log('bold', '   Kỳ vọng: ❌ FAIL (bị chặn bởi Idempotency Key)');

    const { data: result2 } = await supabase.rpc('fn_release_milestone', {
        p_milestone_id: milestone.id,
        p_client_id: client_id,
        p_freelancer_id: freelancer_id,
        p_idempotency_key: idempotency_key // CÙNG KEY
    });

    if (result2 && !result2.success) {
        log('green', ✅ PASS (Bị chặn đúng) - Lý do: "");
    } else if (result2 && result2.success) {
        log('red', ❌ NGUY HIỂM! Giải ngân lần 2 THÀNH CÔNG - Hệ thống có lỗ hổng!);
    }

    // === TEST 3: Giải ngân lần 3 KEY MỚI (vẫn phải FAIL - milestone đã PAID) ===
    log('bold', '\n-------------------------------------------');
    log('bold', '🧪 TEST 3: Giải ngân lần 3 - KEY MỚI (chống Race Condition)');
    log('bold', '   Kỳ vọng: ❌ FAIL (bị chặn bởi status = PAID)');

    const { data: result3 } = await supabase.rpc('fn_release_milestone', {
        p_milestone_id: milestone.id,
        p_client_id: client_id,
        p_freelancer_id: freelancer_id,
        p_idempotency_key: 'DIFFERENT_KEY_' + Date.now()
    });

    if (result3 && !result3.success) {
        log('green', ✅ PASS (Bị chặn đúng) - Lý do: "");
    } else if (result3 && result3.success) {
        log('red', ❌ NGUY HIỂM! Giải ngân lần 3 THÀNH CÔNG - Race Condition vulnerability!);
    }

    // === BƯỚC 4: Ghi lại số dư SAU khi giải ngân ===
    await new Promise(r => setTimeout(r, 1000));
    const { data: clientWalletAfter } = await supabase.from('wallets').select('balance, locked_balance').eq('user_id', client_id).single();
    const { data: freeWalletAfter } = await supabase.from('wallets').select('balance').eq('user_id', freelancer_id).single();

    log('bold', '\n📊 SỐ DƯ SAU KHI GIẢI NGÂN:');
    if (clientWalletAfter) log('cyan',    Client   → Balance:  | Locked: );
    if (freeWalletAfter) log('cyan',    Freelancer → Balance: );

    if (freeWalletBefore && freeWalletAfter && result1 && result1.success) {
        const diff = freeWalletAfter.balance - freeWalletBefore.balance;
        if (Math.abs(diff - milestone.price) < 0.01) {
            log('green', \n✅ TIỀN CHUYỂN ĐÚNG: Freelancer nhận đúng  Token (price = ));
        } else {
            log('red', ❌ TIỀN CHUYỂN SAI: Nhận  nhưng price = );
        }
    }

    // === BƯỚC 5: Kiểm tra Sổ Cái ===
    log('bold', '\n-------------------------------------------');
    log('bold', '📖 SỔ CÁI GIAO DỊCH (wallet_ledger):');
    const { data: ledger } = await supabase
        .from('wallet_ledger')
        .select('type, amount, sender_id, receiver_id, idempotency_key, created_at')
        .eq('milestone_id', milestone.id)
        .order('created_at', { ascending: false });

    if (ledger && ledger.length > 0) {
        log('green', ✅ Tìm thấy  bản ghi trong sổ cái:);
        ledger.forEach(l => {
            log('cyan',    [] Amount:  | Key:  | Thời gian: );
        });
    } else {
        log('yellow', '⚠️  Không tìm thấy bản ghi trong wallet_ledger. Hãy chạy SQL migration trước.');
    }

    log('bold', '\n==========================================');
    log('bold', '           KẾT THÚC TEST');
    log('bold', '==========================================\n');
}

runTests().catch(err => {
    console.error('Lỗi không xác định:', err.message);
});
