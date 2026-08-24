require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function test() {
    console.log('--- TEST ESCROW SCRIPT ---');
    console.log('Vui long su dung trang giao dien Admin (escrow-security-test.html) de test truc quan hon.');
    
    const { data: list, error } = await supabase
        .from('milestones')
        .select('id, title, amount, status')
        .eq('status', 'PENDING_REVIEW')
        .limit(1);

    if (error) {
        console.error('Loi:', error.message);
        return;
    }

    if (!list || list.length === 0) {
        console.log('Khong tim thay milestone PENDING_REVIEW');
        return;
    }

    const ms = list[0];
    console.log('Tim thay Milestone:', ms.title, '| Amount:', ms.amount, 'Token');
}

test().catch(console.error);
