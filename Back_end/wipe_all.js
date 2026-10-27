require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const cloudinary = require('cloudinary').v2;
const { S3Client, ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { autoRefreshToken: false, persistSession: false }
});

const s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

const bucketName = process.env.AWS_S3_BUCKET_NAME;

const tablesToWipe = [
    'notifications', 'system_audit_logs', 'wallet_ledger', 'transactions',
    'deposit_requests', 'withdraw_requests', 'wallets', 'milestone_revisions',
    'milestones', 'job_applications', 'direct_messages', 'friendships',
    'jobs', 'freelancer_profiles', 'otp_verifications', 'users'
];

async function wipeSupabase() {
    console.log('\n--- 1. ĐANG XÓA SUPABASE ---');
    for (const table of tablesToWipe) {
        try {
            const { data, error: selectErr } = await supabase.from(table).select('id').limit(9999);
            if (selectErr) {
                const { error: delErr } = await supabase.from(table).delete().neq('id', 'non-existent');
                console.log(`✅ Đã làm sạch bảng không có id: ${table}`);
                continue;
            }
            if (!data || data.length === 0) continue;
            
            const ids = data.map(r => r.id);
            for (let i = 0; i < ids.length; i += 1000) {
                const batchIds = ids.slice(i, i + 1000);
                await supabase.from(table).delete().in('id', batchIds);
            }
            console.log(`✅ Đã xóa ${ids.length} dòng từ bảng: ${table}`);
        } catch (err) {
            console.error(`❌ Lỗi bảng ${table}:`, err.message);
        }
    }
}

async function wipeCloudinary() {
    console.log('\n--- 2. ĐANG XÓA CLOUDINARY ---');
    try {
        // Xóa images
        const resultImg = await cloudinary.api.delete_all_resources({ resource_type: 'image' });
        console.log('✅ Đã xóa toàn bộ ảnh trên Cloudinary:', Object.keys(resultImg.deleted || {}).length, 'file');
        
        // Xóa raw files (pdf, doc, zip)
        const resultRaw = await cloudinary.api.delete_all_resources({ resource_type: 'raw' });
        console.log('✅ Đã xóa toàn bộ tài liệu (raw) trên Cloudinary:', Object.keys(resultRaw.deleted || {}).length, 'file');
    } catch (err) {
        console.error('❌ Lỗi xóa Cloudinary:', err.message);
    }
}

async function wipeS3() {
    console.log('\n--- 3. ĐANG XÓA AWS S3 ---');
    try {
        let isTruncated = true;
        let continuationToken = undefined;
        let totalDeleted = 0;

        while (isTruncated) {
            const listCommand = new ListObjectsV2Command({
                Bucket: bucketName,
                ContinuationToken: continuationToken
            });
            const listRes = await s3.send(listCommand);

            if (listRes.Contents && listRes.Contents.length > 0) {
                const deleteParams = {
                    Bucket: bucketName,
                    Delete: {
                        Objects: listRes.Contents.map(c => ({ Key: c.Key }))
                    }
                };
                await s3.send(new DeleteObjectsCommand(deleteParams));
                totalDeleted += listRes.Contents.length;
            }
            
            isTruncated = listRes.IsTruncated;
            continuationToken = listRes.NextContinuationToken;
        }
        console.log(`✅ Đã xóa ${totalDeleted} file trên bucket S3: ${bucketName}`);
    } catch (err) {
        console.error('❌ Lỗi xóa AWS S3:', err.message);
    }
}

function wipeLocalUploads() {
    console.log('\n--- 4. ĐANG XÓA THƯ MỤC UPLOADS LOCAL ---');
    const uploadsDir = path.join(__dirname, 'uploads');
    if (fs.existsSync(uploadsDir)) {
        const files = fs.readdirSync(uploadsDir);
        let count = 0;
        for (const file of files) {
            fs.unlinkSync(path.join(uploadsDir, file));
            count++;
        }
        console.log(`✅ Đã xóa ${count} file trong thư mục uploads local.`);
    }
}

async function main() {
    console.log('🚀 BẮT ĐẦU QUÁ TRÌNH WIPE ALL DATA (SUPABASE, CLOUDINARY, S3, LOCAL) 🚀\n');
    await wipeSupabase();
    await wipeCloudinary();
    await wipeS3();
    wipeLocalUploads();
    console.log('\n⚠️ LƯU Ý VỀ BLOCKCHAIN:');
    console.log('Blockchain (Ethereum/Sepolia) là công nghệ BẤT BIẾN (Immutable). Bạn KHÔNG THỂ xóa lịch sử giao dịch hay dữ liệu trên Smart Contract đã deploy.');
    console.log('👉 Giải pháp: Để "Reset" blockchain, bạn cần Deploy lại 1 Smart Contract mới và copy địa chỉ mới dán vào biến BLOCKCHAIN_CONTRACT_ADDRESS trong file .env');
    console.log('\n🎉 HOÀN TẤT TOÀN BỘ QUÁ TRÌNH DỌN DẸP! 🎉');
}

main();
