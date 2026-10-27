const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

const reviewFilePath = path.join(__dirname, '..', 'data', 'reviews.json');

function loadReviews() {
    try {
        if (!fs.existsSync(reviewFilePath)) {
            return [];
        }
        const raw = fs.readFileSync(reviewFilePath, 'utf-8');
        const clean = raw.replace(/^\uFEFF/, '').trim();
        return clean ? JSON.parse(clean) : [];
    } catch (err) {
        console.error('Lỗi đọc reviews.json:', err);
        return [];
    }
}

function saveReviews(reviews) {
    try {
        fs.writeFileSync(reviewFilePath, JSON.stringify(reviews, null, 2), 'utf-8');
        return true;
    } catch (err) {
        console.error('Lỗi ghi reviews.json:', err);
        return false;
    }
}

// 1. API: Khách hàng gửi Đánh giá & Chấm sao cho Freelancer
router.post('/api/reviews/submit', async (req, res) => {
    let { job_id, client_id, freelancer_id, rating, comment, tags } = req.body;
    console.log(`\n⭐ [API POST /api/reviews/submit] Client ${client_id} đánh giá Freelancer ${freelancer_id} (${rating}⭐) cho Job: ${job_id}`);
    try {
        if (!job_id || !client_id) {
            throw new Error('Thiếu thông tin đánh giá bắt buộc!');
        }

        // Tự động tìm freelancer_id nếu client gửi thiếu hoặc gửi 'null'
        if (!freelancer_id || freelancer_id === 'null' || freelancer_id === 'undefined') {
            const { data: appData } = await supabase
                .from('job_applications')
                .select('freelancer_id')
                .eq('job_id', job_id)
                .eq('status', 'accepted')
                .maybeSingle();
            if (appData && appData.freelancer_id) {
                freelancer_id = appData.freelancer_id;
            }
        }

        if (!freelancer_id || freelancer_id === 'null' || freelancer_id === 'undefined') {
            throw new Error('Không xác định được Freelancer để đánh giá cho dự án này!');
        }

        const score = Math.max(1, Math.min(5, parseInt(rating) || 5));

        // Lấy tên khách hàng, tên dự án và thông tin freelancer
        const { data: client } = await supabase.from('users').select('full_name, avatar_url').eq('id', client_id).maybeSingle();
        const { data: job } = await supabase.from('jobs').select('title').eq('id', job_id).maybeSingle();
        const { data: freelancer } = await supabase.from('users').select('full_name, avatar_url').eq('id', freelancer_id).maybeSingle();

        const reviews = loadReviews();
        
        // Kiểm tra xem đã đánh giá dự án này chưa
        const existingIndex = reviews.findIndex(r => r.job_id === job_id && r.client_id === client_id);

        const reviewObj = {
            id: existingIndex >= 0 ? reviews[existingIndex].id : ('rev_' + Date.now().toString(36)),
            job_id,
            job_title: job?.title || 'Dự án KGS Work',
            client_id,
            client_name: client?.full_name || 'Khách hàng',
            client_avatar: client?.avatar_url || '',
            freelancer_id,
            freelancer_name: freelancer?.full_name || 'Freelancer',
            freelancer_avatar: freelancer?.avatar_url || '',
            rating: score,
            comment: comment ? comment.trim() : 'Freelancer làm việc rất uy tín và chuyên nghiệp!',
            tags: Array.isArray(tags) ? tags : (tags ? [tags] : []),
            created_at: new Date().toISOString()
        };

        if (existingIndex >= 0) {
            reviews[existingIndex] = reviewObj;
        } else {
            reviews.push(reviewObj);
        }

        saveReviews(reviews);

        // Gửi thông báo đến Freelancer
        await supabase.from('notifications').insert([{
            user_id: freelancer_id,
            title: `⭐ Nhận được đánh giá ${score} sao mới!`,
            content: `Khách hàng ${client?.full_name || 'Khách hàng'} vừa chấm ${score}⭐ cho dự án "${job?.title || 'Dự án'}": "${reviewObj.comment}"`
        }]);

        console.log(`✅ [API POST /api/reviews/submit] Lưu đánh giá thành công cho Freelancer ${freelancer?.full_name || freelancer_id}!`);
        res.status(200).json({ success: true, message: 'Đã gửi đánh giá thành công!', review: reviewObj });
    } catch (error) {
        console.error(`❌ [API POST /api/reviews/submit] Lỗi: ${error.message}`);
        res.status(400).json({ error: error.message });
    }
});

// 2. API: Lấy đánh giá của một Job
router.get('/api/reviews/job/:job_id', (req, res) => {
 try {
 const { job_id } = req.params;
 const reviews = loadReviews();
 const review = reviews.find(r => r.job_id === job_id);
 res.status(200).json({ review: review || null });
 } catch (error) {
 res.status(400).json({ error: error.message });
 }
});

// 3. API: Lấy toàn bộ đánh giá và thống kê của một Freelancer
router.get('/api/reviews/freelancer/:freelancer_id', (req, res) => {
    try {
        const { freelancer_id } = req.params;
        const reviews = loadReviews();
        const fReviews = reviews.filter(r => r.freelancer_id === freelancer_id && r.freelancer_id !== 'null');
        
        let avgRating = null;
        if (fReviews.length > 0) {
            const sum = fReviews.reduce((acc, cur) => acc + (cur.rating || 5), 0);
            avgRating = Math.round((sum / fReviews.length) * 10) / 10;
        }

        res.status(200).json({
            total_reviews: fReviews.length,
            average_rating: avgRating,
            reviews: fReviews
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
// 4. API: Lấy toàn bộ đánh giá do một Client viết
router.get('/api/reviews/client/:client_id', (req, res) => {
    try {
        const { client_id } = req.params;
        const reviews = loadReviews();
        const cReviews = reviews.filter(r => r.client_id === client_id).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
        res.status(200).json({
            total_reviews: cReviews.length,
            reviews: cReviews
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

module.exports = router;
