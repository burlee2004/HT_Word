const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const supabase = require('../config/supabase');

const catFilePath = path.join(__dirname, '..', 'data', 'categories.json');

function loadCategories() {
    try {
        if (!fs.existsSync(catFilePath)) {
            return [];
        }
        const raw = fs.readFileSync(catFilePath, 'utf-8');
        return JSON.parse(raw);
    } catch (err) {
        console.error('Lỗi đọc categories.json:', err);
        return [];
    }
}

function saveCategories(cats) {
    try {
        fs.writeFileSync(catFilePath, JSON.stringify(cats, null, 2), 'utf-8');
        return true;
    } catch (err) {
        console.error('Lỗi ghi categories.json:', err);
        return false;
    }
}

// 1. API: Lấy danh sách danh mục đang kích hoạt (Dành cho Client & Freelancer)
router.get('/api/categories', (req, res) => {
    try {
        const cats = loadCategories();
        const activeCats = cats.filter(c => c.is_active !== false).sort((a, b) => (a.sort_order || 99) - (b.sort_order || 99));
        res.json({ success: true, categories: activeCats });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. API Admin: Lấy danh sách danh mục + Thống kê số lượng dự án & phân tích mục "Khác"
router.get('/api/admin/categories/stats', async (req, res) => {
    try {
        const cats = loadCategories();
        
        // Lấy toàn bộ jobs để thống kê
        const { data: jobs, error } = await supabase
            .from('jobs')
            .select('id, title, description, budget, status, created_at');

        const allJobs = jobs || [];
        const totalJobsCount = allJobs.length;

        // Thống kê phân bổ theo từng danh mục
        const categoriesWithStats = cats.map(cat => {
            const catJobs = allJobs.filter(j => {
                const desc = (j.description || '').toLowerCase();
                const title = (j.title || '').toLowerCase();
                const catSlug = cat.slug.toLowerCase();
                const catName = cat.name.toLowerCase();

                // Kiểm tra xem job có gắn category này trong description hoặc title không
                return desc.includes(`[danh mục: ${catSlug}]`) || 
                       desc.includes(`[danh mục: ${catName}]`) ||
                       desc.includes(`danh mục: ${cat.name}`) ||
                       desc.includes(catSlug) ||
                       (cat.slug === 'web-dev' && (title.includes('web') || desc.includes('website') || desc.includes('web '))) ||
                       (cat.slug === 'mobile-app' && (title.includes('app') || desc.includes('mobile') || desc.includes('ứng dụng'))) ||
                       (cat.slug === 'ui-ux' && (title.includes('ui') || title.includes('ux') || title.includes('thiết kế') || desc.includes('figma'))) ||
                       (cat.slug === 'ai-data' && (title.includes('ai') || desc.includes('chatbot') || desc.includes('python') || desc.includes('data'))) ||
                       (cat.slug === 'blockchain-web3' && (title.includes('smart contract') || title.includes('solidity') || desc.includes('blockchain') || desc.includes('token'))) ||
                       (cat.slug === 'devops-cloud' && (title.includes('server') || title.includes('vps') || desc.includes('docker') || desc.includes('deploy')));
            });

            const totalBudget = catJobs.reduce((sum, j) => sum + (parseFloat(j.budget) || 0), 0);
            const openJobsCount = catJobs.filter(j => j.status === 'open').length;
            const completedJobsCount = catJobs.filter(j => j.status === 'completed' || j.status === 'in_progress').length;

            return {
                ...cat,
                total_jobs: catJobs.length,
                open_jobs: openJobsCount,
                completed_jobs: completedJobsCount,
                total_budget: totalBudget,
                percentage: totalJobsCount > 0 ? Math.round((catJobs.length / totalJobsCount) * 100) : 0
            };
        });

        // Phân tích nhóm dự án thuộc mục "Khác" (other) để cảnh báo xu hướng cho Admin
        const otherCategory = categoriesWithStats.find(c => c.slug === 'other') || { total_jobs: 0 };
        const otherJobsList = allJobs.slice(0, 5).map(j => ({
            id: j.id,
            title: j.title,
            budget: j.budget,
            created_at: j.created_at
        }));

        res.json({
            success: true,
            total_jobs_overall: totalJobsCount,
            categories: categoriesWithStats,
            other_analysis: {
                total_other_jobs: otherCategory.total_jobs,
                percentage_other: otherCategory.percentage,
                recommendation: otherCategory.total_jobs >= 3 
                    ? `Phát hiện ${otherCategory.total_jobs} dự án thuộc mục "Khác". Bạn nên cân nhắc tạo thêm danh mục chuyên biệt mới để tăng tỷ lệ kết nối!` 
                    : 'Số lượng dự án mục "Khác" ở mức an toàn (< 10%).',
                recent_samples: otherJobsList
            }
        });
    } catch (error) {
        console.error('Lỗi lấy thống kê danh mục:', error);
        res.status(500).json({ error: error.message });
    }
});

// 3. API Admin: Thêm Danh mục Mới
router.post('/api/admin/categories', (req, res) => {
    try {
        const { name, icon, description, tags_preset } = req.body;
        if (!name) {
            return res.status(400).json({ error: 'Tên danh mục là bắt buộc' });
        }

        const cats = loadCategories();
        
        // Tạo slug từ name
        const slug = name.toLowerCase()
            .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
            .replace(/đ/g, 'd').replace(/Đ/g, 'D')
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');

        const newCat = {
            id: 'cat_' + Date.now().toString(36),
            name: name.trim(),
            slug: slug || 'cat-' + Date.now(),
            icon: icon || '📁',
            description: description || '',
            tags_preset: Array.isArray(tags_preset) ? tags_preset : (tags_preset ? tags_preset.split(',').map(t => t.trim()).filter(Boolean) : []),
            is_active: true,
            sort_order: cats.length + 1,
            created_at: new Date().toISOString()
        };

        cats.push(newCat);
        saveCategories(cats);

        console.log(`✅ [Admin Categories] Thêm danh mục mới: ${newCat.name} (${newCat.id})`);
        res.status(201).json({ success: true, message: 'Đã thêm danh mục mới thành công!', category: newCat });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. API Admin: Cập nhật Danh mục (Sửa tên, icon, tags, Ẩn/Hiện)
router.put('/api/admin/categories/:id', (req, res) => {
    try {
        const { id } = req.params;
        const { name, icon, description, tags_preset, is_active, sort_order } = req.body;

        const cats = loadCategories();
        const index = cats.findIndex(c => c.id === id);

        if (index === -1) {
            return res.status(404).json({ error: 'Không tìm thấy danh mục' });
        }

        if (name !== undefined) cats[index].name = name.trim();
        if (icon !== undefined) cats[index].icon = icon;
        if (description !== undefined) cats[index].description = description;
        if (tags_preset !== undefined) {
            cats[index].tags_preset = Array.isArray(tags_preset) ? tags_preset : tags_preset.split(',').map(t => t.trim()).filter(Boolean);
        }
        if (is_active !== undefined) cats[index].is_active = Boolean(is_active);
        if (sort_order !== undefined) cats[index].sort_order = Number(sort_order);

        saveCategories(cats);
        console.log(`✅ [Admin Categories] Cập nhật danh mục: ${cats[index].name}`);
        res.json({ success: true, message: 'Đã cập nhật danh mục thành công!', category: cats[index] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. API Admin: Xóa Danh mục
router.delete('/api/admin/categories/:id', (req, res) => {
    try {
        const { id } = req.params;
        let cats = loadCategories();

        if (!cats.some(c => c.id === id)) {
            return res.status(404).json({ error: 'Không tìm thấy danh mục' });
        }

        const deleted = cats.find(c => c.id === id);
        cats = cats.filter(c => c.id !== id);
        saveCategories(cats);

        console.log(`🗑️ [Admin Categories] Xóa danh mục: ${deleted?.name}`);
        res.json({ success: true, message: 'Đã xóa danh mục thành công!' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
