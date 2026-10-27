import os
import json
import re

# Khởi tạo file json mặc định
config_path = r'd:\Project_internship\New_code\code\Back_end\dashboard_config.json'
default_config = {
    "widgets": [
        {
            "id": "widget-1",
            "title": "Dòng Tiền Lưu Thông",
            "type": "line",
            "source_table": "wallet_ledger",
            "group_by": "created_at",
            "metric": "sum",
            "metric_column": "amount",
            "w": 6,
            "h": 4,
            "x": 0,
            "y": 0
        },
        {
            "id": "widget-2",
            "title": "Tỷ Trọng Giao Dịch",
            "type": "doughnut",
            "source_table": "wallet_ledger",
            "group_by": "transaction_type",
            "metric": "sum",
            "metric_column": "amount",
            "w": 6,
            "h": 4,
            "x": 6,
            "y": 0
        }
    ]
}

if not os.path.exists(config_path):
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=4)

# Thêm API vào adminRoutes.js
routes_path = r'd:\Project_internship\New_code\code\Back_end\routes\adminRoutes.js'
with open(routes_path, 'r', encoding='utf-8') as f:
    content = f.read()

api_code = '''
// API: Đọc cấu hình Dashboard
router.get('/api/admin/dashboard-config', (req, res) => {
    try {
        const configPath = path.join(__dirname, '../dashboard_config.json');
        if (fs.existsSync(configPath)) {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            return res.json(config);
        }
        res.json({ widgets: [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API: Lưu cấu hình Dashboard
router.post('/api/admin/dashboard-config', (req, res) => {
    try {
        const configPath = path.join(__dirname, '../dashboard_config.json');
        fs.writeFileSync(configPath, JSON.stringify(req.body, null, 4), 'utf8');
        res.json({ message: 'Saved successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
'''

if '/api/admin/dashboard-config' not in content:
    # Need to make sure fs and path are imported
    if "const fs = require('fs');" not in content:
        content = "const fs = require('fs');\nconst path = require('path');\n" + content
    content += '\n' + api_code
    with open(routes_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Added Dashboard Config APIs to adminRoutes.js")
else:
    print("API already exists.")
