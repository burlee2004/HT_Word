const fs = require('fs');
const path = require('path');

const FRONTEND_DIR = path.resolve(__dirname, '..', 'Front_end');

function scanHtmlFiles(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    for (const item of list) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(scanHtmlFiles(fullPath));
        } else if (item.endsWith('.html')) {
            results.push(fullPath);
        }
    }
    return results;
}

const files = scanHtmlFiles(FRONTEND_DIR);
let patchedCount = 0;

for (const file of files) {
    let content = fs.readFileSync(file, 'utf8');
    let modified = false;

    // 1. Thêm data-cfasync="false" vào cdn.tailwindcss.com nếu chưa có
    if (content.includes('cdn.tailwindcss.com') && !content.includes('cdn.tailwindcss.com" data-cfasync="false"')) {
        content = content.replace(
            /<script\s+src="https:\/\/cdn\.tailwindcss\.com"><\/script>/g,
            '<script src="https://cdn.tailwindcss.com" data-cfasync="false"></script>'
        );
        modified = true;
    }

    // 2. Thêm data-cfasync="false" vào tailwind.config script nếu chưa có
    if (content.includes('tailwind.config =') && !content.includes('<script data-cfasync="false">')) {
        content = content.replace(
            /<script>(\s*tailwind\.config\s*=)/g,
            '<script data-cfasync="false">$1'
        );
        modified = true;
    }

    if (modified) {
        fs.writeFileSync(file, content, 'utf8');
        patchedCount++;
    }
}

console.log(`Đã vá bảo vệ chống lỗi Cloudflare Rocket Loader thành công cho ${patchedCount} files HTML!`);
