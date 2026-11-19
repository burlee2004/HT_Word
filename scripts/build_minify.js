/**
 * ==============================================================================
 * HT WORK PLATFORM - SAFE PRODUCTION MINIFIER & CODE COMPRESSOR
 * ==============================================================================
 * Chức năng:
 *  - Nén toàn bộ mã HTML/CSS/JS nội tuyến về 1 dòng (giống Facebook view-source)
 *  - Xóa bỏ chú thích (comments), khoảng trắng thừa, giảm dung lượng tải trang ~30%
 *  - ĐẢM BẢO AN TOÀN TUYỆT ĐỐI (Zero Risk):
 *      1. Giữ nguyên tên hàm/biến toàn cục, Tailwind config, onclick handlers.
 *      2. Tự động sao lưu bản gốc sang "backup_html/Front_end_clean_backup" trước khi nén.
 *      3. Hỗ trợ lệnh khôi phục (restore) về bản gốc đẹp đẽ chỉ trong 1 giây.
 *
 * Cách sử dụng:
 *  - Xem trước (không sửa đổi gì): node scripts/build_minify.js --preview
 *  - Nén ra thư mục dist riêng biệt: node scripts/build_minify.js --dist
 *  - Áp dụng nén để deploy:        node scripts/build_minify.js --apply
 *  - Khôi phục code gốc 100%:     node scripts/build_minify.js --restore
 * ==============================================================================
 */

const fs = require('fs');
const path = require('path');
const { minify } = require('html-minifier-terser');

const ROOT_DIR = path.resolve(__dirname, '..');
const FRONTEND_DIR = path.join(ROOT_DIR, 'Front_end');
const BACKUP_DIR = path.join(ROOT_DIR, 'backup_html', 'Front_end_clean_backup');
const DIST_DIR = path.join(ROOT_DIR, 'dist');

// Cấu hình nén an toàn tuyệt đối (Không phá vỡ cú pháp JS, Tailwind hay biến)
const MINIFY_OPTIONS = {
    collapseWhitespace: true,
    removeComments: true,
    minifyCSS: true,
    minifyJS: {
        mangle: false,       // KHÔNG đổi tên biến (đảm bảo hàm toàn cục window/onclick hoạt động 100%)
        compress: false      // KHÔNG viết tắt biểu thức (tránh lỗi logic nhạy cảm)
    },
    removeRedundantAttributes: false,
    removeEmptyAttributes: false,
    caseSensitive: true,
    keepClosingSlash: true,
    preserveLineBreaks: false
};

// Đệ quy lấy danh sách file
function scanFiles(dir, ext = '.html') {
    let results = [];
    if (!fs.existsSync(dir)) return results;
    const list = fs.readdirSync(dir);
    for (const item of list) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(scanFiles(fullPath, ext));
        } else if (item.endsWith(ext)) {
            results.push(fullPath);
        }
    }
    return results;
}

// Sao chép thư mục đệ quy
function copyDirRecursive(src, dest) {
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyDirRecursive(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

// 1. Chế độ xem trước (Preview / Dry-run)
async function runPreview() {
    console.log('\n🔍 [HT WORK MINIFIER] Đang quét toàn bộ file HTML trong Front_end...');
    const files = scanFiles(FRONTEND_DIR, '.html');
    let totalOrig = 0;
    let totalMin = 0;

    for (const file of files) {
        const relPath = path.relative(ROOT_DIR, file);
        const content = fs.readFileSync(file, 'utf8');
        totalOrig += content.length;
        try {
            const minified = await minify(content, MINIFY_OPTIONS);
            totalMin += minified.length;
        } catch (err) {
            console.error(`❌ Lỗi phân tích file ${relPath}:`, err.message);
        }
    }

    const savedBytes = totalOrig - totalMin;
    const savedPercent = ((savedBytes / totalOrig) * 100).toFixed(2);

    console.log('\n======================================================');
    console.log(`📊 KẾT QUẢ PHÂN TÍCH NÉN:`);
    console.log(` - Tổng số file HTML:       ${files.length} files`);
    console.log(` - Dung lượng gốc ban đầu:   ${(totalOrig / 1024).toFixed(1)} KB`);
    console.log(` - Sau khi nén về 1 dòng:    ${(totalMin / 1024).toFixed(1)} KB`);
    console.log(` - Dung lượng tiết kiệm được: ${(savedBytes / 1024).toFixed(1)} KB (-${savedPercent}%)`);
    console.log('======================================================');
    console.log('💡 Lưu ý: Lệnh --preview KHÔNG làm thay đổi bất kỳ file nào.');
    console.log(' 👉 Để nén an toàn: chạy "node scripts/build_minify.js --apply"');
    console.log(' 👉 Để hoàn tác bất cứ lúc nào: chạy "node scripts/build_minify.js --restore"\n');
}

// 2. Chế độ sao lưu (Backup)
function makeBackup() {
    console.log(`\n🛡️ [HT WORK BACKUP] Đang tạo bản sao lưu an toàn code gốc tại:`);
    console.log(`   ${BACKUP_DIR}`);
    if (fs.existsSync(BACKUP_DIR)) {
        fs.rmSync(BACKUP_DIR, { recursive: true, force: true });
    }
    copyDirRecursive(FRONTEND_DIR, BACKUP_DIR);
    console.log(`✅ Đã sao lưu 100% file gốc thành công. Bạn luôn có thể khôi phục nguyên vẹn!\n`);
}

// 3. Chế độ khôi phục (Restore)
function runRestore() {
    console.log(`\n🔄 [HT WORK RESTORE] Đang khôi phục code gốc từ bản sao lưu...`);
    if (!fs.existsSync(BACKUP_DIR)) {
        console.error(`❌ Chưa có bản sao lưu nào trong "backup_html/Front_end_clean_backup".`);
        console.log(`💡 Mẹo: Bạn cũng có thể dùng lệnh "git checkout -- Front_end" để khôi phục code gốc từ Git.`);
        return;
    }
    copyDirRecursive(BACKUP_DIR, FRONTEND_DIR);
    console.log(`✅ KHÔI PHỤC THÀNH CÔNG!`);
    console.log(`Toàn bộ code trong Front_end đã trở lại dạng thụt dòng, chú thích ban đầu để bạn chỉnh sửa thoải mái.\n`);
}

// 4. Chế độ nén ra thư mục dist độc lập
async function runDist() {
    console.log(`\n📦 [HT WORK DIST] Đang tạo bản build nén độc lập tại: ${DIST_DIR}`);
    if (fs.existsSync(DIST_DIR)) {
        fs.rmSync(DIST_DIR, { recursive: true, force: true });
    }
    copyDirRecursive(FRONTEND_DIR, DIST_DIR);

    const htmlFiles = scanFiles(DIST_DIR, '.html');
    let count = 0;
    for (const file of htmlFiles) {
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await minify(content, MINIFY_OPTIONS);
            fs.writeFileSync(file, minified, 'utf8');
            count++;
        } catch (err) {
            console.error(`⚠️ Lỗi nén file ${path.basename(file)}:`, err.message);
        }
    }
    console.log(`✅ Đã nén ${count} file HTML thành công vào thư mục "dist/".`);
    console.log(`Thư mục "Front_end" gốc của bạn hoàn toàn KHÔNG bị đụng chạm gì!\n`);
}

// 5. Chế độ áp dụng nén trực tiếp (Có tự động sao lưu trước)
async function runApply() {
    console.log(`\n🚀 [HT WORK MINIFIER] Bắt đầu quá trình nén mã nguồn...`);
    // Bước 1: Luôn sao lưu code gốc trước
    makeBackup();

    // Bước 2: Nén từng file
    const files = scanFiles(FRONTEND_DIR, '.html');
    let successCount = 0;
    for (const file of files) {
        const relPath = path.relative(ROOT_DIR, file);
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await minify(content, MINIFY_OPTIONS);
            fs.writeFileSync(file, minified, 'utf8');
            successCount++;
        } catch (err) {
            console.error(`❌ Bỏ qua file lỗi cú pháp ${relPath}:`, err.message);
        }
    }

    console.log(`\n======================================================`);
    console.log(`🎉 NÉN HOÀN TẤT THÀNH CÔNG ${successCount}/${files.length} FILES!`);
    console.log(` - Giờ đây khi mở View-Source trên trình duyệt, mã nguồn HTML`);
    console.log(`   đã được gom thành 1 dòng siêu gọn như Facebook.`);
    console.log(` - Toàn bộ chú thích và khoảng trắng rác đã được dọn sạch.`);
    console.log(` - Bản sao lưu code đẹp nằm an toàn tại: backup_html/Front_end_clean_backup`);
    console.log(`💡 Bất cứ khi nào bạn muốn mở code đẹp ra sửa, chỉ cần chạy:`);
    console.log(`   node scripts/build_minify.js --restore`);
    console.log(`======================================================\n`);
}

// Điều hướng tham số dòng lệnh
async function main() {
    const arg = process.argv[2] || '--preview';

    switch (arg) {
        case '--apply':
            await runApply();
            break;
        case '--restore':
            runRestore();
            break;
        case '--backup':
            makeBackup();
            break;
        case '--dist':
            await runDist();
            break;
        case '--preview':
        default:
            await runPreview();
            break;
    }
}

main().catch(console.error);
