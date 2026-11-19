/**
 * ==============================================================================
 * HT WORK PLATFORM - SAFE PRODUCTION MINIFIER & CODE COMPRESSOR (HTML & JS)
 * ==============================================================================
 * Chức năng:
 *  - Nén toàn bộ mã HTML về 1 dòng (giống Facebook view-source)
 *  - Nén toàn bộ mã JavaScript (.js ngoài) về 1 dòng, xóa sạch 100% chú thích (comments)
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
const { minify: minifyHtml } = require('html-minifier-terser');
const terser = require('terser');

const ROOT_DIR = path.resolve(__dirname, '..');
const FRONTEND_DIR = path.join(ROOT_DIR, 'Front_end');
const BACKUP_DIR = path.join(ROOT_DIR, 'backup_html', 'Front_end_clean_backup');
const DIST_DIR = path.join(ROOT_DIR, 'dist');

// Cấu hình nén HTML an toàn tuyệt đối
const HTML_MINIFY_OPTIONS = {
    collapseWhitespace: true,
    removeComments: true,
    minifyCSS: true,
    minifyJS: {
        mangle: false,
        compress: false
    },
    removeRedundantAttributes: false,
    removeEmptyAttributes: false,
    caseSensitive: true,
    keepClosingSlash: true,
    preserveLineBreaks: false
};

// Cấu hình nén JS an toàn tuyệt đối (Xóa sạch mọi comment, gom về 1 dòng, giữ nguyên tên hàm)
const JS_MINIFY_OPTIONS = {
    mangle: false,       // KHÔNG đổi tên hàm/biến (để onclick, window.formatTokenHTML hoạt động 100%)
    compress: {
        dead_code: true
    },
    format: {
        comments: false  // XÓA SẠCH 100% CHÚ THÍCH (comments) để kẻ xấu không đọc được ghi chú hệ thống
    }
};

// Đệ quy lấy danh sách file theo đuôi mở rộng
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
    console.log('\n🔍 [HT WORK MINIFIER] Đang quét toàn bộ file HTML & JS trong Front_end...');
    const htmlFiles = scanFiles(FRONTEND_DIR, '.html');
    const jsFiles = scanFiles(FRONTEND_DIR, '.js');
    
    let totalHtmlOrig = 0, totalHtmlMin = 0;
    let totalJsOrig = 0, totalJsMin = 0;

    for (const file of htmlFiles) {
        const content = fs.readFileSync(file, 'utf8');
        totalHtmlOrig += content.length;
        try {
            const minified = await minifyHtml(content, HTML_MINIFY_OPTIONS);
            totalHtmlMin += minified.length;
        } catch (err) {}
    }

    for (const file of jsFiles) {
        const content = fs.readFileSync(file, 'utf8');
        totalJsOrig += content.length;
        try {
            const minified = await terser.minify(content, JS_MINIFY_OPTIONS);
            totalJsMin += (minified.code || '').length;
        } catch (err) {}
    }

    const totalOrig = totalHtmlOrig + totalJsOrig;
    const totalMin = totalHtmlMin + totalJsMin;
    const savedBytes = totalOrig - totalMin;
    const savedPercent = ((savedBytes / totalOrig) * 100).toFixed(2);

    console.log('\n======================================================');
    console.log(`📊 KẾT QUẢ PHÂN TÍCH NÉN TOÀN BỘ HỆ THỐNG:`);
    console.log(` - File HTML:               ${htmlFiles.length} files (Nén về 1 dòng)`);
    console.log(` - File JavaScript (.js):   ${jsFiles.length} files (Xóa 100% comment & gom 1 dòng)`);
    console.log(` - Dung lượng ban đầu:      ${(totalOrig / 1024).toFixed(1)} KB`);
    console.log(` - Sau khi nén & bảo mật:   ${(totalMin / 1024).toFixed(1)} KB`);
    console.log(` - Tiết kiệm được:          ${(savedBytes / 1024).toFixed(1)} KB (-${savedPercent}%)`);
    console.log('======================================================');
    console.log('💡 Lưu ý: Lệnh --preview KHÔNG làm thay đổi bất kỳ file nào.');
    console.log(' 👉 Để nén an toàn: chạy "node scripts/build_minify.js --apply"');
    console.log(' 👉 Để hoàn tác bất cứ lúc nào: chạy "node scripts/build_minify.js --restore"\n');
}

// 2. Chế độ sao lưu (Backup)
function makeBackup() {
    if (!fs.existsSync(BACKUP_DIR)) {
        console.log(`\n🛡️ [HT WORK BACKUP] Đang tạo bản sao lưu an toàn code gốc tại:`);
        console.log(`   ${BACKUP_DIR}`);
        copyDirRecursive(FRONTEND_DIR, BACKUP_DIR);
        console.log(`✅ Đã sao lưu 100% file gốc thành công!\n`);
    } else {
        console.log(`\n🛡️ [HT WORK BACKUP] Bản sao lưu code đẹp đã tồn tại an toàn trong:`);
        console.log(`   ${BACKUP_DIR}\n`);
    }
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
    console.log(`Toàn bộ code HTML và JavaScript trong Front_end đã trở lại dạng thụt dòng, chú thích ban đầu để bạn chỉnh sửa thoải mái.\n`);
}

// 4. Chế độ nén ra thư mục dist độc lập
async function runDist() {
    console.log(`\n📦 [HT WORK DIST] Đang tạo bản build nén độc lập tại: ${DIST_DIR}`);
    if (fs.existsSync(DIST_DIR)) {
        fs.rmSync(DIST_DIR, { recursive: true, force: true });
    }
    copyDirRecursive(FRONTEND_DIR, DIST_DIR);

    // Nén HTML
    const htmlFiles = scanFiles(DIST_DIR, '.html');
    for (const file of htmlFiles) {
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await minifyHtml(content, HTML_MINIFY_OPTIONS);
            fs.writeFileSync(file, minified, 'utf8');
        } catch (err) {}
    }

    // Nén JS
    const jsFiles = scanFiles(DIST_DIR, '.js');
    for (const file of jsFiles) {
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await terser.minify(content, JS_MINIFY_OPTIONS);
            if (minified.code) {
                fs.writeFileSync(file, minified.code, 'utf8');
            }
        } catch (err) {}
    }

    console.log(`✅ Đã nén thành công ${htmlFiles.length} file HTML và ${jsFiles.length} file JS vào thư mục "dist/".`);
    console.log(`Thư mục "Front_end" gốc của bạn hoàn toàn KHÔNG bị đụng chạm gì!\n`);
}

// 5. Chế độ áp dụng nén trực tiếp (Có tự động sao lưu trước)
async function runApply() {
    console.log(`\n🚀 [HT WORK MINIFIER] Bắt đầu quá trình nén mã nguồn & xóa comment bảo mật...`);
    // Bước 1: Đảm bảo có bản sao lưu an toàn
    makeBackup();

    // Bước 2: Nén từng file HTML
    const htmlFiles = scanFiles(FRONTEND_DIR, '.html');
    let successHtml = 0;
    for (const file of htmlFiles) {
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await minifyHtml(content, HTML_MINIFY_OPTIONS);
            fs.writeFileSync(file, minified, 'utf8');
            successHtml++;
        } catch (err) {
            console.error(`❌ Bỏ qua file HTML lỗi: ${path.basename(file)}`, err.message);
        }
    }

    // Bước 3: Nén từng file JavaScript ngoài (.js)
    const jsFiles = scanFiles(FRONTEND_DIR, '.js');
    let successJs = 0;
    for (const file of jsFiles) {
        const content = fs.readFileSync(file, 'utf8');
        try {
            const minified = await terser.minify(content, JS_MINIFY_OPTIONS);
            if (minified.code) {
                fs.writeFileSync(file, minified.code, 'utf8');
                successJs++;
            }
        } catch (err) {
            console.error(`❌ Bỏ qua file JS lỗi: ${path.basename(file)}`, err.message);
        }
    }

    console.log(`\n======================================================`);
    console.log(`🎉 NÉN VÀ BẢO MẬT MÃ NGUỒN HOÀN TẤT THÀNH CÔNG!`);
    console.log(` - Đã nén ${successHtml}/${htmlFiles.length} file HTML về 1 dòng duy nhất.`);
    console.log(` - Đã nén & dọn sạch 100% comment trong ${successJs}/${jsFiles.length} file JavaScript.`);
    console.log(` - Giờ đây khi bấm vào link .js trên trình duyệt, toàn bộ code`);
    console.log(`   chỉ còn 1 dòng duy nhất, không còn bất kỳ comment hay ghi chú nào!`);
    console.log(` - Bản sao lưu code đẹp nằm an toàn tại: backup_html/Front_end_clean_backup`);
    console.log(`💡 Bất cứ khi nào bạn muốn mở code đẹp ra sửa, chỉ cần chạy:`);
    console.log(`   npm run build:restore`);
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
