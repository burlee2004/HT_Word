require('dotenv').config();
const express = require('express');
const cors = require('cors');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(require('./routes/authRoutes'));

const TEST_PORT = 5899;

async function runUploadDestinationsTest() {
    console.log('========================================================================');
    console.log('🎯 KIỂM THỬ TÁCH BIỆT: HÌNH ẢNH ➔ CLOUDINARY | TÀI LIỆU & VIDEO ➔ AWS S3');
    console.log('========================================================================');

    const server = app.listen(TEST_PORT, async () => {
        try {
            console.log(`📡 Máy chủ test đang lắng nghe tại cổng ${TEST_PORT}...\n`);

            // 1. TEST POST /upload-image (Hình ảnh PNG ➔ Cloudinary)
            console.log('--- TEST 1: Upload Hình Ảnh PNG (/upload-image) ---');
            const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
            const imgBlob = new Blob([Buffer.from(pngBase64, 'base64')], { type: 'image/png' });
            const imgFormData = new FormData();
            imgFormData.append('image', imgBlob, 'avatar_profile_test.png');

            const resImg = await fetch(`http://localhost:${TEST_PORT}/upload-image`, {
                method: 'POST',
                body: imgFormData
            });
            const dataImg = await resImg.json();
            assert.strictEqual(resImg.status, 200, 'Upload ảnh trả về HTTP 200');
            assert(dataImg.imageUrl, 'Có trường imageUrl');
            assert(dataImg.imageUrl.includes('res.cloudinary.com'), 'Ảnh BẮT BUỘC lưu trữ trên Cloudinary (res.cloudinary.com)');
            console.log(`✅ [PASS] Hình ảnh PNG đã lưu thành công trên Cloudinary: ${dataImg.imageUrl}\n`);

            // 2. TEST POST /upload-file (Tài liệu PDF ➔ AWS S3)
            console.log('--- TEST 2: Upload Tài Liệu PDF (/upload-file) ---');
            const pdfBlob = new Blob([Buffer.from('%PDF-1.4 Mock PDF for test\n%%EOF')], { type: 'application/pdf' });
            const pdfFormData = new FormData();
            pdfFormData.append('file', pdfBlob, 'project_spec_document.pdf');

            const resPdf = await fetch(`http://localhost:${TEST_PORT}/upload-file`, {
                method: 'POST',
                body: pdfFormData
            });
            const dataPdf = await resPdf.json();
            assert.strictEqual(resPdf.status, 200, 'Upload PDF trả về HTTP 200');
            assert(dataPdf.fileUrl, 'Có trường fileUrl');
            assert(dataPdf.fileUrl.includes('amazonaws.com'), 'File PDF BẮT BUỘC lưu trữ trên AWS S3 (amazonaws.com)');
            assert(dataPdf.fileUrl.includes('htwork-app-storage'), 'File PDF lưu đúng Bucket S3 htwork-app-storage');
            console.log(`✅ [PASS] Tài liệu PDF đã lưu thành công trên AWS S3: ${dataPdf.fileUrl}\n`);

            // 3. TEST POST /upload-file (Tài liệu Word DOCX ➔ AWS S3)
            console.log('--- TEST 3: Upload Tài Liệu Word DOCX (/upload-file) ---');
            const docxBlob = new Blob([Buffer.from('PK\x03\x04Mock DOCX Content')], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
            const docxFormData = new FormData();
            docxFormData.append('file', docxBlob, 'hop_dong_dich_vu.docx');

            const resDocx = await fetch(`http://localhost:${TEST_PORT}/upload-file`, {
                method: 'POST',
                body: docxFormData
            });
            const dataDocx = await resDocx.json();
            assert.strictEqual(resDocx.status, 200, 'Upload DOCX trả về HTTP 200');
            assert(dataDocx.fileUrl.includes('amazonaws.com'), 'File DOCX BẮT BUỘC lưu trữ trên AWS S3');
            console.log(`✅ [PASS] Tài liệu DOCX đã lưu thành công trên AWS S3: ${dataDocx.fileUrl}\n`);

            // 4. TEST POST /upload-file (File nén RAR / ZIP ➔ AWS S3)
            console.log('--- TEST 4: Upload File Nén RAR (/upload-file) ---');
            const rarBlob = new Blob([Buffer.from('Rar!\x1a\x07\x00Mock RAR Content')], { type: 'application/x-rar-compressed' });
            const rarFormData = new FormData();
            rarFormData.append('file', rarBlob, 'source_code_backup.rar');

            const resRar = await fetch(`http://localhost:${TEST_PORT}/upload-file`, {
                method: 'POST',
                body: rarFormData
            });
            const dataRar = await resRar.json();
            assert.strictEqual(resRar.status, 200, 'Upload RAR trả về HTTP 200');
            assert(dataRar.fileUrl.includes('amazonaws.com'), 'File RAR BẮT BUỘC lưu trữ trên AWS S3');
            console.log(`✅ [PASS] File nén RAR đã lưu thành công trên AWS S3: ${dataRar.fileUrl}\n`);

            // 5. TEST POST /api/upload/file (Video MP4 ➔ AWS S3)
            console.log('--- TEST 5: Upload Video MP4 (/api/upload/file) ---');
            const videoBlob = new Blob([Buffer.from('ftypmp42Mock Video Content')], { type: 'video/mp4' });
            const videoFormData = new FormData();
            videoFormData.append('file', videoBlob, 'demo_san_pham.mp4');

            const resVideo = await fetch(`http://localhost:${TEST_PORT}/api/upload/file`, {
                method: 'POST',
                body: videoFormData
            });
            const dataVideo = await resVideo.json();
            assert.strictEqual(resVideo.status, 200, 'Upload Video trả về HTTP 200');
            assert(dataVideo.url.includes('amazonaws.com'), 'Video BẮT BUỘC lưu trữ trên AWS S3');
            assert.strictEqual(dataVideo.type, 'video', 'Phát hiện đúng type là video');
            console.log(`✅ [PASS] Video MP4 đã lưu thành công trên AWS S3: ${dataVideo.url}\n`);

            console.log('========================================================================');
            console.log('🎉 XÁC NHẬN TOÀN BỘ 5/5 KIỂM THỬ THÀNH CÔNG VƯỢT TRỘI:');
            console.log('   📸 1. Hình ảnh (.png, .jpg, ...)  ➔ LƯU TRỮ TRÊN CLOUDINARY 100%');
            console.log('   📄 2. Tài liệu (.pdf, .docx, ...) ➔ LƯU TRỮ TRÊN AWS S3 100%');
            console.log('   📦 3. File nén (.rar, .zip, ...)  ➔ LƯU TRỮ TRÊN AWS S3 100%');
            console.log('   🎥 4. Media nặng (.mp4, video)    ➔ LƯU TRỮ TRÊN AWS S3 100%');
            console.log('========================================================================');
            server.close(() => {
                process.exit(0);
            });
        } catch (e) {
            console.error('❌ Kiểm thử thất bại:', e);
            server.close(() => {
                process.exit(1);
            });
        }
    });
}

runUploadDestinationsTest();
