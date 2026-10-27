import sys, re
path = r'd:\Project_internship\New_code\code\Back_end\routes\authRoutes.js'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

log_func = '''
// LOGGER UPLOAD YÊU CẦU
function writeUploadLog(req, type, status, detail) {
    try {
        const fs = require('fs');
        const path = require('path');
        const logFile = path.join(__dirname, '../upload_debug.log');
        const time = new Date().toISOString();
        const ip = req.ip || req.connection.remoteAddress;
        let fileInfo = 'No file info';
        if (req.file) {
            fileInfo = `Name: ${req.file.originalname}, Size: ${req.file.size} bytes, Mime: ${req.file.mimetype}`;
        }
        const logLine = `[${time}] IP: ${ip} | Type: ${type} | Status: ${status} | Detail: ${detail} | File: ${fileInfo}\\n`;
        fs.appendFileSync(logFile, logLine);
        console.log(logLine.trim());
    } catch(e) {}
}
'''

new_routes = '''
router.post('/upload-image', (req, res) => {
    writeUploadLog(req, '/upload-image', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('image')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/upload-image', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/upload-image', 'ERROR', 'Thiếu file ảnh');
            return res.status(400).json({ error: 'Thiếu file ảnh' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/upload-image', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({
            message: 'Upload ảnh thành công!',
            imageUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/upload-file', (req, res) => {
    writeUploadLog(req, '/upload-file', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/upload-file', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/upload-file', 'ERROR', 'Thiếu file tải lên');
            return res.status(400).json({ error: 'Thiếu file tải lên' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/upload-file', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({
            message: 'Upload file thành công!',
            fileUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/api/upload/image', (req, res) => {
    writeUploadLog(req, '/api/upload/image', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/api/upload/image', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/api/upload/image', 'ERROR', 'Không thể upload ảnh (thiếu file)');
            return res.status(400).json({ error: 'Không thể upload ảnh' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        writeUploadLog(req, '/api/upload/image', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        res.status(200).json({ url: localUrl, imageUrl: localUrl, type: 'image' });
    });
});

router.post('/api/upload/file', (req, res) => {
    writeUploadLog(req, '/api/upload/file', 'START', 'Bắt đầu nhận request');
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            writeUploadLog(req, '/api/upload/file', 'ERROR', localErr.message);
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) {
            writeUploadLog(req, '/api/upload/file', 'ERROR', 'Thiếu file tải lên');
            return res.status(400).json({ error: 'Thiếu file tải lên' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        let type = 'document';
        if (req.file.mimetype && req.file.mimetype.startsWith('video/')) type = 'video';
        else if (req.file.mimetype && req.file.mimetype.startsWith('audio/')) type = 'audio';
        writeUploadLog(req, '/api/upload/file', 'SUCCESS', `Đã lưu file: ${localUrl}`);
        return res.status(200).json({ url: localUrl, fileUrl: localUrl, type: type });
    });
});
'''

# Find insertion point
idx = content.find("router.post('/upload-image'")
if idx != -1:
    content = content[:idx] + log_func + '\\n' + new_routes + '\\n' + content[content.find("router.post('/api/upload/base64'", idx):]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Injected logger successfully.")
