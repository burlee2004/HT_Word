import sys, re
path = r'd:\Project_internship\New_code\code\Back_end\routes\authRoutes.js'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()
s = 0
e = 0
for i, l in enumerate(lines):
    if "router.post('/upload-image'" in l:
        s = i
    if "router.post('/api/upload/base64'" in l:
        e = i

# Truncate content and replace
with open(path, 'w', encoding='utf-8') as f:
    f.writelines(lines[:s])
    f.write('''router.post('/upload-image', (req, res) => {
    uploadLocal.single('image')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'Thiếu file ảnh' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        return res.status(200).json({
            message: 'Upload ảnh thành công!',
            imageUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/upload-file', (req, res) => {
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'Thiếu file tải lên' });
        }
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        return res.status(200).json({
            message: 'Upload file thành công!',
            fileUrl: localUrl,
            url: localUrl
        });
    });
});

router.post('/api/upload/image', (req, res) => {
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload ảnh: ' + localErr.message });
        }
        if (!req.file) return res.status(400).json({ error: 'Không thể upload ảnh' });
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        res.status(200).json({ url: localUrl, imageUrl: localUrl, type: 'image' });
    });
});

router.post('/api/upload/file', (req, res) => {
    uploadLocal.single('file')(req, res, function (localErr) {
        if (localErr) {
            if (localErr.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File đã vượt quá 50MB' });
            }
            return res.status(400).json({ error: 'Không thể upload file: ' + localErr.message });
        }
        if (!req.file) return res.status(400).json({ error: 'Thiếu file tải lên' });
        const host = req.get('host') || 'localhost:5000';
        const protocol = req.protocol || 'http';
        const localUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
        let type = 'document';
        if (req.file.mimetype && req.file.mimetype.startsWith('video/')) type = 'video';
        else if (req.file.mimetype && req.file.mimetype.startsWith('audio/')) type = 'audio';
        return res.status(200).json({ url: localUrl, fileUrl: localUrl, type: type });
    });
});

''')
    f.writelines(lines[e:])
