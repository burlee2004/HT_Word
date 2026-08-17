const { S3Client } = require('@aws-sdk/client-s3');
const multer = require('multer');
const multerS3 = require('multer-s3');
require('dotenv').config();

// Cấu hình S3 Client (AWS SDK v3)
const s3 = new S3Client({
  region: (process.env.AWS_REGION || '').trim(),
  credentials: {
    accessKeyId: (process.env.AWS_ACCESS_KEY_ID || '').trim(),
    secretAccessKey: (process.env.AWS_SECRET_ACCESS_KEY || '').trim()
  }
});

// Cấu hình Storage cho Multer
const uploadFile = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.AWS_S3_BUCKET_NAME || 'my-default-bucket',
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname });
    },
    key: function (req, file, cb) {
      // Đặt tên file duy nhất tránh trùng lặp
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, 'htwork_files/' + uniqueSuffix + '-' + file.originalname);
    }
  }),
  limits: { fileSize: 5000 * 1024 * 1024 } // Giới hạn file 5000MB (5GB)
});

module.exports = uploadFile;
