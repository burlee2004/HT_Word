require('dotenv').config();

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'burlee2004',
  api_key: process.env.CLOUDINARY_API_KEY || '765156369761244',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'FC_Xk4fgmtXzMFijGqi6YSAOoXk'
});

// Cấu hình Storage cho Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'kgs work_images', // Tên thư mục trên Cloudinary
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }] // Tự động resize
  }
});

const uploadImage = multer({ storage: storage });

module.exports = uploadImage;
