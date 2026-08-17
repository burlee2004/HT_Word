require('dotenv').config();

// Fix lỗi user copy dính chữ "CLOUDINARY_URL=" hoặc ngoặc "< >" TRƯỚC KHI require Cloudinary
let cloudinaryUrl = process.env.CLOUDINARY_URL || '';
if (cloudinaryUrl) {
  if (cloudinaryUrl.startsWith('CLOUDINARY_URL=')) {
    cloudinaryUrl = cloudinaryUrl.replace('CLOUDINARY_URL=', '');
  }
  cloudinaryUrl = cloudinaryUrl.replace(/[<>]/g, '').trim();
  process.env.CLOUDINARY_URL = cloudinaryUrl;
}

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

// Cấu hình SDK
if (!process.env.CLOUDINARY_URL) {
  cloudinary.config({
    cloud_name: (process.env.CLOUDINARY_CLOUD_NAME || '').trim(),
    api_key: (process.env.CLOUDINARY_API_KEY || '').trim(),
    api_secret: (process.env.CLOUDINARY_API_SECRET || '').trim()
  });
}

// Cấu hình Storage cho Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'htwork_images', // Tên thư mục trên Cloudinary
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }] // Tự động resize
  }
});

const uploadImage = multer({ storage: storage });

module.exports = uploadImage;
