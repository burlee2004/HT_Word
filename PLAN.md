# KẾ HOẠCH TRIỂN KHAI: HỆ THỐNG TRANG CHỦ & TRANG TRẢI NGHIỆM CÔNG KHAI (PUBLIC LANDING & SUB-PAGES)

## Mục tiêu
1. Xây dựng trang chủ công khai hiện đại, chuẩn SaaS cao cấp tại `Front_end/index.html` (thay thế chuyển hướng ép buộc đăng nhập).
2. Cho phép khách vãng lai (khách chưa có tài khoản, cả Freelancer lẫn Client tiềm năng) xem trước các dự án IT đang tuyển và danh sách Freelancer nổi bật.
3. Tạo cơ chế gợi ý đăng ký/đăng nhập tự nhiên (Onboarding Modal / Call to Action mượt mà) khi người dùng bấm vào các nút hành động (Ứng tuyển, Đăng việc, Thuê chuyên gia).
4. Xây dựng thêm các trang phụ trợ công khai (`explore-jobs.html`, `explore-freelancers.html`, `how-it-works.html`) theo đúng cấu trúc thư mục dự án.

---

## Chi tiết các bước thực hiện

### Bước 1: Thiết kế Trang chủ chính (Landing Page) tại `Front_end/index.html`
- [x] Giao diện hiện đại với Tailwind CSS, font `Plus Jakarta Sans`, hỗ trợ Dark/Light mode, hiệu ứng mượt mà.
- [x] **Header Điều hướng:** Logo KGS Work, Menu (Việc làm, Chuyên gia IT, Cơ chế Escrow), nút "Đăng nhập" & "Đăng ký".
- [x] **Hero Section:** Tiêu đề ấn tượng về Sàn IT & Thanh toán Trung gian Escrow; nút CTA kép: "Khám phá dự án" (Freelancer) và "Đăng việc ngay" (Client).
- [x] **Metrics & Trust Proof:** Thống kê dự án, khối lượng giao dịch bảo vệ qua Escrow, độ tin cậy 100%.
- [x] **Live Job Showcase:** Tải tự động các dự án IT mới nhất từ API, xem preview nhanh mà không cần đăng nhập.
- [x] **Top Talents Showcase:** Trình diễn các Freelancer công nghệ tiêu biểu (Fullstack, AI, Mobile, Blockchain) với rating và kỹ năng.
- [x] **Cơ chế Escrow trực quan:** 4 bước bảo vệ giao dịch (Khởi tạo -> Ký quỹ giữ tiền an toàn -> Hoàn thành bài -> Nghiệm thu giải ngân).
- [x] **Modal Onboarding Thông minh:** Khi khách bấm "Ứng tuyển" hoặc "Đăng việc" -> Mở modal chào mừng đẹp mắt dẫn tới trang Đăng ký/Đăng nhập (không bị gián đoạn hay ép buộc khó chịu).

### Bước 2: Xây dựng Trang Khám phá Việc làm công khai (`Front_end/explore-jobs.html`)
- [x] Tích hợp bộ lọc đa năng: Tìm kiếm từ khóa, lọc theo Danh mục (Web, AI, Mobile, v.v.), khoảng ngân sách Token.
- [x] Xem chi tiết mô tả công việc, kỹ năng yêu cầu trong Modal xem nhanh.
- [x] Nút CTA "Ứng tuyển dự án này" dẫn về tạo tài khoản / đăng nhập kèm ghi nhớ hành động.

### Bước 3: Xây dựng Trang Danh sách Chuyên gia IT (`Front_end/explore-freelancers.html`)
- [x] Trưng bày hồ sơ chuyên gia công nghệ, cấp bậc, đánh giá sao, chuyên môn.
- [x] Khách hàng có thể tìm kiếm nhân sự phù hợp trước khi quyết định tạo tài khoản để thuê.
- [x] Nút CTA "Mời làm việc" hoặc "Thuê ngay" kích hoạt luồng đăng ký tài khoản Khách hàng.

### Bước 4: Xây dựng Trang Cơ chế Escrow & Về chúng tôi (`Front_end/how-it-works.html`)
- [x] Giải thích minh bạch cơ chế Smart Contract / Ký quỹ ngân hàng bảo vệ 100% dòng tiền của cả 2 bên.
- [x] Bảng so sánh rủi ro khi làm tự do ngoài thị trường vs Lợi ích khi giao dịch qua KGS Work Escrow.
- [x] Chính sách giải quyết tranh chấp minh bạch và câu hỏi thường gặp (FAQ).

### Bước 5: Cấu hình Routing & Kiểm tra đồng bộ liên kết
- [x] Kiểm tra liên kết từ trang chủ đến các trang con và dẫn sang `sharedFolder/login.html`, `sharedFolder/register.html`.
- [x] Đã cập nhật `netlify.toml` và `vercel.json` phục vụ `index.html` làm Landing Page thay vì ép chuyển sang `login.html`.
- [x] Đảm bảo tương thích trên cả Localhost lẫn khi deploy lên Internet (Render / Netlify / Vercel).
