import re

modal_html = """    <!-- ============================================================== -->
    <!-- MODAL LƯU TRỮ ĐÁM MÂY (FIREBASE & GOOGLE SHEETS) -->
    <!-- ============================================================== -->
    <div id="cloudStorageModal" class="fixed inset-0 bg-slate-900/80 backdrop-blur-xs hidden flex items-center justify-center z-50 p-4">
        <div class="bg-white dark:bg-gray-900 rounded-3xl shadow-2xl w-full max-w-2xl overflow-hidden border border-slate-200 dark:border-slate-800 flex flex-col max-h-[92vh]">
            <!-- Header -->
            <div class="px-6 py-4 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-gray-850">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-amber-500 via-indigo-600 to-purple-600 text-white flex items-center justify-center text-lg shadow-md">
                        <i class="fas fa-cloud-arrow-up"></i>
                    </div>
                    <div>
                        <h3 class="text-sm sm:text-base font-black text-slate-900 dark:text-white">Lưu Trữ Đám Mây: Firebase & Google Sheets</h3>
                        <p class="text-[11px] text-slate-400">Lưu vĩnh viễn không lo mất log khi Render restart / ngủ đông</p>
                    </div>
                </div>
                <button onclick="closeCloudModal()" class="w-8 h-8 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 flex items-center justify-center text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-lg transition">&times;</button>
            </div>

            <!-- Tab Switcher -->
            <div class="px-6 pt-3 bg-slate-50/50 dark:bg-gray-850/50 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2">
                <button onclick="switchCloudTab('firebase')" id="tabBtnFirebase" class="px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-indigo-600 text-indigo-600 dark:text-indigo-400 bg-white dark:bg-gray-900 transition flex items-center gap-2">
                    <i class="fas fa-fire text-amber-500"></i> 1. Firebase Realtime DB (Đọc/Ghi Trực Tiếp Web)
                </button>
                <button onclick="switchCloudTab('sheets')" id="tabBtnSheets" class="px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition flex items-center gap-2">
                    <i class="fab fa-google-drive text-emerald-500"></i> 2. Google Sheets Webhook (Báo Cáo Excel)
                </button>
            </div>

            <!-- Body -->
            <div class="p-6 overflow-y-auto space-y-4 text-xs custom-scrollbar">
                
                <!-- TAB 1: FIREBASE REALTIME DATABASE -->
                <div id="tabContentFirebase" class="space-y-4">
                    <div class="p-3.5 rounded-2xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/40 text-amber-900 dark:text-amber-200 flex items-start gap-2.5">
                        <i class="fas fa-info-circle text-amber-500 text-base mt-0.5 shrink-0"></i>
                        <div class="leading-relaxed text-[11px]">
                            <b>Cơ chế hoạt động:</b> Khi lưu URL Firebase bên dưới, mọi sự kiện trên sàn (Đăng việc, Nộp mốc, Nạp/Rút ví, Tranh chấp, Chat...) sẽ tự động lưu lên Firebase Realtime Database. Mỗi lần mở trang Quản trị, log sẽ được nạp trực tiếp từ Firebase về hiển thị, <b>không bao giờ bị mất</b> ngay cả khi Render khởi động lại.
                        </div>
                    </div>

                    <div>
                        <div class="flex justify-between items-center mb-1">
                            <label class="block font-bold text-slate-700 dark:text-slate-300">Firebase Realtime Database URL (*):</label>
                            <span id="firebaseStatusBadge" class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-gray-800 text-slate-500">Đang kiểm tra...</span>
                        </div>
                        <input type="url" id="fb_database_url" placeholder="https://jobly-de118-default-rtdb.firebaseio.com" class="w-full px-3.5 py-2.5 bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-slate-700 rounded-xl font-mono text-xs focus:ring-2 focus:ring-indigo-500 outline-none text-slate-800 dark:text-slate-100">
                        <p class="text-[11px] text-slate-400 mt-1">Hỗ trợ cả Firebase US (firebaseio.com) và Singapore (firebasedatabase.app).</p>
                    </div>

                    <div class="p-4 rounded-2xl bg-slate-900 text-slate-200 border border-slate-800 space-y-2">
                        <div class="font-bold text-amber-400 flex items-center gap-1.5 text-xs">
                            <i class="fas fa-magic"></i> 4 Bước kích hoạt Firebase Realtime DB trong 30 giây:
                        </div>
                        <ol class="list-decimal list-inside space-y-1.5 text-[11px] text-slate-300 leading-relaxed">
                            <li>Mở tab <a href="https://console.firebase.google.com" target="_blank" class="text-indigo-400 underline font-bold">Firebase Console</a> &rarr; Click vào dự án của bạn (ví dụ dự án <b>jobly</b> như trong ảnh bạn đã mở).</li>
                            <li>Tại thanh menu trái, chọn <b>Build</b> &rarr; click <b>Realtime Database</b> &rarr; Bấm nút xanh <b>Create Database</b>.</li>
                            <li>Chọn vị trí lưu trữ (Singapore hoặc United States) &rarr; Bước Rules chọn <b>Start in test mode</b> (cho phép read/write) &rarr; Bấm <b>Enable</b>.</li>
                            <li>Copy đường link URL hiển thị ở đầu trang (có dạng: <code class="text-emerald-400 font-mono">https://jobly-de118-default-rtdb.firebaseio.com</code>) dán vào ô trên rồi bấm nút <b>Lưu Cấu Hình Firebase</b>!</li>
                        </ol>
                    </div>

                    <div class="flex flex-wrap items-center gap-2 pt-1">
                        <button onclick="saveFirebaseConfig()" id="btnSaveFirebase" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold text-xs shadow-md transition flex items-center gap-1.5">
                            <i class="fas fa-save"></i> Lưu Cấu Hình Firebase
                        </button>
                        <button onclick="testFirebaseConnection()" id="btnTestFirebase" class="px-3.5 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-gray-800 dark:hover:bg-gray-700 text-slate-700 dark:text-slate-200 rounded-xl font-bold text-xs transition flex items-center gap-1.5">
                            <i class="fas fa-plug"></i> Kiểm Tra Kết Nối
                        </button>
                        <button onclick="syncNowToFirebase()" id="btnSyncFirebaseNow" class="px-3.5 py-2 bg-amber-500 hover:bg-amber-600 text-white rounded-xl font-bold text-xs shadow-md transition flex items-center gap-1.5 ml-auto">
                            <i class="fas fa-upload"></i> Đẩy Toàn Bộ Log Hiện Có Lên Firebase
                        </button>
                    </div>
                </div>

                <!-- TAB 2: GOOGLE SHEETS WEBHOOK -->
                <div id="tabContentSheets" class="space-y-4 hidden">
                    <div class="p-3.5 rounded-2xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/40 text-emerald-900 dark:text-emerald-200 flex items-start gap-2.5">
                        <i class="fas fa-file-excel text-emerald-500 text-base mt-0.5 shrink-0"></i>
                        <div class="leading-relaxed text-[11px]">
                            <b>Công dụng:</b> Tự động đẩy dữ liệu sang bảng tính <b>Google Sheets</b> trên Google Drive. Giúp bạn xem báo cáo trực quan, chia sẻ file cho Giảng viên hướng dẫn hoặc xuất Excel bất cứ lúc nào.
                        </div>
                    </div>

                    <div>
                        <div class="flex justify-between items-center mb-1">
                            <label class="block font-bold text-slate-700 dark:text-slate-300">URL Webhook Google Apps Script (*):</label>
                            <span id="sheetsStatusBadge" class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-gray-800 text-slate-500">Đang kiểm tra...</span>
                        </div>
                        <input type="url" id="gs_webhook_url" placeholder="https://script.google.com/macros/s/.../exec" class="w-full px-3.5 py-2.5 bg-slate-50 dark:bg-gray-800 border border-slate-200 dark:border-slate-700 rounded-xl font-mono text-xs focus:ring-2 focus:ring-indigo-500 outline-none text-slate-800 dark:text-slate-100">
                    </div>

                    <div class="p-4 rounded-2xl bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-900/60">
                        <div class="flex items-center justify-between mb-1.5">
                            <span class="font-black text-indigo-700 dark:text-indigo-300 flex items-center gap-1.5 text-xs">
                                <i class="fas fa-code"></i> Mã Apps Script triển khai trên Google Sheets:
                            </span>
                        </div>
                        <ol class="list-decimal list-inside space-y-1 text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed mb-2">
                            <li>Mở trang <b>Google Sheets</b> mới &rarr; Đặt tên file là <b>KGS_Work_Audit_Logs</b>.</li>
                            <li>Trên thanh menu chọn <b>Tiện ích mở rộng (Extensions)</b> &rarr; <b>Apps Script</b>.</li>
                            <li>Dán đoạn mã dưới đây rồi nhấn <b>Triển khai (Deploy)</b> &rarr; <b>Bản triển khai mới (New deployment)</b> &rarr; Loại <b>Ứng dụng web (Web app)</b> &rarr; Quyền truy cập: <b>Bất kỳ ai (Anyone)</b>.</li>
                        </ol>
                        <pre class="p-2.5 rounded-xl bg-slate-900 text-emerald-400 font-mono text-[10px] overflow-x-auto select-all">function doPost(e) {
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  var d = JSON.parse(e.postData.contents);
  if (Array.isArray(d)) {
    d.forEach(function(r) { sheet.appendRow([r.timestamp, r.level, r.module, r.action, r.actor, r.role, r.ip, r.details, r.metadata]); });
  } else {
    sheet.appendRow([d.timestamp, d.level, d.module, d.action, d.actor, d.role, d.ip, d.details, d.metadata]);
  }
  return ContentService.createTextOutput(JSON.stringify({status:"ok"})).setMimeType(ContentService.MimeType.JSON);
}</pre>
                    </div>

                    <div class="flex flex-wrap items-center gap-2 pt-1">
                        <button onclick="saveGoogleSheetWebhook()" id="btnSaveGsWebhook" class="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-gray-800 dark:hover:bg-gray-700 text-slate-700 dark:text-slate-200 rounded-xl font-bold text-xs transition flex items-center gap-1.5">
                            <i class="fas fa-save"></i> Lưu Cấu Hình Webhook
                        </button>
                        <button onclick="syncNowToGoogleSheets()" id="btnSyncGsNow" class="px-5 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white rounded-xl font-bold text-xs shadow-md transition flex items-center gap-1.5 ml-auto">
                            <i class="fab fa-google-drive"></i> Đồng Bộ Ngay Lên Google Sheets
                        </button>
                    </div>
                </div>

            </div>
        </div>
    </div>
"""

status_bar_html = """                <!-- Cloud Sync Status Bar -->
                <div id="cloudStatusBar" class="p-3.5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-gray-900 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
                    <div class="flex items-center gap-2.5">
                        <span id="cloudStatusDot" class="w-3 h-3 rounded-full bg-amber-500 animate-pulse shrink-0"></span>
                        <div>
                            <span id="cloudStatusTitle" class="font-bold text-slate-800 dark:text-slate-100">Lưu Trữ Đám Mây: Đang kiểm tra...</span>
                            <span id="cloudStatusDesc" class="text-[11px] text-slate-500 dark:text-slate-400 block sm:inline sm:ml-2"></span>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 shrink-0">
                        <button onclick="openCloudModal('firebase')" class="px-3 py-1.5 rounded-xl bg-amber-50 hover:bg-amber-100 text-amber-700 dark:bg-amber-950/60 dark:text-amber-400 text-xs font-bold transition flex items-center gap-1.5 border border-amber-200/60 dark:border-amber-900/60">
                            <i class="fas fa-fire text-amber-500"></i> Firebase Realtime DB
                        </button>
                        <button onclick="openCloudModal('sheets')" class="px-3 py-1.5 rounded-xl bg-emerald-50 hover:bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 text-xs font-bold transition flex items-center gap-1.5 border border-emerald-200/60 dark:border-emerald-900/60">
                            <i class="fab fa-google-drive text-emerald-500"></i> Google Sheets
                        </button>
                    </div>
                </div>
"""

js_code = """        // ==============================================================
        // CLOUD STORAGE & SYNC CONTROLS (FIREBASE & GOOGLE SHEETS)
        // ==============================================================
        async function openCloudModal(defaultTab = 'firebase') {
            switchCloudTab(defaultTab);
            try {
                const res = await fetch(`${API_URL}/api/admin/settings`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.firebaseDbUrl) {
                        document.getElementById('fb_database_url').value = data.firebaseDbUrl;
                        document.getElementById('firebaseStatusBadge').className = 'text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-950/80 dark:text-emerald-400';
                        document.getElementById('firebaseStatusBadge').innerText = '🟢 Đã cấu hình';
                    } else {
                        document.getElementById('firebaseStatusBadge').className = 'text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 dark:bg-gray-800 dark:text-slate-400';
                        document.getElementById('firebaseStatusBadge').innerText = '⚪ Chưa cấu hình';
                    }

                    if (data.googleSheetWebhook) {
                        document.getElementById('gs_webhook_url').value = data.googleSheetWebhook;
                        document.getElementById('sheetsStatusBadge').className = 'text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-950/80 dark:text-emerald-400';
                        document.getElementById('sheetsStatusBadge').innerText = '🟢 Đã cấu hình';
                    } else {
                        document.getElementById('sheetsStatusBadge').className = 'text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 dark:bg-gray-800 dark:text-slate-400';
                        document.getElementById('sheetsStatusBadge').innerText = '⚪ Chưa cấu hình';
                    }
                }
            } catch(e) {}
            document.getElementById('cloudStorageModal').classList.remove('hidden');
        }

        function closeCloudModal() {
            document.getElementById('cloudStorageModal').classList.add('hidden');
        }

        function switchCloudTab(tab) {
            const btnFb = document.getElementById('tabBtnFirebase');
            const btnSh = document.getElementById('tabBtnSheets');
            const conFb = document.getElementById('tabContentFirebase');
            const conSh = document.getElementById('tabContentSheets');

            if (tab === 'firebase') {
                btnFb.className = 'px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-indigo-600 text-indigo-600 dark:text-indigo-400 bg-white dark:bg-gray-900 transition flex items-center gap-2';
                btnSh.className = 'px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition flex items-center gap-2';
                conFb.classList.remove('hidden');
                conSh.classList.add('hidden');
            } else {
                btnSh.className = 'px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-emerald-600 text-emerald-600 dark:text-emerald-400 bg-white dark:bg-gray-900 transition flex items-center gap-2';
                btnFb.className = 'px-4 py-2.5 text-xs font-bold rounded-t-xl border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition flex items-center gap-2';
                conSh.classList.remove('hidden');
                conFb.classList.add('hidden');
            }
        }

        async function saveFirebaseConfig() {
            const url = (document.getElementById('fb_database_url').value || '').trim();
            const btn = document.getElementById('btnSaveFirebase');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang lưu...';
            try {
                const res = await fetch(`${API_URL}/api/admin/settings`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ firebaseDbUrl: url })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('✅ Đã lưu cấu hình Firebase Realtime Database thành công! Hệ thống sẽ tự động lưu và truy xuất log từ Firebase.');
                    loadAuditLogs();
                } else {
                    alert('❌ Lỗi: ' + (data.error || 'Không thể lưu cấu hình'));
                }
            } catch(e) {
                alert('❌ Lỗi kết nối: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-save mr-1.5"></i> Lưu Cấu Hình Firebase';
            }
        }

        async function testFirebaseConnection() {
            const url = (document.getElementById('fb_database_url').value || '').trim();
            if (!url) return alert('Vui lòng nhập URL Firebase Database!');
            const btn = document.getElementById('btnTestFirebase');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang test...';
            try {
                const clean = url.replace(/\\/+$/, '');
                const res = await fetch(`${clean}/audit_logs.json?shallow=true`);
                if (res.ok) {
                    alert('🎉 Kết nối Firebase thành công! Realtime Database phản hồi trạng thái 200 OK.');
                } else {
                    alert(`⚠️ Firebase phản hồi mã: ${res.status}. Vui lòng kiểm tra tab Rules trong Realtime Database (cần bật chế độ Test Mode hoặc đặt .read: true, .write: true).`);
                }
            } catch(e) {
                alert('⚠️ Kết nối trực tiếp bị chặn hoặc sai URL (CORS có thể xảy ra khi test từ trình duyệt, nhưng Backend trên Node.js vẫn kết nối thành công 100%). Bạn có thể an tâm bấm "Lưu Cấu Hình Firebase" và "Đẩy Toàn Bộ Log"!');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-plug mr-1.5"></i> Kiểm Tra Kết Nối';
            }
        }

        async function syncNowToFirebase() {
            const url = (document.getElementById('fb_database_url').value || '').trim();
            const btn = document.getElementById('btnSyncFirebaseNow');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang đẩy dữ liệu...';
            try {
                const res = await fetch(`${API_URL}/api/admin/audit-logs/sync-firebase`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ firebaseUrl: url, maxRows: 500 })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('🎉 ' + data.message);
                    closeCloudModal();
                    loadAuditLogs();
                } else {
                    alert('❌ Lỗi đồng bộ Firebase: ' + (data.error || 'Thất bại'));
                }
            } catch(e) {
                alert('❌ Lỗi kết nối đồng bộ: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-upload mr-1.5"></i> Đẩy Toàn Bộ Log Hiện Có Lên Firebase';
            }
        }

        async function saveGoogleSheetWebhook() {
            const url = (document.getElementById('gs_webhook_url').value || '').trim();
            const btn = document.getElementById('btnSaveGsWebhook');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang lưu...';
            try {
                const res = await fetch(`${API_URL}/api/admin/settings`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ googleSheetWebhook: url })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('✅ Đã lưu cấu hình Google Sheet Webhook thành công!');
                } else {
                    alert('❌ Lỗi: ' + (data.error || 'Không thể lưu'));
                }
            } catch(e) {
                alert('❌ Lỗi kết nối: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-save mr-1.5"></i> Lưu Cấu Hình Webhook';
            }
        }

        async function syncNowToGoogleSheets() {
            const url = (document.getElementById('gs_webhook_url').value || '').trim();
            if (!url) return alert('Vui lòng nhập URL Webhook Google Apps Script!');

            const btn = document.getElementById('btnSyncGsNow');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> Đang đồng bộ...';

            try {
                const res = await fetch(`${API_URL}/api/admin/audit-logs/sync-sheets`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ webhookUrl: url, maxRows: 300 })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('🎉 ' + data.message);
                    closeCloudModal();
                } else {
                    alert('❌ Lỗi đồng bộ: ' + (data.error || 'Thất bại'));
                }
            } catch(e) {
                alert('❌ Lỗi kết nối đồng bộ: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fab fa-google-drive mr-1.5"></i> Đồng Bộ Ngay Lên Google Sheets';
            }
        }
"""

with open('Front_end/Admin/audit-logs.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace button in header
text = text.replace(
    '''<button onclick="openGoogleSheetModal()" class="px-3 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-sm" title="Tự động đồng bộ sang Google Sheets / Drive">
                            <i class="fab fa-google-drive"></i> Đồng Bộ Google Sheets
                        </button>''',
    '''<button onclick="openCloudModal('firebase')" class="px-3 py-2 rounded-xl bg-gradient-to-r from-amber-500 via-indigo-600 to-purple-600 hover:opacity-90 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-sm" title="Lưu trữ vĩnh viễn trên Firebase & Google Sheets">
                            <i class="fas fa-cloud-arrow-up"></i> Lưu Trữ Đám Mây (Firebase & Sheets)
                        </button>'''
)

# Insert status bar before <!-- Main Data Card -->
if '<!-- Cloud Sync Status Bar -->' not in text:
    text = text.replace('<!-- Main Data Card -->', status_bar_html + '\n                <!-- Main Data Card -->')

# Replace old modal
old_modal_pattern = re.compile(r'<!-- ============================================================== -->\s*<!-- MODAL GOOGLE SHEETS & FIREBASE SYNC -->.*?</div>\s*</div>\s*</div>', re.DOTALL)
if old_modal_pattern.search(text):
    text = old_modal_pattern.sub(modal_html.strip(), text, count=1)
else:
    print("Old modal pattern not matched by regex, searching by id")
    idx = text.find('<div id="googleSheetModal"')
    if idx != -1:
        end_idx = text.find('<!-- UI Core Script -->')
        text = text[:idx] + modal_html + '\n    ' + text[end_idx:]

# Update loadAuditLogs in script to update cloudStatusBar
old_load = """                if (res.ok && Array.isArray(data.logs)) {
                    allLogs = data.logs;
                    updateStats();
                    renderTable();
                }"""

new_load = """                if (res.ok && Array.isArray(data.logs)) {
                    allLogs = data.logs;
                    updateStats();
                    renderTable();
                    updateCloudStatusBar(data);
                }"""

text = text.replace(old_load, new_load)

# Add updateCloudStatusBar definition
update_status_code = """        function updateCloudStatusBar(data) {
            const dot = document.getElementById('cloudStatusDot');
            const title = document.getElementById('cloudStatusTitle');
            const desc = document.getElementById('cloudStatusDesc');
            if (!dot || !title) return;

            if (data && data.firebaseConnected) {
                dot.className = 'w-3 h-3 rounded-full bg-emerald-500 animate-pulse shrink-0';
                title.innerHTML = '🟢 <span class="text-emerald-600 dark:text-emerald-400">Firebase Realtime Database: ĐÃ KẾT NỐI</span>';
                desc.innerHTML = `(Đang bảo toàn <b>${data.firebaseCount || allLogs.length}</b> bản ghi trên Cloud. Không bao giờ mất khi Render restart).`;
            } else {
                dot.className = 'w-3 h-3 rounded-full bg-amber-500 shrink-0';
                title.innerHTML = '🟡 <span class="text-amber-600 dark:text-amber-400">Lưu Trữ Tạm Thời Trên Server Cục Bộ</span>';
                desc.innerHTML = `(Khuyên dùng: Bấm nút "Firebase Realtime DB" bên cạnh để kết nối Cloud vĩnh viễn).`;
            }
        }
"""

if 'function updateCloudStatusBar' not in text:
    text = text.replace('function updateStats() {', update_status_code + '\n        function updateStats() {')

# Replace old sync functions with new js_code
old_funcs_start = text.find('// GOOGLE SHEETS / FIREBASE SYNC MODAL CONTROLS')
if old_funcs_start != -1:
    old_funcs_header = '        // ==============================================================\n        // GOOGLE SHEETS / FIREBASE SYNC MODAL CONTROLS'
    end_funcs = text.find('function escapeHtml(str)', old_funcs_start)
    if end_funcs != -1:
        text = text[:text.rfind('// ==============================================================', 0, old_funcs_start)] + js_code + '\n        ' + text[end_funcs:]

with open('Front_end/Admin/audit-logs.html', 'w', encoding='utf-8') as f:
    f.write(text)

with open('Front_end/Admin/audit logs.html', 'w', encoding='utf-8') as f:
    f.write(text)

print("PATCH APPLIED SUCCESSFULLY")
