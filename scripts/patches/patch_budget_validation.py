import re

filepath = r'd:\Project_internship\New_code\code\Front_end\user\post-job.html'

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Inject Modal HTML before </body>
modal_html = """
    <!-- Budget Warning Modal -->
    <div id="budgetWarningModal" class="hidden fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
        <div class="bg-white dark:bg-gray-800 rounded-3xl p-8 max-w-md w-full shadow-2xl text-center border-t-8 border-red-500">
            <div class="w-20 h-20 bg-red-100 dark:bg-red-900/50 rounded-full flex items-center justify-center mx-auto mb-6">
                <i class="fas fa-exclamation-triangle text-4xl text-red-500"></i>
            </div>
            <h2 class="text-2xl font-black text-gray-900 dark:text-white mb-2">Vượt Quá Ngân Sách!</h2>
            <p class="text-gray-600 dark:text-gray-300 mb-6">
                Số dư khả dụng của bạn hiện tại là <strong id="warningAvailableBalance" class="text-indigo-600 dark:text-indigo-400">0 Token</strong>.<br>
                Bạn không đủ số dư để ký quỹ <strong id="warningRequiredBudget" class="text-red-500">0 Token</strong> cho dự án này.
            </p>
            <div class="flex flex-col space-y-3">
                <button onclick="document.getElementById('budgetWarningModal').classList.add('hidden'); document.getElementById('budget').focus();" class="w-full bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-white font-bold py-3 rounded-xl transition">
                    <i class="fas fa-edit mr-2"></i>Sửa lại giá
                </button>
                <a href="wallet.html" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-xl transition shadow-lg shadow-indigo-500/30">
                    <i class="fas fa-wallet mr-2"></i>Tới trang Nạp Tiền
                </a>
                <a href="dashboard.html" class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 text-sm font-semibold mt-2 underline">
                    Quay về Trang chủ
                </a>
            </div>
        </div>
    </div>
"""
if 'budgetWarningModal' not in content:
    content = content.replace('</body>', modal_html + '\n</body>')

# 2. Modify nextStep
# First, change `function nextStep` to `async function nextStep`
content = content.replace('function nextStep(direction) {', 'async function nextStep(direction) {')

# Second, inject the validation logic
validation_logic = """
                    if (!budget || isNaN(budget) || parseInt(budget) < 10000) {
                        alert('Vui lòng nhập ngân sách hợp lệ (tối thiểu 10,000 Token)!');
                        document.getElementById('budget')?.focus();
                        return;
                    }

                    // --- CHECK BALANCE LÊN BACKEND TRƯỚC KHI TỚI BƯỚC 3 ---
                    try {
                        const nextBtn = document.getElementById('nextBtn');
                        const oldHtml = nextBtn.innerHTML;
                        nextBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> Đang kiểm tra...';
                        nextBtn.disabled = true;

                        const res = await fetch(`${API_URL}/api/wallet/${currentUser.id}`);
                        const data = await res.json();
                        
                        nextBtn.innerHTML = oldHtml;
                        nextBtn.disabled = false;

                        if (res.ok && data.success) {
                            const availableBalance = data.wallet.balance || 0;
                            if (budget > availableBalance) {
                                document.getElementById('warningAvailableBalance').textContent = parseInt(availableBalance).toLocaleString('vi-VN').replace(/,/g, '.') + ' Token';
                                document.getElementById('warningRequiredBudget').textContent = parseInt(budget).toLocaleString('vi-VN').replace(/,/g, '.') + ' Token';
                                document.getElementById('budgetWarningModal').classList.remove('hidden');
                                return; // BLOCK CHUYỂN BƯỚC
                            }
                        }
                    } catch (e) {
                        console.error('Lỗi check số dư', e);
                        document.getElementById('nextBtn').disabled = false;
                    }
                    // ----------------------------------------------------
"""

# We need to replace the old if (!budget ...) block with the new validation_logic
content = re.sub(
    r'if \(!budget \|\| isNaN\(budget\) \|\| parseInt\(budget\) < 10000\) \{[\s\S]*?return;\s*\}',
    validation_logic,
    content,
    count=1
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print("Patched validation in post-job")
