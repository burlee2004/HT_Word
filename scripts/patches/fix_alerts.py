import os

def fix_file(path, old, new):
    if not os.path.exists(path): return
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    content = content.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

# user/direct-chat.html
fix_file(r'd:\Project_internship\New_code\code\Front_end\user\direct-chat.html', 
    '${formatTokenHTML(title}" (${budget, false)})', 
    '${title}" (${formatTokenHTML(budget, false)})')

# freelancer/direct-chat.html
fix_file(r'd:\Project_internship\New_code\code\Front_end\freelancer\direct-chat.html', 
    '${formatTokenHTML(title}" (${budget, false)})', 
    '${title}" (${formatTokenHTML(budget, false)})')

# freelancer/home.html
fix_file(r'd:\Project_internship\New_code\code\Front_end\freelancer\home.html', 
    '${formatTokenHTML(title}" (${budget, false)})', 
    '${title}" (${formatTokenHTML(budget, false)})')

# user/my-jobs.html
# alert(`LỖI: Tổng trị giá các giai đoạn (${formatTokenHTML(totalAmount, false)}) phải bằng ĐÚNG VỚI giá trị đã chốt của dự án (${formatTokenHTML(jobBudget)})!`);
fix_file(r'd:\Project_internship\New_code\code\Front_end\user\my-jobs.html', 
    '(${formatTokenHTML(jobBudget)})', 
    '(${formatTokenHTML(jobBudget, false)})')

print("Fixed alerts")
