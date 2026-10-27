with open('Front_end/user/review-work.html', 'r', encoding='utf-8') as f: content = f.read()
for i, line in enumerate(content.split('\n')):
    if 'approve' in line or 'cancel' in line.lower() or 'Duyệt' in line or 'Hủy' in line:
        print(f"{i}: {line.strip()}")
