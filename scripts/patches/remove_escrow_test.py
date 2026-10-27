import re

filepath = r'd:\Project_internship\New_code\code\Front_end\Admin\admin-ui.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace <a href="escrow-security-test.html"... </a>
content = re.sub(r'<a href="escrow-security-test\.html"[\s\S]*?</a>', '', content)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
