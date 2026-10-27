import os
import re

path = r'd:\Project_internship\New_code\code\Front_end\Admin\withdrawals.html'
if os.path.exists(path):
    with open(path, 'r', encoding='utf-8') as file:
        content = file.read()
    content = re.sub(r'\.innerHTML\s*=\s*formatTokenHTML\((.+?)\);', r'.innerText = (\1).toLocaleString();', content)
    with open(path, 'w', encoding='utf-8') as file:
        file.write(content)
    print("Fixed withdrawals.html")
