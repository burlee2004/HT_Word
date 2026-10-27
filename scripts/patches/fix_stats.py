import os
import re

dir_path = r'd:\Project_internship\New_code\code\Front_end\Admin'

files_to_fix_all = ['audit logs.html', 'audit-logs.html', 'chat rules.html', 'chat-rules.html']

for f in files_to_fix_all:
    path = os.path.join(dir_path, f)
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as file:
            content = file.read()
        content = re.sub(r'\.innerHTML\s*=\s*formatTokenHTML\((.+?)\);', r'.innerText = (\1).toLocaleString();', content)
        with open(path, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Fixed {f}")

path_pm = os.path.join(dir_path, 'projects-monitor.html')
if os.path.exists(path_pm):
    with open(path_pm, 'r', encoding='utf-8') as file:
        content = file.read()
    
    content = content.replace("document.getElementById('stat_total').innerHTML = formatTokenHTML(total);", "document.getElementById('stat_total').innerText = total.toLocaleString();")
    content = content.replace("document.getElementById('stat_disputed').innerHTML = formatTokenHTML(disputed);", "document.getElementById('stat_disputed').innerText = disputed.toLocaleString();")
    content = content.replace("document.getElementById('stat_active').innerHTML = formatTokenHTML(active);", "document.getElementById('stat_active').innerText = active.toLocaleString();")
    content = content.replace("document.getElementById('stat_completed').innerHTML = formatTokenHTML(completed);", "document.getElementById('stat_completed').innerText = completed.toLocaleString();")
    
    with open(path_pm, 'w', encoding='utf-8') as file:
        file.write(content)
    print("Fixed projects-monitor.html")

