import os
import re

directory = r'd:\Project_internship\New_code\code\Front_end'

for root, dirs, files in os.walk(directory):
    for f in files:
        if f.endswith('.html') or f.endswith('.js'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            original = content
            
            # fix missing brace for jobId in home.html / direct-chat.html
            content = content.replace('#${jobId\\n', '#${jobId}\\n')
            
            # fix Nghiệm Thu & Giải Ngân
            content = content.replace('Nghiệm Thu & Giải Ngân (${formatTokenHTML(parseInt(m.amount))}\n', 'Nghiệm Thu & Giải Ngân (${formatTokenHTML(parseInt(m.amount))})\n')
            content = content.replace('Nghiệm Thu & Giải Ngân (${formatTokenHTML(parseInt(m.amount))}<', 'Nghiệm Thu & Giải Ngân (${formatTokenHTML(parseInt(m.amount))})<')
            
            if content != original:
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
                print(f"Fixed syntax in {f}")

print("Done")
