import os
import time
import re

ts = str(int(time.time()))
frontend_dir = r'd:\Project_internship\New_code\code\Front_end'

for root, dirs, files in os.walk(frontend_dir):
    for f in files:
        if f.endswith('.html'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            original = content
            
            # Replace script paths, avoiding adding ?v= twice
            content = re.sub(r'ui\.js(?:\?v=\d+)?\"', f'ui.js?v={ts}"', content)
            content = re.sub(r'freelancer-ui\.js(?:\?v=\d+)?\"', f'freelancer-ui.js?v={ts}"', content)
            content = re.sub(r'token-formatter\.js(?:\?v=\d+)?\"', f'token-formatter.js?v={ts}"', content)
            
            if content != original:
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
                print(f"Added cache busting to {f}")
