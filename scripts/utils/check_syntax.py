import os
import re
import subprocess

directory = r'd:\Project_internship\New_code\code\Front_end'
errors = 0

for root, dirs, files in os.walk(directory):
    for f in files:
        if f.endswith('.html'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)
            for i, script in enumerate(scripts):
                with open('tmp.js', 'w', encoding='utf-8') as tmp:
                    tmp.write(script)
                
                res = subprocess.run(['node', '-c', 'tmp.js'], capture_output=True, text=True)
                if res.returncode != 0:
                    print(f"Error in {f} script block {i}:")
                    print(res.stderr.strip().split('\n')[0])
                    errors += 1

if errors == 0:
    print("All inline scripts are valid.")
