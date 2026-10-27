import os
import re

frontend_dir = r'd:\Project_internship\New_code\code\Front_end'

for root, dirs, files in os.walk(frontend_dir):
    for f in files:
        if f.endswith('.js'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            original = content
            
            # Replace .innerText = (data.balance || 0).toLocaleString() + ' Token';
            # with .innerHTML = typeof formatTokenHTML === 'function' ? formatTokenHTML(...) : ...
            
            content = re.sub(
                r'(\.innerText|\.textContent)\s*=\s*(.+?)\.toLocaleString\(\)\s*\+\s*[\'"]\s*Token[\'"]',
                r'.innerHTML = typeof window.formatTokenHTML === "function" ? window.formatTokenHTML(\2) : (\2).toLocaleString() + " Token"',
                content
            )
            
            if content != original:
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
                print(f"Fixed {f}")
