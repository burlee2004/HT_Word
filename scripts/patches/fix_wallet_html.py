import os
import re

frontend_dir = r'd:\Project_internship\New_code\code\Front_end'

for root, dirs, files in os.walk(frontend_dir):
    for f in files:
        if f.endswith('.html'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            original = content
            
            # Replace textContent with innerHTML if formatTokenHTML is present
            content = re.sub(r'\.textContent\s*=\s*([^\n;]+formatTokenHTML[^\n;]+;?)', r'.innerHTML = \1', content)
            
            # Fix alerts to not use HTML tokens
            content = re.sub(
                r'alert\(`(.*?)(\$\{formatTokenHTML\((.*?)\)\})(.*?)`\)',
                r'alert(`\1${formatTokenHTML(\3, false)}\4`)',
                content
            )

            # Some files might have multiple alerts or different formats.
            # E.g. alert(`... ${formatTokenHTML(amount)} ...`)
            # Just do a generic replace inside alert
            # Actually, the regex above handles template literal alerts
            
            if content != original:
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
                print(f"Fixed {f}")
