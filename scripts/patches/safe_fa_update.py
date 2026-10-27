import os, glob

for f in glob.glob(r'd:\Project_internship\New_code\code\Front_end\Admin\*.html'):
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    
    if 'font-awesome/6.0.0/css' in content:
        content = content.replace('font-awesome/6.0.0/css', 'font-awesome/6.4.0/css')
        with open(f, 'w', encoding='utf-8') as file:
            file.write(content)
        print(f"Updated {f}")
