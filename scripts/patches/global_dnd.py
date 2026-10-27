import os

dirs = [
    r'd:\Project_internship\New_code\code\Front_end\user',
    r'd:\Project_internship\New_code\code\Front_end\freelancer',
    r'd:\Project_internship\New_code\code\Front_end\sharedFolder',
    r'd:\Project_internship\New_code\code\Front_end\Admin'
]

js_setup = '''
    <script>
        // Global Drag and Drop protection
        window.addEventListener('dragover', function(e) {
            e.preventDefault();
        }, false);
        window.addEventListener('drop', function(e) {
            e.preventDefault();
        }, false);
    </script>
</body>
'''

for d in dirs:
    if not os.path.exists(d): continue
    for f in os.listdir(d):
        if f.endswith('.html'):
            path = os.path.join(d, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            if 'Global Drag and Drop protection' not in content:
                content = content.replace('</body>', js_setup)
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(content)
print("Added global drop protection to all HTML files")
