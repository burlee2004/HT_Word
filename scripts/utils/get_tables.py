import os, re
res = set()
for root, dirs, files in os.walk(r'd:\Project_internship\New_code\code\Back_end'):
    for f in files:
        if f.endswith('.js'):
            with open(os.path.join(root, f), 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    matches = re.findall(r'\.from\(([\'"])([a-zA-Z0-9_]+)\1\)', line)
                    for match in matches:
                        res.add(match[1])
print('\n'.join(list(res)))
