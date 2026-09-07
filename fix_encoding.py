import os
import sys

def reverse_powershell_mojibake(text):
    result = bytearray()
    for char in text:
        try:
            # Try cp1252 first
            b = char.encode('cp1252')
            result.extend(b)
        except UnicodeEncodeError:
            # If it's something like \x81, \x8d, \x8f, \x90, \x9d which powershell mapped directly
            if ord(char) < 256:
                result.append(ord(char))
            else:
                # This shouldn't happen if it was pure byte reading, but just in case
                result.extend(char.encode('utf-8'))
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError as e:
        # If it fails to decode as utf-8, it means our byte reconstruction is slightly off
        return result.decode('utf-8', errors='replace')

html_files = ['home.html', 'wallet.html', 'post-job.html', 'escrow-test.html', 'review-work.html', 'my-requests.html', 'profile.html']
base_dir = r"d:\Project_personal\code\backup_html"
out_dir = r"d:\Project_personal\code\Front_end\user"

for filename in html_files:
    filepath = os.path.join(base_dir, filename)
    outpath = os.path.join(out_dir, filename)
    if not os.path.exists(filepath):
        continue
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if content.startswith('\ufeff'):
        content = content[1:]
    
    fixed_content = reverse_powershell_mojibake(content)
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    print(f"Fixed {filename}")

