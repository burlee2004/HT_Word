import re
content = open(r'd:\Project_internship\New_code\code\Front_end\user\direct-chat.html', encoding='utf-8').read()
match = re.search(r'<form.*?id="chatForm".*?>', content)
if match:
    print(match.group(0))
else:
    print("No chatForm found")
