import sys
path = r'd:\Project_internship\New_code\code\Front_end\user\direct-chat.html'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace <div id="chatForm" ...> with <form id="chatForm" onsubmit="event.preventDefault(); handleSendMessage(event); return false;" ...>
# And replace </div> with </form> for that specific block.

old_start = '<div id="chatForm" class="flex items-center gap-1 sm:gap-1.5">'
new_start = '<form id="chatForm" onsubmit="event.preventDefault(); handleSendMessage(event); return false;" class="flex items-center gap-1 sm:gap-1.5">'

if old_start in content:
    idx = content.find(old_start)
    end_idx = content.find('</div>', idx)
    
    # Actually wait, the button is:
    # <button type="button" onclick="event.preventDefault(); event.stopPropagation(); handleSendMessage(event); return false;" id="btnSendMessage" disabled class="...">
    # We should change type="button" to type="submit".
    
    part1 = content[:idx]
    part2 = content[idx:end_idx].replace(old_start, new_start)
    part2 = part2.replace('id="btnSendMessage" disabled', 'id="btnSendMessage" type="submit" disabled')
    part2 = part2.replace('type="button" onclick="event.preventDefault(); event.stopPropagation(); handleSendMessage(event); return false;" id="btnSendMessage"', 'type="submit" id="btnSendMessage"')
    
    part3 = '</form>' + content[end_idx+6:]
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(part1 + part2 + part3)
    print("Replaced chatForm div with form")
else:
    print("chatForm div not found!")
