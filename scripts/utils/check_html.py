import sys, html.parser
class P(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.in_form = False
    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)
        if tag == "form":
            self.in_form = True
        if dict(attrs).get("id") == "messageInput":
            print("MessageInput is inside form?", self.in_form)
            print("Stack:", self.stack)
    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
content = open(r"d:\Project_internship\New_code\code\Front_end\user\direct-chat.html", "r", encoding="utf-8", errors="ignore").read()
P().feed(content)
