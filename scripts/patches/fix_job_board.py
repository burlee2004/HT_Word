import os

fixes = [
    # job-board.html
    (
        'Ngân sách của Khách hàng (${formatTokenHTML(jobBudget, false))!`);',
        'Ngân sách của Khách hàng (${formatTokenHTML(jobBudget, false)})!`);'
    ),
    (
        '(${formatTokenHTML(jobBudget, false))',
        '(${formatTokenHTML(jobBudget, false)})'
    )
]

path = r'd:\Project_internship\New_code\code\Front_end\freelancer\job-board.html'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

for broken, fixed in fixes:
    content = content.replace(broken, fixed)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Fixed job-board.html")
