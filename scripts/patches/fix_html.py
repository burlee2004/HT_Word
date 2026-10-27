content = open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', encoding='utf-8').read()
content = content.replace('onchange="renderCharts()"', 'onchange="renderCharts(); renderLedgerTable();"')
open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', 'w', encoding='utf-8').write(content)
