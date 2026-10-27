import re
content = open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', encoding='utf-8').read()

# Modify renderLedgerTable to include Date Filter
old_filter_code = '''            let filtered = allTransactions;
            if (filterType !== 'ALL') {
                filtered = filtered.filter(t => (t.type || '').toUpperCase().includes(filterType));
            }'''

new_filter_code = '''            let filtered = allTransactions;
            if (filterType !== 'ALL') {
                filtered = filtered.filter(t => (t.type || '').toUpperCase().includes(filterType));
            }
            const dateFilter = document.getElementById('chartDateFilter') ? document.getElementById('chartDateFilter').value : '';
            if (dateFilter) {
                filtered = filtered.filter(t => t.created_at && t.created_at.startsWith(dateFilter));
            }'''

if "const dateFilter = document.getElementById('chartDateFilter')" not in content:
    content = content.replace(old_filter_code, new_filter_code)

# Make ledgerTypeFilter onchange trigger renderCharts as well, so both are in sync
if 'onchange="renderLedgerTable()"' in content:
    content = content.replace('onchange="renderLedgerTable()"', 'onchange="renderLedgerTable(); if(typeof renderCharts === \'function\') renderCharts();"')

open(r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html', 'w', encoding='utf-8').write(content)
print("Updated renderLedgerTable for Date sync")
