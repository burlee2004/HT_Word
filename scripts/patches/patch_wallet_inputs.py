import os, re

files = [
    r'd:\Project_internship\New_code\code\Front_end\user\wallet.html',
    r'd:\Project_internship\New_code\code\Front_end\freelancer\wallet.html'
]

for filepath in files:
    if not os.path.exists(filepath): continue
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Change type="number" to type="text" inputmode="numeric" and add oninput event
    content = re.sub(
        r'<input type="number" id="amount"([^>]*)>',
        r'<input type="text" inputmode="numeric" id="amount" oninput="formatNumberInput(this)"\1>',
        content
    )
    content = re.sub(
        r'<input type="number" id="withdrawAmount"([^>]*)>',
        r'<input type="text" inputmode="numeric" id="withdrawAmount" oninput="formatNumberInput(this)"\1>',
        content
    )

    # 2. Add the JS formatting function at the end of the file
    format_js = """
        // Auto-format currency inputs
        function formatNumberInput(input) {
            let val = input.value.replace(/[^0-9]/g, '');
            if (val !== '') {
                input.value = parseInt(val, 10).toLocaleString('vi-VN').replace(/,/g, '.');
            } else {
                input.value = '';
            }
        }
        
        // Helper to parse formatted string back to integer
        function parseFormattedNumber(val) {
            if(!val) return 0;
            return parseInt(val.toString().replace(/[^0-9]/g, ''), 10);
        }
    """
    if 'function formatNumberInput' not in content:
        content = content.replace('function setQuickAmount', format_js + '\n        function setQuickAmount')
        # Also need to parse it back inside setQuickAmount:
        content = content.replace("document.getElementById('amount').value = val;", "document.getElementById('amount').value = parseInt(val).toLocaleString('vi-VN').replace(/,/g, '.');")
        content = content.replace("document.getElementById('withdrawAmount').value = val;", "document.getElementById('withdrawAmount').value = parseInt(val).toLocaleString('vi-VN').replace(/,/g, '.');")

    # 3. Fix the parsing logic wherever they use .value
    content = re.sub(r'const amount = document.getElementById\(\'amount\'\)\.value;', r"const amountStr = document.getElementById('amount').value; const amount = parseFormattedNumber(amountStr);", content)
    content = re.sub(r'const amount = parseInt\(document.getElementById\(\'withdrawAmount\'\)\.value\);', r"const amount = parseFormattedNumber(document.getElementById('withdrawAmount').value);", content)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
        print("Patched", filepath)
