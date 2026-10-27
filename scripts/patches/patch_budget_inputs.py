import os, re

filepath = r'd:\Project_internship\New_code\code\Front_end\user\post-job.html'

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Change type="number" to type="text" inputmode="numeric" and add oninput event
content = re.sub(
    r'<input type="number" id="budget"([^>]*)>',
    r'<input type="text" inputmode="numeric" id="budget" oninput="formatNumberInput(this)"\1>',
    content
)
content = re.sub(
    r'<input type="number" id="edit_budget"([^>]*)>',
    r'<input type="text" inputmode="numeric" id="edit_budget" oninput="formatNumberInput(this)"\1>',
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
    # Inject it near the start of <script>
    content = content.replace('<script>', '<script>\n' + format_js)
    
# 3. Fix the parsing logic wherever they use .value
# For budget in step 2 validation:
# const budget = document.getElementById('budget')?.value;
# => const budgetStr = document.getElementById('budget')?.value; const budget = parseFormattedNumber(budgetStr);
content = re.sub(
    r'const budget = document.getElementById\(\'budget\'\)\?\.value;',
    r"const budgetStr = document.getElementById('budget')?.value; const budget = parseFormattedNumber(budgetStr);",
    content
)

# For budgetVal in step 2 confirm:
# const budgetVal = document.getElementById('budget')?.value || 0;
# => const budgetVal = parseFormattedNumber(document.getElementById('budget')?.value) || 0;
content = re.sub(
    r'const budgetVal = document\.getElementById\(\'budget\'\)\?\.value \|\| 0;',
    r"const budgetVal = parseFormattedNumber(document.getElementById('budget')?.value) || 0;",
    content
)

# For edit_budget:
# const budget = parseFloat(document.getElementById('edit_budget')?.value);
# => const budget = parseFormattedNumber(document.getElementById('edit_budget')?.value);
content = re.sub(
    r'const budget = parseFloat\(document\.getElementById\(\'edit_budget\'\)\?\.value\);',
    r"const budget = parseFormattedNumber(document.getElementById('edit_budget')?.value);",
    content
)

# For AI fill budget:
# document.getElementById('budget').value = job.estimated_budget;
# => document.getElementById('budget').value = parseInt(job.estimated_budget).toLocaleString('vi-VN').replace(/,/g, '.');
content = re.sub(
    r'document\.getElementById\(\'budget\'\)\.value = job\.estimated_budget;',
    r"document.getElementById('budget').value = parseInt(job.estimated_budget).toLocaleString('vi-VN').replace(/,/g, '.');",
    content
)

# For manual submit form:
# const budgetVal = document.getElementById('budget').value;
# const budget = parseFloat(budgetVal);
# =>
content = re.sub(
    r'const budgetVal = document\.getElementById\(\'budget\'\)\.value;\s*const budget = parseFloat\(budgetVal\);',
    r"const budget = parseFormattedNumber(document.getElementById('budget').value);",
    content
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)
print("Patched post-job.html")
