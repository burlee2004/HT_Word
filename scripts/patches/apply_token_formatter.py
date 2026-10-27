import os
import re

formatter_js = """
window.formatTokenHTML = function(amount, isToken = true) {
    if (amount === undefined || amount === null) return isToken ? '0 Token' : '0';
    let num = parseFloat(amount);
    if (isNaN(num)) return '0';
    
    let str = '';
    let absNum = Math.abs(num);
    if (absNum >= 1000000000) str = (num / 1000000000).toFixed(1).replace(/\\.0$/, '') + 'B';
    else if (absNum >= 1000000) str = (num / 1000000).toFixed(1).replace(/\\.0$/, '') + 'M';
    else if (absNum >= 1000) str = (num / 1000).toFixed(1).replace(/\\.0$/, '') + 'K';
    else str = num.toString();

    if (!isToken) return str;

    let colorClass = num >= 0 ? 'from-emerald-500 to-teal-400' : 'from-red-500 to-rose-400';
    return `<span class="inline-flex items-baseline gap-1 font-black text-transparent bg-clip-text bg-gradient-to-r ${colorClass} drop-shadow-sm" style="letter-spacing: -0.5px; font-size: 1.1em;">
        ${str}
        <i class="fas fa-coins drop-shadow-md" style="font-size: 0.85em; -webkit-text-fill-color: #facc15; color: #facc15;"></i>
    </span>`;
};
"""

assets_dir = r'd:\Project_internship\New_code\code\Front_end\assets\js'
os.makedirs(assets_dir, exist_ok=True)
open(os.path.join(assets_dir, 'token-formatter.js'), 'w', encoding='utf-8').write(formatter_js)

frontend_dir = r'd:\Project_internship\New_code\code\Front_end'
for root, dirs, files in os.walk(frontend_dir):
    for f in files:
        if f.endswith('.html'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Inject script tag
            depth = path.replace(frontend_dir, '').count(os.sep) - 1
            rel_path = '../' * max(0, depth) + 'assets/js/token-formatter.js'
            script_tag = f'<script src="{rel_path}"></script>'
            
            if 'token-formatter.js' not in content:
                content = content.replace('</head>', f'    {script_tag}\n</head>')

            # Replace JS logic in HTML
            # Case 1: .innerText = ...toLocaleString() + ' Token'
            content = re.sub(
                r'\.innerText\s*=\s*(.+?)\.toLocaleString\(\)(?:\s*\+\s*[\'"]\s*Token[\'"])?',
                r'.innerHTML = formatTokenHTML(\1)',
                content
            )
            # Case 2: Template literals `${...toLocaleString()} Token`
            content = re.sub(
                r'\$\{\s*(.+?)\.toLocaleString\(\)\s*\}\s*Token',
                r'${formatTokenHTML(\1)}',
                content
            )
            
            # Case 3: parseInt(t.amount).toLocaleString() + ' Token' in dashboard
            content = re.sub(
                r'parseInt\((.+?)\)\.toLocaleString\(\)\s*\+\s*[\'"]\s*Token[\'"]',
                r'formatTokenHTML(\1)',
                content
            )

            # Special cases for Dashboard Admin (statEscrowLocked, pendingWithdrawAmount)
            content = content.replace('s.total_escrow_locked.toLocaleString()', 'formatTokenHTML(s.total_escrow_locked)')
            content = content.replace('`${s.pending_withdraw_amount.toLocaleString()} Token chờ duyệt`', '`${formatTokenHTML(s.pending_withdraw_amount)} <span class="text-xs">chờ duyệt</span>`')
            content = content.replace('.innerText = `${formatTokenHTML', '.innerHTML = `${formatTokenHTML')
            
            with open(path, 'w', encoding='utf-8') as file:
                file.write(content)

print("Applied token formatter globally.")
