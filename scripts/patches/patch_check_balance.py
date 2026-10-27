import os

filepath = r'd:\Project_internship\New_code\code\Front_end\user\post-job.html'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

dummy = """
        async function checkBalance() { 
            try { 
                const r = await fetch(`${API_URL}/api/wallet/${currentUser?.id}`); 
                const d = await r.json(); 
                if(r.ok && d.success) { 
                    const balEls = document.querySelectorAll('.wallet-balance, .user-balance');
                    balEls.forEach(el => el.textContent = parseInt(d.wallet.balance).toLocaleString('vi-VN').replace(/,/g, '.') + ' Token');
                } 
            } catch(e) {} 
        }
"""

if 'async function checkBalance' not in content:
    content = content.replace('let currentUser = null;', 'let currentUser = null;\n' + dummy)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
