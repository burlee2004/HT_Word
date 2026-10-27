import os
import re

def fix_html_layout(filepath, remove_buttons_regex):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Fix head Tailwind config and scrollbar CSS
    if 'tailwind.config' not in content:
        head_addon = """
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: { 50: '#eef2ff', 100: '#e0e7ff', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca', 900: '#312e81' },
                        dark: { 800: '#1e293b', 850: '#172033', 900: '#0f172a', 950: '#020617' }
                    }
                }
            }
        }
    </script>
    <style>
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        .dark .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; }
    </style>"""
        content = content.replace('</head>', f'{head_addon}\n</head>')

    # 2. Extract inner content between body and script/end body
    body_match = re.search(r'<body[^>]*>', content)
    if not body_match: return
    body_start_idx = body_match.end()

    end_match = re.search(r'(<script[^>]*>[\s\S]*?</script>\s*)*</body>', content[body_start_idx:])
    if not end_match: return
    body_end_idx = body_start_idx + end_match.start()
    
    scripts_and_closing = content[body_end_idx:]
    inner_content = content[body_start_idx:body_end_idx].strip()

    # If already wrapped, skip
    if 'id="sidebar-container"' in inner_content:
        return

    for regex in remove_buttons_regex:
        inner_content = re.sub(regex, '', inner_content, flags=re.DOTALL)

    new_body = f"""
<body class="bg-slate-50 dark:bg-dark-950 text-slate-800 dark:text-slate-100 font-sans transition-colors duration-200">
    <div class="flex h-screen overflow-hidden">
        <!-- Sidebar Navigation -->
        <aside id="sidebar-container" class="shrink-0"></aside>

        <!-- Main Content Area -->
        <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
            <!-- Topbar Header -->
            <header id="topbar-container" class="shrink-0"></header>

            <!-- Main Scrollable Body -->
            <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8 space-y-6">
                {inner_content}
            </main>
        </div>
    </div>
"""

    final_content = content[:body_match.start()] + new_body + scripts_and_closing

    if 'admin-ui.js' not in final_content:
        final_content = final_content.replace('</body>', '    <script src="admin-ui.js"></script>\n</body>')
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(final_content)
    print(f"Fixed layout for {filepath}")

admin_dir = r'd:\Project_internship\New_code\code\Front_end\Admin'

bc_regex = [
    r'<button onclick="window\.location\.href=\'dashboard\.html\'"[^>]*>.*?</button>',
]
fix_html_layout(os.path.join(admin_dir, 'blockchain-audit.html'), bc_regex)

