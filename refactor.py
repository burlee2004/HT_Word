import os
import re

html_files = ['home.html', 'wallet.html', 'post-job.html', 'escrow-test.html', 'review-work.html', 'my-requests.html', 'profile.html']
base_dir = r"d:\Project_personal\code\Front_end\user"

tailwind_config = '''
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#4f46e5',
                        dark: '#111827',
                        darkCard: '#1f2937'
                    }
                }
            }
        }
    </script>
'''

for filename in html_files:
    filepath = os.path.join(base_dir, filename)
    if not os.path.exists(filepath):
        continue
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove old <nav>
    content = re.sub(r'<nav.*?</nav>', '', content, flags=re.DOTALL)
    
    # Remove old script ui.js if accidentally added multiple times
    content = re.sub(r'<script src="ui.js"></script>', '', content)
    
    # Add tailwind config if not there
    if 'tailwind.config' not in content:
        content = content.replace('</head>', tailwind_config + '</head>')
        
    # Replace body class
    content = re.sub(r'<body[^>]*>', '<body class="bg-gray-50 dark:bg-gray-900 transition-colors text-gray-800 dark:text-gray-100 h-screen flex overflow-hidden">', content)
    
    # Wrap body content
    body_match = re.search(r'<body[^>]*>', content)
    body_start_idx = body_match.end()
    body_end_idx = content.rfind('</body>')
    
    body_inner = content[body_start_idx:body_end_idx]
    
    # Create new layout structure ONLY if not already wrapped
    if 'id="sidebar-container"' not in body_inner:
        new_inner = f'''
    <!-- Sidebar Placeholder -->
    <div id="sidebar-container"></div>
    
    <!-- Main Wrapper -->
    <div class="flex-1 flex flex-col overflow-hidden">
        <!-- Header Placeholder -->
        <div id="header-container"></div>
        
        <!-- Main Content -->
        <main class="flex-1 overflow-y-auto p-4 md:p-8 relative">
            {body_inner}
        </main>
    </div>
    
    <!-- Shared UI Script -->
    <script src="ui.js"></script>
        '''
        new_content = content[:body_start_idx] + new_inner + content[body_end_idx:]
        
        # Remove old broken javascript listeners that reference nav elements
        new_content = new_content.replace("document.getElementById('bellBtn')", "// removed bellBtn")
        new_content = new_content.replace("document.getElementById('logoutBtn')", "// removed logoutBtn")
        
        # Add dark mode classes for common elements
        new_content = new_content.replace('bg-white', 'bg-white dark:bg-gray-800 dark:border-gray-700')
        new_content = new_content.replace('text-gray-800', 'text-gray-800 dark:text-gray-100')
        new_content = new_content.replace('text-gray-500', 'text-gray-500 dark:text-gray-400')
        new_content = new_content.replace('text-gray-600', 'text-gray-600 dark:text-gray-300')

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
print("Refactoring complete.")
