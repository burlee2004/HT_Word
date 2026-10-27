import sys
filepath = r'd:\Project_internship\New_code\code\Front_end\Admin\admin-ui.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

link = '''
                <li>
                    <a href="chart-builder.html" class="nav-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 hover:text-white font-semibold transition text-xs sm:text-sm">
                        <i class="fas fa-chart-pie w-5 text-purple-400"></i> <span>Quản lý Biểu đồ</span>
                    </a>
                </li>'''

drawer_link = '''<a href="chart-builder.html" class="drawer-item flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-gray-300 hover:bg-gray-800 font-semibold"><i class="fas fa-chart-pie w-5 text-purple-400"></i> <span>Quản lý Biểu đồ</span></a>'''

if 'chart-builder.html' not in content:
    if '<!-- End Navigation -->' in content:
        content = content.replace('<!-- End Navigation -->', link + '\n                <!-- End Navigation -->')
    else:
        # Just append it before the blockchain-audit.html if we can't find End Navigation
        content = content.replace('<a href="blockchain-audit.html"', link + '\n<a href="blockchain-audit.html"')
        
    content = content.replace('<a href="blockchain-audit.html" class="drawer-item', drawer_link + '\n                        <a href="blockchain-audit.html" class="drawer-item')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Added link')
else:
    print('Link already exists')
