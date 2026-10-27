import os

path = r'd:\Project_internship\New_code\code\Front_end\Admin\dashboard.html'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

bad_str = """        loadDashboardAll = async function() {
            await originalLoadDashboardAll();
            if(!cashflowChartInstance) renderDynamicCharts(); // Chỉ render lần đầu, các lần sau setInterval tự render
        };"""

if bad_str in content:
    content = content.replace(bad_str, "")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Removed bad string")
else:
    print("Bad string not found")

bad_str2 = """        const originalLoadDashboardAll = loadDashboardAll;
        loadDashboardAll = async function() {
            await originalLoadDashboardAll();
            if(!cashflowChartInstance) renderDynamicCharts(); // Chỉ render lần đầu, các lần sau setInterval tự render
        };"""

if bad_str2 in content:
    content = content.replace(bad_str2, "")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Removed bad string 2")
