import os

path = r'd:\Project_internship\New_code\code\Front_end\user\post-job.html'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add id="editDropZone" to the edit upload container
old_edit_container = '''<div onclick="document.getElementById('editFileUploadInput').click()" class="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-3 text-center hover:bg-indigo-50/40 dark:hover:bg-indigo-950/20 transition cursor-pointer bg-gray-50/50 dark:bg-gray-800 flex items-center justify-center space-x-2">'''
new_edit_container = '''<div id="editDropZone" onclick="document.getElementById('editFileUploadInput').click()" class="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-3 text-center hover:bg-indigo-50/40 dark:hover:bg-indigo-950/20 transition cursor-pointer bg-gray-50/50 dark:bg-gray-800 flex items-center justify-center space-x-2">'''
content = content.replace(old_edit_container, new_edit_container)

# 2. Add Drag and Drop Setup script at the end of the script block
js_setup = '''
        // Bổ sung: Chặn trình duyệt văng ra ngoài khi kéo thả file và xử lý Drag & Drop
        function setupDragAndDrop(zoneId, inputId, handlerFunction) {
            const zone = document.getElementById(zoneId);
            const input = document.getElementById(inputId);
            if (!zone || !input) return;

            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                window.addEventListener(eventName, preventDefaults, false);
                zone.addEventListener(eventName, preventDefaults, false);
            });

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            ['dragenter', 'dragover'].forEach(eventName => {
                zone.addEventListener(eventName, () => zone.classList.add('bg-indigo-100', 'dark:bg-indigo-900/40'), false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                zone.addEventListener(eventName, () => zone.classList.remove('bg-indigo-100', 'dark:bg-indigo-900/40'), false);
            });

            zone.addEventListener('drop', (e) => {
                let dt = e.dataTransfer;
                let files = dt.files;
                if (files && files.length > 0) {
                    input.files = files;
                    handlerFunction(input);
                }
            }, false);
        }

        document.addEventListener('DOMContentLoaded', () => {
            setupDragAndDrop('dropZone', 'fileUploadInput', handleFileUpload);
            setupDragAndDrop('editDropZone', 'editFileUploadInput', handleEditFileUpload);
        });
'''

# Find the end of the script block to insert
idx = content.rfind('</script>')
if idx != -1:
    content = content[:idx] + js_setup + '\n' + content[idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Added Drag and Drop support to post-job.html")
