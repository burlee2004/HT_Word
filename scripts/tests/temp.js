
        // Global Drag and Drop protection
        window.addEventListener('dragover', function(e) {
            e.preventDefault();
        }, false);
        window.addEventListener('drop', function(e) {
            e.preventDefault();
        }, false);
    
        // --- Reapply Logic ---
        function openReapplyModal(jobId, currentBudget) {
            document.getElementById('reapplyJobId').value = jobId;
            document.getElementById('reapplyBid').value = currentBudget || '';
            document.getElementById('reapplyCover').value = 'Chào anh/chị, em xin gửi lại báo giá phù hợp hơn cho dự án này ạ.';
            
            const modal = document.getElementById('reapplyModal');
            const content = document.getElementById('reapplyModalContent');
            
            modal.classList.remove('hidden');
            // Trigger reflow
            void modal.offsetWidth;
            
            modal.classList.remove('opacity-0');
            content.classList.remove('scale-95');
            content.classList.add('scale-100');
        }

        function closeReapplyModal() {
            const modal = document.getElementById('reapplyModal');
            const content = document.getElementById('reapplyModalContent');
            
            modal.classList.add('opacity-0');
            content.classList.remove('scale-100');
            content.classList.add('scale-95');
            
            setTimeout(() => {
                modal.classList.add('hidden');
            }, 300);
        }

        async function submitReapply() {
            const jobId = document.getElementById('reapplyJobId').value;
            const bidAmount = document.getElementById('reapplyBid').value;
            const coverLetter = document.getElementById('reapplyCover').value;
            const btn = document.getElementById('reapplyBtn');

            if (!bidAmount || bidAmount <= 0) {
                alert('Vui lòng nhập báo giá hợp lệ!');
                return;
            }

            try {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> Đang gửi...';

                const res = await fetch(`${API_URL}/api/jobs/reapply`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        job_id: jobId,
                        freelancer_id: currentUser.id,
                        bid_amount: bidAmount,
                        cover_letter: coverLetter
                    })
                });
                
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Lỗi ứng tuyển lại');

                alert('Đã gửi lại đề xuất thành công! Vui lòng chờ khách hàng duyệt.');
                closeReapplyModal();
                loadJobs(); // Tải lại danh sách
                
            } catch (error) {
                alert(error.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<span>Gửi đề xuất</span>';
            }
        }
        // ---------------------


        // --- AI Auto Generate Milestones ---
        
        // --- AI PLAN CHAT ---
        let currentGeneratedMilestones = [];

        function openAiPlanModal() {
            const modal = document.getElementById('aiPlanModal');
            const content = document.getElementById('aiPlanModalContent');
            if (modal) {
                modal.classList.remove('hidden');
                void modal.offsetWidth;
                modal.classList.remove('opacity-0');
                content.classList.remove('scale-95');
                content.classList.add('scale-100');
                setTimeout(() => document.getElementById('aiPlanInput')?.focus(), 300);
            }
        }

        function closeAiPlanModal() {
            const modal = document.getElementById('aiPlanModal');
            const content = document.getElementById('aiPlanModalContent');
            if (modal) {
                modal.classList.add('opacity-0');
                content.classList.remove('scale-100');
                content.classList.add('scale-95');
                setTimeout(() => modal.classList.add('hidden'), 300);
            }
        }

        function sendAiPlanPrompt(txt) {
            const input = document.getElementById('aiPlanInput');
            if(input) {
                input.value = txt;
                submitAiPlanChat(new Event('submit'));
            }
        }

        async function submitAiPlanChat(e) {
            if(e) e.preventDefault();
            const input = document.getElementById('aiPlanInput');
            const txt = input.value.trim();
            if(!txt) return;

            const jobId = document.getElementById('modal_job_id').value;
            const jobBudget = parseFloat(document.getElementById('modal_job_budget').value);
            const job = allJobs.find(j => String(j.id) === String(jobId));
            if (!job) return;

            const history = document.getElementById('aiPlanHistory');
            const sendBtn = document.getElementById('aiPlanSendBtn');

            // User Message
            history.insertAdjacentHTML('beforeend', `
                <div class="flex items-start justify-end space-x-3">
                    <div class="bg-gradient-to-r from-purple-600 to-indigo-600 text-white p-3.5 rounded-2xl rounded-tr-sm shadow-sm max-w-[85%] text-sm">
                        ${escapeHtml(txt)}
                    </div>
                    <div class="w-8 h-8 rounded-full bg-indigo-100 dark:bg-indigo-900 text-indigo-700 flex items-center justify-center text-sm shrink-0 font-bold shadow">U</div>
                </div>
            `);
            
            input.value = '';
            history.scrollTop = history.scrollHeight;
            sendBtn.disabled = true;

            // Loading state
            const loadingId = 'ai-loading-' + Date.now();
            history.insertAdjacentHTML('beforeend', `
                <div id="${loadingId}" class="flex items-start space-x-3">
                    <div class="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-700 animate-pulse shrink-0"></div>
                    <div class="bg-gray-100 dark:bg-gray-800 p-4 rounded-2xl rounded-tl-sm w-48 h-12 animate-pulse"></div>
                </div>
            `);
            history.scrollTop = history.scrollHeight;

            try {
                const res = await fetch(`${API_URL}/api/ai/suggest-milestones`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        job_title: job.title,
                        job_description: job.description,
                        budget: jobBudget,
                        custom_prompt: txt
                    })
                });
                
                const data = await res.json();
                document.getElementById(loadingId)?.remove();

                if (!res.ok) throw new Error(data.error || 'Lỗi gọi AI');
                
                const ms = data.data?.milestones;
                if (!ms || ms.length === 0) throw new Error('AI không tạo được kế hoạch.');
                
                currentGeneratedMilestones = ms; // Lưu lại để apply

                let msHtml = `<ul class="mt-3 space-y-2 text-xs">`;
                ms.forEach((m, idx) => {
                    msHtml += `
                        <li class="bg-gray-50 dark:bg-gray-750 p-2.5 rounded-lg border border-gray-200 dark:border-gray-650">
                            <div class="font-bold text-gray-800 dark:text-white">GĐ ${idx+1}: ${escapeHtml(m.title)}</div>
                            <div class="text-indigo-600 font-bold my-0.5">${formatTokenHTML(m.amount)}</div>
                            <div class="text-gray-500">Bàn giao: ${escapeHtml(m.deliverables)}</div>
                        </li>
                    `;
                });
                msHtml += `</ul>`;

                const aiMessage = data.data?.ai_message || `Đã chia dự án thành ${ms.length} giai đoạn với tổng ngân sách ${formatTokenHTML(jobBudget)}!`;

                history.insertAdjacentHTML('beforeend', `
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 rounded-full bg-gradient-to-tr from-purple-600 to-indigo-600 text-white flex items-center justify-center text-sm shrink-0 shadow">🤖</div>
                        <div class="bg-white dark:bg-gray-800 p-4 rounded-2xl rounded-tl-sm shadow-sm border border-gray-100 dark:border-gray-700 max-w-[92%] text-sm text-gray-800 dark:text-gray-200">
                            <p class="font-medium">${escapeHtml(aiMessage)}</p>
                            ${msHtml}
                            <div class="mt-4 pt-3 border-t border-gray-100 dark:border-gray-700 flex justify-end">
                                <button onclick="applyAiMilestones()" class="bg-emerald-500 hover:bg-emerald-600 text-white px-4 py-2 rounded-xl text-xs font-bold shadow-md transition flex items-center">
                                    <i class="fas fa-check-circle mr-1.5"></i> Áp Dụng Kế Hoạch Này
                                </button>
                            </div>
                        </div>
                    </div>
                `);

            } catch (err) {
                document.getElementById(loadingId)?.remove();
                history.insertAdjacentHTML('beforeend', `
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 rounded-full bg-red-500 text-white flex items-center justify-center text-sm shrink-0 shadow">⚠️</div>
                        <div class="bg-red-50 text-red-700 p-3.5 rounded-2xl rounded-tl-sm text-sm border border-red-200 max-w-[85%]">
                            ${escapeHtml(err.message)}
                        </div>
                    </div>
                `);
            } finally {
                sendBtn.disabled = false;
                history.scrollTop = history.scrollHeight;
            }
        }

        function applyAiMilestones() {
            if(!currentGeneratedMilestones || currentGeneratedMilestones.length === 0) return;
            
            // Xóa form cũ
            document.getElementById('milestonesContainer').innerHTML = '';
            milestoneCount = 0;
            
            currentGeneratedMilestones.forEach(m => {
                addMilestoneForm();
                const forms = document.querySelectorAll('.milestone-item');
                const lastForm = forms[forms.length - 1];
                
                if(lastForm.querySelector('.m-title')) lastForm.querySelector('.m-title').value = m.title || '';
                if(lastForm.querySelector('.m-amount')) lastForm.querySelector('.m-amount').value = m.amount || '';
                if(lastForm.querySelector('.m-desc')) lastForm.querySelector('.m-desc').value = m.expected_deliverables || '';
                if(lastForm.querySelector('.m-deliver')) lastForm.querySelector('.m-deliver').value = m.expected_deliverables || '';
            });
            
            if(typeof updatePlanSummary === 'function') updatePlanSummary();
            closeAiPlanModal();
            
            if(typeof Swal !== 'undefined') {
                Swal.fire({ title: 'Đã áp dụng', text: 'Kế hoạch đã được điền vào Form!', icon: 'success', toast: true, position: 'top-end', showConfirmButton: false, timer: 3000 });
            }
        }

        async function old_autoGenerateMilestonesAI() {
            const jobId = document.getElementById('modal_job_id').value;
            const jobBudget = parseFloat(document.getElementById('modal_job_budget').value);
            const job = allJobs.find(j => String(j.id) === String(jobId));
            if (!job) return;

            const btn = document.getElementById('btnGenerateAI');
            const originalHtml = btn.innerHTML;
            
            try {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1.5"></i> AI Đang phân bổ...';
                
                const res = await fetch(`${API_URL}/api/ai/suggest-milestones`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        job_title: job.title,
                        job_description: job.description,
                        budget: jobBudget
                    })
                });
                
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Lỗi AI');
                
                const milestones = data.data?.milestones;
                if (!milestones || milestones.length === 0) throw new Error('AI không trả về kết quả hợp lệ.');
                
                // Clear existing forms and add the ones from AI
                document.getElementById('milestonesContainer').innerHTML = '';
                milestoneCount = 0;
                
                milestones.forEach(m => {
                    addMilestoneForm();
                    // Lấy ra form vừa được append (là form cuối cùng)
                    const forms = document.querySelectorAll('.milestone-item');
                    const lastForm = forms[forms.length - 1];
                    
                    lastForm.querySelector('.m-title').value = m.title || '';
                    lastForm.querySelector('.m-amount').value = m.amount || '';
                    lastForm.querySelector('.m-desc').value = m.expected_deliverables || '';
                });
                
                if(typeof updatePlanSummary === 'function') updatePlanSummary(); // Cập nhật lại số dư phân bổ
                
                // Báo thành công (nếu có SweetAlert thì dùng, không thì alert)
                if(typeof Swal !== 'undefined') {
                    Swal.fire({ title: 'Thành công', text: 'AI đã phân bổ kế hoạch dựa trên ngân sách dự án!', icon: 'success', toast: true, position: 'top-end', showConfirmButton: false, timer: 3000 });
                } else {
                    alert('Trợ lý AI đã tự động phân bổ ngân sách kế hoạch thành công!');
                }
                
            } catch (err) {
                console.error(err);
                if(typeof Swal !== 'undefined') Swal.fire('Lỗi', err.message, 'error');
                else alert(err.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        }
        // -----------------------------------

