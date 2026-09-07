with open('Front_end/user/review-work.html', 'r', encoding='utf-8') as f: content = f.read()
print("pending_plan_approval" in content)
print("approvePlanAndLock" in content)
