with open('app.py') as f:
    lines = f.readlines()
for i, line in enumerate(lines, 1):
    if 'def get_real_ip' in line:
        print(f"get_real_ip starts at line {i}")
    if 'return request.remote_addr' in line:
        print(f"get_real_ip ends at line {i}")
