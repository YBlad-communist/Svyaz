with open('app.py') as f:
    lines = f.readlines()
for i, line in enumerate(lines, 1):
    if 'limiter' in line.lower() and ('limit' in line.lower() or '=' in line):
        print(f"Line {i}: {line.rstrip()[:100]}")
