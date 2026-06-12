with open('app.py') as f:
    lines = f.readlines()
for i, line in enumerate(lines, 1):
    if 'limiter = Limiter(' in line:
        print(f"Line {i}: {line.rstrip()}")
    if 'def totp_verify' in line:
        print(f"Line {i}: {line.rstrip()}")
