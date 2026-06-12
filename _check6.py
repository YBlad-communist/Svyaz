with open('app.py') as f:
    lines = f.readlines()
for i in range(595, 615):
    if i < len(lines):
        print(f"{i+1}: {lines[i].rstrip()[:120]}")
