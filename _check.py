with open('app.py') as f:
    content = f.read()
print("health:", content.count("('/health'"))
print("readiness:", content.count("'/readiness'"))
import re
routes = re.findall(r"@app\.route\('([^']+)", content)
for r in sorted(set(routes)):
    if routes.count(r) > 1:
        print(f"DUPLICATE: {r} ({routes.count(r)})")
print("Total unique routes:", len(set(routes)))
