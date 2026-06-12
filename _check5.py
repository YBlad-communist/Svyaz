with open('app.py') as f:
    lines = f.readlines()
dupes = {}
for i, line in enumerate(lines, 1):
    for keyword in ['def not_found', 'def internal_error', 'def security_txt', 'def robots_txt',
                    'def health', 'def readiness', 'def unhandled_exception',
                    'def totp_verify', 'def totp_setup', 'def totp_disable',
                    'app.wsgi_app']:
        if keyword in line:
            dupes.setdefault(keyword, []).append(i)
for k, v in dupes.items():
    if len(v) > 1:
        print(f"DUPLICATE: {k} at lines {v}")
    else:
        print(f"OK: {k} at line {v[0]}")
