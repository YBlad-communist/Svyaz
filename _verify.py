import urllib.request, re

resp = urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=5)
csp = resp.headers.get('Content-Security-Policy', 'NONE')
print('Status:', resp.status)
print('CSP:', csp[:300])

html = resp.read().decode()
nonces = re.findall(r'nonce="([^"]+)"', html)
print('Nonces found:', len(nonces))
print('Unique nonces:', len(set(nonces)))
for n in set(nonces):
    print('  nonce:', n[:20])

# Verify nonce is in CSP
if 'nonce-' in csp:
    print('NONCE IN CSP: YES')
else:
    print('NONCE IN CSP: NO - PROBLEM!')

# Check CSRF token presence
if 'csrf_token' in html:
    print('CSRF token in HTML: YES')
else:
    print('CSRF token in HTML: NO')
