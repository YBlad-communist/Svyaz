import urllib.request, http.client, re

BASE = 'http://127.0.0.1:5000'

# 1. Login page (should be 200)
resp = urllib.request.urlopen(BASE + '/login', timeout=5)
csp = resp.headers.get('Content-Security-Policy', '')
html = resp.read().decode()
has_nonce = 'nonce-' in csp
has_csrf = 'csrf_token' in html
print('1. GET /login: Status=%d, Nonce in CSP=%s, CSRF in HTML=%s' % (resp.status, has_nonce, has_csrf))

# 2. Register page
resp2 = urllib.request.urlopen(BASE + '/register', timeout=5)
print('2. GET /register: Status=%d' % resp2.status)

# 3. POST login without CSRF (should NOT crash - no @csrf_required)
token = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html)
token = token.group(1) if token else ''
conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
conn.request('POST', '/login', 'username=nobody&password=test&_csrf_token=' + token,
             headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp3 = conn.getresponse()
data3 = resp3.read().decode()
csrf_ok = 'Security check failed' not in data3
print('3. POST /login (no CSRF): Status=%d, No security error=%s' % (resp3.status, csrf_ok))

# 4. Health with Redis
resp4 = urllib.request.urlopen(BASE + '/health', timeout=5)
print('4. GET /health: Status=%d, Body=%s' % (resp4.status, resp4.read().decode()))

print()
if resp.status == 200 and resp2.status == 200 and csrf_ok and (resp4.status == 200):
    print('ALL OK')
else:
    print('SOME CHECKS FAILED')
