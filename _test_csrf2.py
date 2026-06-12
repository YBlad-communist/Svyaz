import urllib.request, http.client, re

resp = urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=5)
html = resp.read().decode()
m = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html)
token = m.group(1) if m else ''
print('CSRF token:', token[:20] + '...' if token else 'NONE')

conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
body = 'username=testuser&password=test123&_csrf_token=' + token
conn.request('POST', '/login', body=body,
             headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp2 = conn.getresponse()
body2 = resp2.read().decode()
print('Login POST: Status=%d' % resp2.status)
if 'Security check failed' in body2:
    print('FAIL: CSRF security check still failing!')
elif resp2.status == 302:
    print('OK: POST accepted, redirect to:', resp2.getheader('Location'))
elif 'Invalid username or password' in body2:
    print('OK: CSRF passed, invalid credentials (expected)')
else:
    print('Other body[:250]:', body2[:250])
