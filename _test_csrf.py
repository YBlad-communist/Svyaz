import urllib.request
import re
resp = urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=5)
print('Status:', resp.status)
html = resp.read().decode()
m = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html)
if m:
    print('CSRF token in form: YES (len=%d)' % len(m.group(1)))
else:
    print('CSRF token in form: NO')
# Test login with CSRF
import http.client
conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
body = 'username=testuser&password=test123&_csrf_token=' + (m.group(1) if m else 'test')
conn.request('POST', '/login', body=body, headers=headers)
resp2 = conn.getresponse()
print('Login attempt: Status=%d, Location=%s' % (resp2.status, resp2.getheader('Location','NONE')))
body2 = resp2.read().decode()
if 'Security check failed' in body2:
    print('CSRF ERROR: Security check failed')
elif 'Invalid username or password' in body2:
    print('Expected: Invalid username (no such user)')
else:
    print('Other response (first 200 chars):', body2[:200])
