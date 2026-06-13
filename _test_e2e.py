"""End-to-end test: register a user and login"""
import urllib.request, http.client, re

BASE = 'http://127.0.0.1:5000'

# Step 1: GET register form, extract CSRF
resp = urllib.request.urlopen(BASE + '/register', timeout=5)
html = resp.read().decode()
token = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html)
if not token:
    print('FAIL: No CSRF token in register page')
    exit(1)
token = token.group(1)
print('1. Register page loaded, CSRF token:', token[:16] + '...')

# Step 2: POST register with CSRF
conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
body = 'username=seu&email=seu@test.com&password=Secret123!&confirm_password=Secret123!&_csrf_token=' + token
conn.request('POST', '/register', body=body,
             headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp2 = conn.getresponse()
data = resp2.read().decode()
print('2. Register POST: Status=%d' % resp2.status)
if resp2.status == 302:
    print('   Redirect to:', resp2.getheader('Location'))
elif 'Security check failed' in data:
    print('   FAIL: Security check failed!')
elif 'already' in data.lower() or 'exists' in data.lower():
    print('   User may already exist (ok)')
else:
    print('   First 200 chars:', data[:200])

# Step 3: GET login form, extract CSRF
resp3 = urllib.request.urlopen(BASE + '/login', timeout=5)
html3 = resp3.read().decode()
token3 = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html3)
token3 = token3.group(1) if token3 else ''
print('3. Login page loaded, CSRF token:', token3[:16] + '...' if token3 else 'NONE')

# Step 4: POST login  
conn2 = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
body4 = 'username=seu&password=Secret123!&_csrf_token=' + token3
conn2.request('POST', '/login', body=body4,
              headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp4 = conn2.getresponse()
data4 = resp4.read().decode()
print('4. Login POST: Status=%d' % resp4.status)
if resp4.status == 302:
    print('   OK: Logged in, redirect to:', resp4.getheader('Location'))
elif 'Security check failed' in data4:
    print('   FAIL: Security check failed!')
elif 'Invalid username or password' in data4:
    print('   Expected: invalid credentials')
else:
    print('   First 200 chars:', data4[:200])

print('\nDone.')
