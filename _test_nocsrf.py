import http.client

# Test POST without CSRF token to see if CSRFProtect blocks it
conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
body = 'username=testuser&password=test123'
conn.request('POST', '/login', body=body,
             headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp = conn.getresponse()
body = resp.read().decode()
print('Status:', resp.status)
if 'Security check failed' in body or 'CSRF' in body:
    print('ERROR: CSRF block seen')
    print(body[:300])
elif resp.status == 302:
    print('OK: Route accepted (redirects)')
else:
    print('Other:', body[:200])
