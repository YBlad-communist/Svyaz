import urllib.request, http.client, re

BASE = 'http://127.0.0.1:5000'

# Login
resp = urllib.request.urlopen(BASE + '/login', timeout=5)
html = resp.read().decode()
token = re.search(r'name="_csrf_token"[^>]*value="([^"]+)"', html).group(1)

conn = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
conn.request('POST', '/login',
    body='username=seu&password=Secret123!&_csrf_token=' + token,
    headers={'Content-Type': 'application/x-www-form-urlencoded'})
resp2 = conn.getresponse()
cookies = resp2.getheader('Set-Cookie')
print('Login: Status=%d, Has session cookie: %s' % (resp2.status, 'session=' in (cookies or '')))

# Follow redirect to feed
conn3 = http.client.HTTPConnection('127.0.0.1', 5000, timeout=5)
conn3.request('GET', '/feed', headers={'Cookie': cookies.split(';')[0] if cookies else ''})
resp3 = conn3.getresponse()
print('Feed page: Status=%d, Length=%d' % (resp3.status, len(resp3.read())))

# Check `/health`
resp4 = urllib.request.urlopen(BASE + '/health', timeout=5)
print('Health: Status=%d, Body=%s' % (resp4.status, resp4.read().decode()))
