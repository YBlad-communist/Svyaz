import urllib.request

try:
    resp = urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=5)
    print('Status:', resp.status)
    print('Body[:500]:', resp.read().decode()[:500])
except urllib.error.HTTPError as e:
    print('HTTP Error:', e.code)
    print('Body:', e.read().decode()[:500])
except Exception as e:
    print('Error:', str(e)[:200])
