import os, requests, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

BASE = 'http://localhost:8000'

# Wait for app
for i in range(10):
    try:
        r = requests.get(f'{BASE}/api/v1/auth/login/')
        print(f'  App check {i}: HTTP {r.status_code}')
        if r.status_code in (200, 405):
            break
    except Exception as e:
        print(f'  App check {i}: {e}')
    time.sleep(3)

# Login
r = requests.post(f'{BASE}/api/v1/auth/login/', json={'email':'immah@gmail.com','password':'wXXTBTT7dHrU5p4e75cuXeAd5wQ'})
print(f'\nLogin: {r.status_code}')
if r.status_code != 200:
    print(f'  Body: {r.text[:300]}')
else:
    token = r.json()['access']
    h = {'Authorization': f'Bearer {token}'}

    # Try web-scans list
    r2 = requests.get(f'{BASE}/api/v1/web-scans/', headers=h)
    print(f'web-scans list: {r2.status_code}')
    print(f'  Body: {r2.text[:300]}')
    
    # Try the specific scan
    NEW_SCAN = '0010457a-7673-47bf-9269-c30cc69cab5b'
    r3 = requests.get(f'{BASE}/api/v1/web-scans/{NEW_SCAN}/', headers=h)
    print(f'\nweb-scans/{NEW_SCAN}: {r3.status_code}')
    print(f'  Content-Type: {r3.headers.get("content-type","?")}')
    print(f'  Body: {r3.text[:300]}')
