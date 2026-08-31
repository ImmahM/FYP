import os, requests
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

BASE = 'http://localhost:8000'

# Upload ZAP scan using API key
API_KEY = '2e3157c4eb252b7aa7b52502ea1c794bbabc1cfb877861be14c099445c54c81f'

files = {'filename': ('juiceshop_zap_scan.xml', open('/home/archerysec/app/juiceshop_zap_scan.xml','rb'), 'text/xml')}
data = {
    'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3',
    'scanner': 'zap_scan',
    'scan_url': 'http://localhost:3000',
}
r = requests.post(f'{BASE}/api/v1/uploadscan/', headers={'X-Api-Key': API_KEY}, files=files, data=data)
print(f'Upload: HTTP {r.status_code}')
try:
    print(f'Response: {r.json()}')
except:
    print(f'Response: {r.text[:300]}')
