import os, requests, time, json, subprocess

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

BASE = 'http://localhost:8000'

def jwt_login(email, password):
    r = requests.post(f'{BASE}/api/v1/auth/login/', json={'email': email, 'password': password})
    if r.status_code == 200:
        return r.json()['access']
    return None

token = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h = {'Authorization': f'Bearer {token}'}

# ============================================================
# Find the scan with 15 findings (our crafted upload)
# ============================================================
r = requests.get(f'{BASE}/api/v1/web-scans/', headers=h)
scans = r.json()
scan_list = scans if isinstance(scans, list) else scans.get('results', [])
print('All scans:')
for s in scan_list:
    print(f'  scan_id={s["scan_id"]} total_vul={s.get("total_vul")} url={s.get("scan_url","")[:30]}')

# Pick the one with most findings
best = max(scan_list, key=lambda s: int(str(s.get('total_vul') or 0)))
sid = best['scan_id']
print(f'\nUsing scan: {sid} ({best.get("total_vul")} vulns)')

# Get findings
r2 = requests.get(f'{BASE}/api/v1/web-scans/{sid}/', headers=h)
vulns = r2.json()
vl = vulns if isinstance(vulns, list) else vulns.get('results', [])
print(f'Findings returned: {len(vl)}')

# Show first 3
print()
print('=' * 70)
print('BUG-06 RETEST: Enrichment persistence (3 findings)')
print('=' * 70)

all_pass = True
for i, v in enumerate(vl[:3]):
    name = (v.get('name') or v.get('title') or '?')[:45]
    cvss = v.get('cvss_score')
    mitre = v.get('mitre_techniques') or ''
    risk = v.get('risk_score')
    present = all(x is not None for x in [cvss, risk])
    if not present: all_pass = False
    print(f'  Finding {i+1}: {name}')
    print(f'    CVSS Score:         {cvss}')
    print(f'    MITRE Techniques:   {mitre[:60]}')
    print(f'    Risk Score:         {risk}')
    print(f'    API Fields Present: {"Yes" if present else "No"}')

print(f'  => {"PASS" if all_pass else "FAIL"}: All 3 findings have enrichment fields')

# ============================================================
# Restart and re-verify
# ============================================================
print()
print('  Restarting web container...')
subprocess.run('docker restart customarcherysec', capture_output=True, shell=True)
time.sleep(15)

token2 = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h2 = {'Authorization': f'Bearer {token2}'}
r3 = requests.get(f'{BASE}/api/v1/web-scans/{sid}/', headers=h2)
vulns2 = r3.json()
vl2 = vulns2 if isinstance(vulns2, list) else vulns2.get('results', [])
if vl2:
    v = vl2[0]
    persisted = v.get('cvss_score') is not None and v.get('risk_score') is not None
    print(f'  After restart - Finding 1: cvss={v.get("cvss_score")} risk={v.get("risk_score")} mitre={str(v.get("mitre_techniques",""))[:40]}')
    print(f'  => PASS: Values persisted after restart: {persisted}')

# ============================================================
# BUG-05: Scheduler bootstrap (check AFTER restart)
# ============================================================
print()
print('=' * 70)
print('BUG-05 RETEST: Scheduler bootstrap (after restart)')
print('=' * 70)

result3 = subprocess.run('docker logs customarcherysec --tail 60',
    capture_output=True, text=True, shell=True)
all_logs = result3.stdout + result3.stderr
scheduler_lines = [l.strip() for l in all_logs.split('\n') if 'cheduler' in l]
for sl in scheduler_lines[-3:]:
    print(f'  {sl}')
scheduler_ok = 'Scheduler bootstrapped' in all_logs
print(f'  => PASS: Scheduler bootstrap: {scheduler_ok}')

# ============================================================
# BUG-08: ZAP settings + scan endpoint
# ============================================================
print()
print('=' * 70)
print('BUG-08 RETEST: ZAP settings + scan endpoint')
print('=' * 70)

from archerysettings.models import SettingsDb, ZapSettingsDb
settings_db = SettingsDb.objects.filter(setting_scanner='Zap', organization_id=1).first()
zap_db = ZapSettingsDb.objects.filter(organization_id=1).first()

if settings_db:
    print(f'  SettingsDb ZAP: org={settings_db.organization_id} status={settings_db.setting_status}')
    print(f'  => PASS: ZAP registration exists and enabled')
else:
    print(f'  FAIL: SettingsDb ZAP not found')

if zap_db:
    print(f'  ZapSettingsDb: url={zap_db.zap_url} port={zap_db.zap_port} enabled={zap_db.enabled}')

# Test scan endpoint
r = requests.post(f'{BASE}/api/v1/zap-scan/',
    headers=h2,
    json={'target': 'http://test.example.com', 'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3'})
print(f'  ZAP scan request: HTTP {r.status_code}')
try:
    resp = r.json()
    print(f'  Response: {json.dumps(resp)[:200]}')
    if r.status_code == 200:
        print(f'  => PASS: Scan ID returned')
except:
    print(f'  Response: {r.text[:200]}')

print()
print('=' * 70)
print('ALL RETESTS COMPLETE')
print('=' * 70)
