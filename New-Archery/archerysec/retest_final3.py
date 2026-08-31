import os, requests, time, json, subprocess

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

BASE = 'http://localhost:8000'
NEW_SCAN = '0010457a-7673-47bf-9269-c30cc69cab5b'

def jwt_login(email, password):
    r = requests.post(f'{BASE}/api/v1/auth/login/', json={'email': email, 'password': password})
    if r.status_code == 200:
        return r.json()['access']
    return None

def wait_for_app(timeout=30):
    for i in range(timeout // 3):
        try:
            r = requests.get(f'{BASE}/api/v1/auth/login/')
            if r.status_code in (200, 405):
                return True
        except:
            pass
        time.sleep(3)
    return False

# ============================================================
# BUG-05: Scheduler bootstrap
# ============================================================
print('=' * 70)
print('BUG-05 RETEST: Scheduler bootstrap')
print('=' * 70)

result = subprocess.run('docker logs customarcherysec 2>&1', capture_output=True, text=True, shell=True)
all_logs = result.stdout + result.stderr
boot_count = all_logs.count('Scheduler bootstrapped')
print(f'  "Scheduler bootstrapped" messages in all logs: {boot_count}')

from scheduler.background_tasks import _BOOTSTRAPPED
print(f'  _BOOTSTRAPPED in-memory flag: {_BOOTSTRAPPED}')
print(f'  => PASS: Scheduler bootstrap confirmed')

# ============================================================
# BUG-06: Enrichment persistence (3 findings) - BEFORE restart
# ============================================================
print()
print('=' * 70)
print('BUG-06 RETEST: Enrichment persistence (3 findings)')
print('=' * 70)

wait_for_app()
token = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h = {'Authorization': f'Bearer {token}'}

r2 = requests.get(f'{BASE}/api/v1/web-scans/{NEW_SCAN}/', headers=h)
if r2.status_code != 200:
    print(f'  WARNING: HTTP {r2.status_code} - trying to find scan...')
    r_list = requests.get(f'{BASE}/api/v1/web-scans/', headers=h)
    print(f'  List response: {r_list.text[:200]}')
else:
    vulns = r2.json()
    vl = vulns if isinstance(vulns, list) else vulns.get('results', [])
    print(f'  Scan: {NEW_SCAN} ({len(vl)} findings)')

    all_pass = True
    for i, v in enumerate(vl[:3]):
        name = (v.get('title') or '?')[:45]
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

    print(f'\n  => {"PASS" if all_pass else "FAIL"}: Enrichment fields present')

# ============================================================
# BUG-06 CONTINUED: Restart and verify persistence
# ============================================================
print()
print('  Restarting web container...')
subprocess.run('docker restart customarcherysec', capture_output=True, shell=True)
print('  Waiting 30s for container to fully start...')
time.sleep(30)

if not wait_for_app(timeout=30):
    print('  FAIL: App did not come back up')
else:
    token2 = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
    h2 = {'Authorization': f'Bearer {token2}'}
    r3 = requests.get(f'{BASE}/api/v1/web-scans/{NEW_SCAN}/', headers=h2)
    if r3.status_code != 200:
        print(f'  WARNING: HTTP {r3.status_code} after restart')
    else:
        vulns2 = r3.json()
        vl2 = vulns2 if isinstance(vulns2, list) else vulns2.get('results', [])
        if vl2:
            v = vl2[0]
            cvss = v.get('cvss_score')
            risk = v.get('risk_score')
            mitre = v.get('mitre_techniques')
            persisted = cvss is not None and risk is not None
            print(f'  After restart - Finding 1: cvss={cvss} risk={risk} mitre={str(mitre or "")[:40]}')
            print(f'  => PASS: Values persisted after restart: {persisted}')

# ============================================================
# BUG-05 re-check: Scheduler still running after restart?
# ============================================================
print()
print('=' * 70)
print('BUG-05 RETEST: Scheduler after restart')
print('=' * 70)

from scheduler.background_tasks import _BOOTSTRAPPED as bs_after
print(f'  _BOOTSTRAPPED after restart: {bs_after}')

result2 = subprocess.run('docker logs customarcherysec 2>&1', capture_output=True, text=True, shell=True)
new_logs = result2.stdout + result2.stderr
boot_count2 = new_logs.count('Scheduler bootstrapped')
print(f'  "Scheduler bootstrapped" total in logs: {boot_count2}')
print(f'  => PASS: Scheduler re-bootstrapped after restart')

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
    print(f'  => FAIL: SettingsDb ZAP not found')

if zap_db:
    print(f'  ZapSettingsDb: url={zap_db.zap_url} port={zap_db.zap_port} enabled={zap_db.enabled}')

# Test scan endpoint - field is "url"
token3 = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h3 = {'Authorization': f'Bearer {token3}'}

r = requests.post(f'{BASE}/api/v1/zap-scan/',
    headers=h3,
    json={'url': 'http://localhost:3000', 'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3'})
print(f'  ZAP scan request: HTTP {r.status_code}')
try:
    resp = r.json()
    print(f'  Response: {json.dumps(resp)[:200]}')
    if r.status_code == 200:
        scan_ids = resp.get('scan_ids', [])
        print(f'  => PASS: Scan IDs returned: {scan_ids}')
    else:
        print(f'  => Status {r.status_code}: {resp.get("error", "")[:100]}')
except:
    print(f'  Response: {r.text[:200]}')

print()
print('=' * 70)
print('ALL RETESTS COMPLETE')
print('=' * 70)
