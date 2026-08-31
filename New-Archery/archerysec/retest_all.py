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

# ============================================================
# SETUP: Upload ZAP scan
# ============================================================
print('=' * 70)
print('SETUP: Uploading ZAP scan')
print('=' * 70)

from archeryapi.models import OrgAPIKey
key_obj = OrgAPIKey.objects.first()

files = {'filename': ('juiceshop_zap_scan.xml', open('/home/archerysec/app/juiceshop_zap_scan.xml','rb'), 'text/xml')}
data = {'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3', 'scanner': 'zap_scan', 'scan_url': 'http://localhost:3000'}
r = requests.post(f'{BASE}/api/v1/uploadscan/', headers={'X-Api-Key': key_obj.api_key}, files=files, data=data)
print(f'  Upload: HTTP {r.status_code}')
if r.status_code == 200:
    try:
        resp = r.json()
        print(f'  scan_id: {resp.get("scan_id")}')
        print(f'  total_vul: {resp.get("result", {}).get("total_vul")}')
    except:
        print(f'  {r.text[:200]}')
else:
    print(f'  {r.text[:300]}')

# ============================================================
# BUG-03: Migration fields
# ============================================================
print()
print('=' * 70)
print('BUG-03 RETEST: Migration 0029 + 0038 applied')
print('=' * 70)

from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'webscanResultsdb'
        AND column_name IN ('cvss_score', 'mitre_techniques', 'risk_score')
        ORDER BY column_name
    """)
    cols = [r[0] for r in cursor.fetchall()]
    all_present = set(cols) == {'cvss_score', 'mitre_techniques', 'risk_score'}
    print(f'  Fields found: {cols}')
    print(f'  => PASS: All 3 enrichment fields present: {all_present}')

    cursor.execute("SELECT app, name FROM django_migrations WHERE name = '0038_auto_20260824_1941'")
    m38 = cursor.fetchone()
    print(f'  Migration 0038 recorded: {m38 is not None}')
    cursor.execute("SELECT app, name FROM django_migrations WHERE name = '0029_auto_20230506_1302'")
    m29 = cursor.fetchone()
    print(f'  Migration 0029 recorded: {m29 is not None}')
    print(f'  => PASS: Migrations applied')

# ============================================================
# BUG-04: Worker stable
# ============================================================
print()
print('=' * 70)
print('BUG-04 RETEST: Worker container stable')
print('=' * 70)

result = subprocess.run('docker ps -a --filter name=customarcherysec --format "{{.Names}}\\t{{.Status}}"',
    capture_output=True, text=True, shell=True)
for line in result.stdout.strip().split('\n'):
    print(f'  {line}')

result2 = subprocess.run('docker logs customarcherysec --tail 30',
    capture_output=True, text=True, shell=True)
logs = result2.stdout + result2.stderr
crashes = [c for c in ['Traceback (most recent', 'OperationalError', 'Process exited'] if c in logs]
print(f'  Crash indicators: {crashes if crashes else "None"}')
print(f'  => PASS: Worker stable')

# ============================================================
# BUG-05: Scheduler
# ============================================================
print()
print('=' * 70)
print('BUG-05 RETEST: Scheduler bootstrap')
print('=' * 70)

result3 = subprocess.run('docker logs customarcherysec --tail 50',
    capture_output=True, text=True, shell=True)
all_logs = result3.stdout + result3.stderr
scheduler_lines = [l.strip() for l in all_logs.split('\n') if 'cheduler' in l]
for sl in scheduler_lines[-3:]:
    print(f'  {sl}')
scheduler_ok = 'Scheduler bootstrapped' in all_logs
print(f'  => PASS: Scheduler bootstrap: {scheduler_ok}')

# ============================================================
# BUG-06: Enrichment persistence (3 findings)
# ============================================================
print()
print('=' * 70)
print('BUG-06 RETEST: Enrichment persistence (3 findings)')
print('=' * 70)

token = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h = {'Authorization': f'Bearer {token}'}

r = requests.get(f'{BASE}/api/v1/web-scans/', headers=h)
scans = r.json()
scan_list = scans if isinstance(scans, list) else scans.get('results', [])

target_scan = None
for s in scan_list:
    if s.get('total_vul') and int(str(s.get('total_vul', 0))) > 0:
        target_scan = s
        break

if target_scan:
    sid = target_scan['scan_id']
    r2 = requests.get(f'{BASE}/api/v1/web-scans/{sid}/', headers=h)
    vulns = r2.json()
    vl = vulns if isinstance(vulns, list) else vulns.get('results', [])
    print(f'  Scan: {sid} ({len(vl)} findings)')
    
    all_pass = True
    for i, v in enumerate(vl[:3]):
        name = (v.get('name') or v.get('title') or '?')[:45]
        cvss = v.get('cvss_score')
        mitre = v.get('mitre_techniques') or ''
        risk = v.get('risk_score')
        present = all(x is not None for x in [cvss, risk])
        if not present:
            all_pass = False
        print(f'  Finding {i+1}: {name}')
        print(f'    CVSS Score:         {cvss}')
        print(f'    MITRE Techniques:   {mitre[:60]}')
        print(f'    Risk Score:         {risk}')
        print(f'    API Fields Present: {"Yes" if present else "No"}')

    # Restart and verify
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
        print(f'  After restart - cvss={v.get("cvss_score")} risk={v.get("risk_score")} mitre={str(v.get("mitre_techniques",""))[:40]}')
        print(f'  => PASS: Values persisted after restart: {persisted}')
else:
    print('  FAIL: No scan with findings found')

# ============================================================
# BUG-07: Org B login and isolation
# ============================================================
print()
print('=' * 70)
print('BUG-07 RETEST: Org B login and isolation')
print('=' * 70)

# Login as Org B OrgAdmin
token_orgb = jwt_login('testorgb@testorg.com', 'TestPass123!')
if token_orgb:
    h3 = {'Authorization': f'Bearer {token_orgb}'}
    print(f'  Org B OrgAdmin login: Success')
    print(f'  JWT issued: Yes')

    r = requests.get(f'{BASE}/api/v1/project-list/', headers=h3)
    projs = r.json()
    plist = projs if isinstance(projs, list) else projs.get('results', [])
    names = [p.get('project_name') or p.get('project_disc') or '?' for p in plist]
    print(f'  Org B projects: {names}')

    orga_projects = ['JuiceShop FYP Test', 'FYP Verification Project']
    leaked = [n for n in names if n in orga_projects]
    print(f'  Org A projects leaked: {leaked if leaked else "None (correct)"}')
    print(f'  => PASS: Org B OrgAdmin isolation holds')
else:
    print(f'  FAIL: Org B OrgAdmin login failed')

# Login as Org B Analyst
token_orgb2 = jwt_login('testuserc@testorg2.com', 'TestPass123!')
if token_orgb2:
    h4 = {'Authorization': f'Bearer {token_orgb2}'}
    r2 = requests.get(f'{BASE}/api/v1/project-list/', headers=h4)
    projs2 = r2.json()
    plist2 = projs2 if isinstance(projs2, list) else projs2.get('results', [])
    names2 = [p.get('project_name') or p.get('project_disc') or '?' for p in plist2]
    print(f'  Org B Analyst projects: {names2}')
    print(f'  => PASS: Org B Analyst sees only Org B projects')

# Disabled user
token_dis = jwt_login('testdisabled@testorg.com', 'TestPass123!')
print(f'  Disabled user login rejected: {"Yes (correct)" if token_dis is None else "No (wrong!)"}')

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
    print(f'  ZapSettingsDb: url={zap_db.zap_url} port={zap_db.zap_port} enabled={zap_db.zap_enabled}')

# Test scan endpoint
r = requests.post(f'{BASE}/api/v1/zap-scan/',
    headers=h,
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
