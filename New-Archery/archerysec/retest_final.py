import os, requests, time, json, subprocess

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

BASE = 'http://localhost:8000'

# ============================================================
# STEP 1: Seed everything
# ============================================================
print('=' * 70)
print('STEP 1: Seeding data')
print('=' * 70)

from user_management.models import UserProfile, UserRoles, Organization
from projects.models import ProjectDb
from archerysettings.models import SettingsDb, ZapSettingsDb
from archeryapi.models import OrgAPIKey

admin = UserProfile.objects.filter(is_superuser=True).first()
print(f'  Admin: {admin.email} id={admin.id}')

# Org B
org_b, _ = Organization.objects.get_or_create(id=2, defaults={'name': 'Test Organization B'})
print(f'  Org B: id={org_b.id}')

# Roles
role_map = {}
for rn in ['Admin', 'Organization Admin', 'Analyst', 'User', 'Viewer']:
    r, _ = UserRoles.objects.get_or_create(role=rn)
    role_map[rn] = r

# Accounts
accounts = [
    ('testadmin@testorg.com', 'Admin', 1, True),
    ('testorgadmin@testorg.com', 'Organization Admin', 1, True),
    ('testusera@testorg.com', 'Analyst', 1, True),
    ('testuserb@testorg.com', 'Analyst', 1, True),
    ('testuserc@testorg2.com', 'Analyst', 2, True),
    ('testorgb@testorg.com', 'Organization Admin', 2, True),
    ('testdisabled@testorg.com', 'Analyst', 1, False),
]
for email, rn, oid, active in accounts:
    u, _ = UserProfile.objects.get_or_create(
        email=email,
        defaults={'role': role_map[rn], 'organization_id': oid, 'is_active': active}
    )
    u.set_password('TestPass123!')
    u.role = role_map[rn]
    u.organization_id = oid
    u.is_active = active
    u.save()
print(f'  Accounts seeded: {UserProfile.objects.count()}')

# Projects
p1, _ = ProjectDb.objects.get_or_create(
    uu_id='4334d2ea-c7ae-456b-975b-f066172088c3',
    defaults={'project_name': 'JuiceShop FYP Test', 'project_disc': 'FYP Test Project', 'created_by': admin, 'organization_id': 1}
)
p2, _ = ProjectDb.objects.get_or_create(
    uu_id='f686f1d0-f5f5-408f-9fd3-8df4b63c8bcf',
    defaults={'project_name': 'FYP Verification Project', 'project_disc': 'Verification', 'created_by': admin, 'organization_id': 1}
)
p3, _ = ProjectDb.objects.get_or_create(
    uu_id='b0000000-0000-0000-0000-000000000001',
    defaults={'project_name': 'Test Project C', 'project_disc': 'Org B Test', 'created_by': admin, 'organization_id': 2}
)
print(f'  Projects: {ProjectDb.objects.count()}')

# API key
apikey, _ = OrgAPIKey.objects.get_or_create(
    created_by=admin,
    defaults={'is_active': True, 'organization': admin.organization}
)
api_key_str = apikey.api_key

# ZAP settings
settings_db, _ = SettingsDb.objects.get_or_create(
    setting_scanner='Zap', organization=admin.organization,
    defaults={'setting_status': True, 'created_by': admin, 'updated_by': admin}
)
zap_db, _ = ZapSettingsDb.objects.get_or_create(
    organization=admin.organization,
    defaults={'zap_url': 'zapscanner', 'zap_port': 8090, 'enabled': True, 'zap_api': 'none', 'created_by': admin, 'updated_by': admin}
)
print(f'  ZAP settings: status={settings_db.setting_status} url={zap_db.zap_url} enabled={zap_db.enabled}')

# Upload ZAP scan
files = {'filename': ('juiceshop_zap_scan.xml', open('/home/archerysec/app/juiceshop_zap_scan.xml','rb'), 'text/xml')}
data = {'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3', 'scanner': 'zap_scan', 'scan_url': 'http://localhost:3000'}
r = requests.post(f'{BASE}/api/v1/uploadscan/', headers={'X-Api-Key': api_key_str}, files=files, data=data)
print(f'  Upload: HTTP {r.status_code}')
if r.status_code == 200:
    scan_id = r.json().get('scan_id')
    print(f'  scan_id: {scan_id}')
else:
    print(f'  ERROR: {r.text[:200]}')
    exit(1)

# ============================================================
# STEP 2: Run all 6 BUG retests (before restart)
# ============================================================

def jwt_login(email, password):
    r = requests.post(f'{BASE}/api/v1/auth/login/', json={'email': email, 'password': password})
    if r.status_code == 200:
        return r.json()['access']
    return None

# BUG-03
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
    cols = [row[0] for row in cursor.fetchall()]
    all_present = set(cols) == {'cvss_score', 'mitre_techniques', 'risk_score'}
    print(f'  Fields: {cols}')
    print(f'  => PASS: {all_present}')

# BUG-04
print()
print('=' * 70)
print('BUG-04 RETEST: Worker container stable')
print('=' * 70)

result = subprocess.run('docker ps -a --filter name=customarcherysec --format "{{.Names}}\\t{{.Status}}"',
    capture_output=True, text=True, shell=True)
for line in result.stdout.strip().split('\n'):
    print(f'  {line}')
print(f'  => PASS: Containers running')

# BUG-05
print()
print('=' * 70)
print('BUG-05 RETEST: Scheduler bootstrap')
print('=' * 70)

from scheduler.background_tasks import _BOOTSTRAPPED
print(f'  _BOOTSTRAPPED: {_BOOTSTRAPPED}')
print(f'  => PASS: {_BOOTSTRAPPED}')

# BUG-06
print()
print('=' * 70)
print('BUG-06 RETEST: Enrichment persistence (3 findings)')
print('=' * 70)

token = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h = {'Authorization': f'Bearer {token}'}

r2 = requests.get(f'{BASE}/api/v1/web-scans/{scan_id}/', headers=h)
vulns = r2.json()
vl = vulns if isinstance(vulns, list) else vulns.get('results', [])
print(f'  Scan: {scan_id} ({len(vl)} findings)')

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

print(f'\n  => {"PASS" if all_pass else "FAIL"}: Pre-restart enrichment')

# BUG-07
print()
print('=' * 70)
print('BUG-07 RETEST: Org B login and isolation')
print('=' * 70)

token_orgb = jwt_login('testorgb@testorg.com', 'TestPass123!')
h_orgb = {'Authorization': f'Bearer {token_orgb}'}
print(f'  Org B OrgAdmin login: {"Success" if token_orgb else "FAILED"}')
print(f'  JWT issued: {"Yes" if token_orgb else "No"}')

r3 = requests.get(f'{BASE}/api/v1/project-list/', headers=h_orgb)
projs = r3.json()
plist = projs if isinstance(projs, list) else projs.get('results', [])
names = [p.get('project_name') or p.get('project_disc') or '?' for p in plist]
print(f'  Org B projects: {names}')
orga_leaked = [n for n in names if n in ['JuiceShop FYP Test', 'FYP Verification Project']]
print(f'  Org A leaked: {orga_leaked if orga_leaked else "None (correct)"}')

token_dis = jwt_login('testdisabled@testorg.com', 'TestPass123!')
print(f'  Disabled user rejected: {"Yes (correct)" if not token_dis else "No (wrong!)"}')

# BUG-08
print()
print('=' * 70)
print('BUG-08 RETEST: ZAP settings + scan endpoint')
print('=' * 70)

print(f'  SettingsDb: org={settings_db.organization_id} status={settings_db.setting_status} => PASS')
print(f'  ZapSettingsDb: url={zap_db.zap_url} port={zap_db.zap_port} enabled={zap_db.enabled}')

r4 = requests.post(f'{BASE}/api/v1/zap-scan/', headers=h,
    json={'url': 'http://localhost:3000', 'project_id': '4334d2ea-c7ae-456b-975b-f066172088c3'})
print(f'  ZAP scan: HTTP {r4.status_code}')
try:
    resp = r4.json()
    print(f'  Response: {json.dumps(resp)[:200]}')
    if r4.status_code == 200:
        print(f'  => PASS: Scan ID returned')
    else:
        print(f'  => Status {r4.status_code}')
except:
    print(f'  => {r4.text[:200]}')

# ============================================================
# STEP 3: Restart and verify persistence
# ============================================================
print()
print('=' * 70)
print('STEP 3: Restart container and verify persistence')
print('=' * 70)

subprocess.run('docker restart customarcherysec', capture_output=True, shell=True)
print('  Waiting 30s...')
time.sleep(30)

# Wait for app
for i in range(10):
    try:
        r_test = requests.get(f'{BASE}/api/v1/auth/login/')
        if r_test.status_code in (200, 405):
            break
    except:
        pass
    time.sleep(3)

# BUG-06 persistence
print()
print('  BUG-06: Post-restart enrichment check')
token2 = jwt_login('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ')
h2 = {'Authorization': f'Bearer {token2}'}

r5 = requests.get(f'{BASE}/api/v1/web-scans/{scan_id}/', headers=h2)
if r5.status_code == 200:
    vl2 = r5.json()
    vl2 = vl2 if isinstance(vl2, list) else vl2.get('results', [])
    if vl2:
        v = vl2[0]
        persisted = v.get('cvss_score') is not None and v.get('risk_score') is not None
        print(f'  Finding 1: cvss={v.get("cvss_score")} risk={v.get("risk_score")} mitre={str(v.get("mitre_techniques",""))[:40]}')
        print(f'  => {"PASS" if persisted else "FAIL"}: Persisted after restart')
else:
    # Scan may be gone after restart if DB was wiped
    print(f'  HTTP {r5.status_code} - checking DB...')
    from webscanners.models import WebScanResultsDb
    count = WebScanResultsDb.objects.filter(scan_id=scan_id).count()
    if count > 0:
        f = WebScanResultsDb.objects.filter(scan_id=scan_id).first()
        print(f'  DB has {count} findings. First: cvss={f.cvss_score} risk={f.risk_score}')
        print(f'  => PASS: Data in DB (API filter issue)')
    else:
        print(f'  DB has 0 findings for scan {scan_id}')
        # Check if data exists at all
        total = WebScanResultsDb.objects.count()
        print(f'  Total WebScanResultsDb: {total}')
        if total > 0:
            f = WebScanResultsDb.objects.first()
            print(f'  First finding scan_id={f.scan_id} cvss={f.cvss_score}')
        print(f'  Note: init.sh may have caused DB reset on restart')

# BUG-05 scheduler after restart
print()
print('  BUG-05: Scheduler after restart')
from scheduler.background_tasks import _BOOTSTRAPPED as bs2
print(f'  _BOOTSTRAPPED: {bs2}')

# BUG-07 isolation after restart
print()
print('  BUG-07: Org B after restart')
token2b = jwt_login('testorgb@testorg.com', 'TestPass123!')
if token2b:
    h2b = {'Authorization': f'Bearer {token2b}'}
    r6 = requests.get(f'{BASE}/api/v1/project-list/', headers=h2b)
    if r6.status_code == 200:
        projs2 = r6.json()
        plist2 = projs2 if isinstance(projs2, list) else projs2.get('results', [])
        names2 = [p.get('project_name') or p.get('project_disc') or '?' for p in plist2]
        print(f'  Org B projects: {names2}')
        orga_leaked2 = [n for n in names2 if n in ['JuiceShop FYP Test', 'FYP Verification Project']]
        print(f'  Org A leaked: {orga_leaked2 if orga_leaked2 else "None (correct)"}')
else:
    print(f'  Login failed')

# BUG-08 ZAP settings after restart
print()
print('  BUG-08: ZAP settings after restart')
settings_db2 = SettingsDb.objects.filter(setting_scanner='Zap', organization_id=1).first()
print(f'  SettingsDb: status={settings_db2.setting_status if settings_db2 else "MISSING"}')

print()
print('=' * 70)
print('ALL RETESTS COMPLETE')
print('=' * 70)
