import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from webscanners.models import WebScansDb, WebScanResultsDb
from user_management.models import UserProfile

admin = UserProfile.objects.filter(is_superuser=True).first()
print(f'Admin: id={admin.id} email={admin.email}')

print(f'\nWebScansDb total: {WebScansDb.objects.count()}')
for s in WebScansDb.objects.all():
    print(f'  scan_id={s.scan_id} created_by={s.created_by_id} url={s.scan_url} vulns={s.total_vul}')

print(f'\nWebScanResultsDb total: {WebScanResultsDb.objects.count()}')
print(f'  with cvss: {WebScanResultsDb.objects.filter(cvss_score__isnull=False).count()}')
print(f'  with risk: {WebScanResultsDb.objects.filter(risk_score__isnull=False).count()}')

# Check if scan 0010457a findings exist
new_sid = '0010457a-7673-47bf-9269-c30cc69cab5b'
findings = WebScanResultsDb.objects.filter(scan_id=new_sid)
print(f'\nScan {new_sid}: {findings.count()} findings')
if findings.exists():
    f = findings.first()
    print(f'  First: title={f.title[:30]} cvss={f.cvss_score} risk={f.risk_score} created_by={f.created_by_id}')
