import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from webscanners.models import WebScanResultsDb

# Check the NEW upload scan (0010457a)
new_sid = '0010457a-7673-47bf-9269-c30cc69cab5b'
findings = WebScanResultsDb.objects.filter(scan_id=new_sid)
print(f'New scan ({new_sid}): {findings.count()} findings')
for f in findings[:3]:
    print(f'  title={f.title[:40]} sev={f.severity} cvss={f.cvss_score} mitre={str(f.mitre_techniques or "")[:30]} risk={f.risk_score}')

# Check old scan
old_sid = 'ba75a0f4-0150-4a00-aa72-b1323546cff3'
findings2 = WebScanResultsDb.objects.filter(scan_id=old_sid)
print(f'\nOld scan ({old_sid}): {findings2.count()} findings')
for f in findings2[:3]:
    print(f'  title={f.title[:40]} sev={f.severity} cvss={f.cvss_score} mitre={str(f.mitre_techniques or "")[:30]} risk={f.risk_score}')
