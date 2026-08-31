import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from archerysettings.models import ZapSettingsDb
from user_management.models import Organization, UserProfile

org = Organization.objects.first()
admin = UserProfile.objects.filter(is_superuser=True).first()
print(f'Org: {org.id}, Admin: {admin.email}')

zs = ZapSettingsDb.objects.filter(organization=org).first()
if zs:
    print(f'ZAP settings: url={zs.zap_url}, port={zs.zap_port}, enabled={zs.enabled}, api={zs.zap_api}')
    zs.enabled = True
    zs.zap_url = 'zapscanner'
    zs.zap_port = 8090
    zs.save(update_fields=['enabled', 'zap_url', 'zap_port'])
    print('Fixed ZAP settings')
else:
    ZapSettingsDb.objects.create(
        zap_url='zapscanner',
        zap_api='none',
        zap_port=8090,
        enabled=True,
        organization=org,
        created_by=admin,
        updated_by=admin,
    )
    print('Created ZAP settings')
