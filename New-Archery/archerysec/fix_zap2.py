import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from archerysettings.models import SettingsDb
from user_management.models import Organization, UserProfile

org = Organization.objects.first()
admin = UserProfile.objects.filter(is_superuser=True).first()

settings = SettingsDb.objects.filter(organization=org, setting_scanner='Zap')
print(f'Zap connector settings count: {settings.count()}')
for s in settings:
    print(f'  id={s.id} status={s.setting_status} scanner={s.setting_scanner}')

if not settings.exists():
    SettingsDb.objects.create(
        setting_scanner='Zap',
        setting_status=True,
        organization=org,
        created_by=admin,
        updated_by=admin,
    )
    print('Created Zap connector setting with status=True')
else:
    settings.update(setting_status=True)
    print('Updated existing Zap connector to status=True')
