import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from user_management.models import UserProfile, UserRoles, Organization
from projects.models import ProjectDb
from archerysettings.models import SettingsDb, ZapSettingsDb

org = Organization.objects.first()
admin = UserProfile.objects.filter(is_superuser=True).first()
print(f'Org A: id={org.id} name={org.name}')
print(f'Admin: {admin.email}')

# Create Org B
org_b, created = Organization.objects.get_or_create(id=2, defaults={'name': 'Test Organization B'})
print(f'Org B: id={org_b.id} name={org_b.name} created={created}')

# Roles
role_map = {}
for role_name in ['Admin', 'Organization Admin', 'Analyst', 'User', 'Viewer']:
    r, _ = UserRoles.objects.get_or_create(role=role_name)
    role_map[role_name] = r

# Org B accounts
org_b_accounts = [
    ('testuserc@testorg2.com', 'Analyst', 2, True),
    ('testorgb@testorg.com', 'Organization Admin', 2, True),
]
for email, role_name, org_id, active in org_b_accounts:
    u, created = UserProfile.objects.get_or_create(
        email=email,
        defaults={'role': role_map[role_name], 'organization_id': org_id, 'is_active': active}
    )
    u.set_password('TestPass123!')
    u.role = role_map[role_name]
    u.organization_id = org_id
    u.is_active = active
    u.save()
    print(f'{"Created" if created else "Updated"}: {email}')

# Org B project
p3, _ = ProjectDb.objects.get_or_create(
    uu_id='b0000000-0000-0000-0000-000000000001',
    defaults={'project_name': 'Test Project C', 'project_disc': 'Org B Test', 'created_by': admin, 'organization': org_b}
)
print(f'Org B project ensured')

# ZAP settings
zap, _ = ZapSettingsDb.objects.get_or_create(
    organization=org,
    defaults={'zap_url': 'zapscanner', 'zap_port': 8090, 'zap_enabled': True}
)
settings, _ = SettingsDb.objects.get_or_create(
    setting_scanner='Zap',
    organization=org,
    defaults={'setting_status': True, 'created_by': admin, 'updated_by': admin}
)
print(f'SettingsDb ZAP: status={settings.setting_status}')

# Disabled user
u, created = UserProfile.objects.get_or_create(
    email='testdisabled@testorg.com',
    defaults={'role': role_map['Analyst'], 'organization_id': 1, 'is_active': False}
)
u.set_password('TestPass123!')
u.is_active = False
u.save()
print(f'Disabled user ensured')

print(f'\nTotal users: {UserProfile.objects.count()}')
print(f'Org A users: {UserProfile.objects.filter(organization_id=1).count()}')
print(f'Org B users: {UserProfile.objects.filter(organization_id=2).count()}')
