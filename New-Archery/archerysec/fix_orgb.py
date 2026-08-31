import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from user_management.models import UserProfile

# Reset ALL test accounts to known password
accounts = [
    'testadmin@testorg.com',
    'testorgadmin@testorg.com',
    'testusera@testorg.com',
    'testuserb@testorg.com',
    'testuserc@testorg2.com',
    'testorgb@testorg.com',
    'testdisabled@testorg.com',
]
for email in accounts:
    try:
        u = UserProfile.objects.get(email=email)
        u.set_password('TestPass123!')
        u.is_active = True  # ensure all active except disabled
        u.save()
        print(f'Reset: {email} (org={u.organization_id}, role={u.role})')
    except UserProfile.DoesNotExist:
        print(f'NOT FOUND: {email}')

# Disable the disabled user
try:
    u = UserProfile.objects.get(email='testdisabled@testorg.com')
    u.is_active = False
    u.save()
    print(f'\nDisabled: testdisabled@testorg.com')
except:
    pass
