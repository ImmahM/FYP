import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from user_management.models import UserProfile, UserRoles, Organization

org = Organization.objects.get(name='default')

# Get or create roles
roles = {}
for r, d in [('Admin','Admin'), ('Analyst','Analyst'), ('Viewer','Viewer'), ('Organization Admin','Org Admin')]:
    obj, _ = UserRoles.objects.get_or_create(role=r, defaults={'description': d})
    roles[r] = obj

# Create test accounts
accounts = [
    ('testadmin@testorg.com', 'TestAdmin1!', 'Admin', 'Organization Admin'),
    ('testorgadmin@testorg.com', 'TestOrgAdmin1!', 'Organization Admin', 'Organization Admin'),
    ('testusera@testorg.com', 'TestUserA1!', 'Analyst', 'Organization Admin'),
    ('testuserb@testorg.com', 'TestUserB1!', 'Analyst', 'Organization Admin'),
]

for email, pw, role_name, _ in accounts:
    if not UserProfile.objects.filter(email=email).exists():
        role = roles[role_name]
        UserProfile.objects.create_user(
            email=email, name=email.split('@')[0],
            password=pw, role=role.id, organization=org.id
        )
        print(f'Created: {email} ({role_name})')
    else:
        print(f'Exists:  {email}')

# Create Org B and users
org_b, _ = Organization.objects.get_or_create(
    name='Test Organization B',
    defaults={'description': 'Test Org B', 'logo': 'default', 'contact': '', 'address': ''}
)

for email, pw, role_name in [('testuserc@testorg2.com', 'TestUserC1!', 'Analyst'), ('testorgb@testorg.com', 'TestOrgB1!', 'Organization Admin')]:
    if not UserProfile.objects.filter(email=email).exists():
        role = roles[role_name]
        UserProfile.objects.create_user(
            email=email, name=email.split('@')[0],
            password=pw, role=role.id, organization=org_b.id
        )
        print(f'Created: {email} ({role_name}, OrgB)')
    else:
        print(f'Exists:  {email}')

# Create disabled user
email = 'testdisabled@testorg.com'
if not UserProfile.objects.filter(email=email).exists():
    role = roles['Analyst']
    u = UserProfile.objects.create_user(
        email=email, name='testdisabled',
        password='TestDisabled1!', role=role.id, organization=org.id
    )
    u.is_active = False
    u.save(update_fields=['is_active'])
    print(f'Created disabled: {email}')
else:
    print(f'Exists:  {email}')

# Create Org B project
from projects.models import ProjectDb
from datetime import datetime
admin = UserProfile.objects.get(email='immah@gmail.com')
if not ProjectDb.objects.filter(project_name='Test Project C').exists():
    ProjectDb.objects.create(
        project_name='Test Project C',
        project_disc='Org B test project',
        organization=org_b,
        created_by=admin,
        date_time=datetime.now(),
    )
    print('Created: Test Project C (OrgB)')
else:
    print('Exists:  Test Project C')

print(f'\nTotal users: {UserProfile.objects.count()}')
print(f'Total projects: {ProjectDb.objects.count()}')
