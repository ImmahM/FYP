import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from projects.models import ProjectDb
from user_management.models import UserProfile

admin = UserProfile.objects.filter(is_superuser=True).first()

# Create the correct project with the known UUID
import uuid
target_uuid = '4334d2ea-c7ae-456b-975b-f066172088c3'

# Delete wrong UUID projects if needed, or just create the right one
p, created = ProjectDb.objects.get_or_create(
    uu_id=target_uuid,
    defaults={
        'project_name': 'JuiceShop FYP Test',
        'project_disc': 'FYP Test Project',
        'created_by': admin,
        'organization_id': 1,
    }
)
if not created:
    p.project_name = 'JuiceShop FYP Test'
    p.project_disc = 'FYP Test Project'
    p.created_by = admin
    p.organization_id = 1
    p.save()

print(f'Project: uuid={p.uu_id} name={p.project_name} created={created}')

# Also create FYP Verification Project
p2, created2 = ProjectDb.objects.get_or_create(
    uu_id='f686f1d0-f5f5-408f-9fd3-8df4b63c8bcf',
    defaults={
        'project_name': 'FYP Verification Project',
        'project_disc': 'Verification',
        'created_by': admin,
        'organization_id': 1,
    }
)
print(f'Project 2: uuid={p2.uu_id} name={p2.project_name} created={created2}')

# List all
for p in ProjectDb.objects.all():
    print(f'  id={p.id} uuid={p.uu_id} name={p.project_name} org={p.organization_id}')
