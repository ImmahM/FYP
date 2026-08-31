import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from projects.models import ProjectDb

print('Projects:')
for p in ProjectDb.objects.all():
    print(f'  id={p.id} uuid={p.uu_id} name={p.project_name} org={p.organization_id}')

# Check scheduler model
try:
    from webscanners.models import WebScansDb
    print(f'\nWebScansDb count: {WebScansDb.objects.count()}')
except Exception as e:
    print(f'Error: {e}')

# Check the scheduler package
import scheduler
print(f'\nscheduler dir: {dir(scheduler)}')
import scheduler.background_tasks as bt
print(f'bg_tasks dir: {[x for x in dir(bt) if not x.startswith("_")]}')
