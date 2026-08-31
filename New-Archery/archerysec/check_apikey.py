import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from archeryapi.models import OrgAPIKey, APIKeys

print('OrgAPIKey entries:')
for k in OrgAPIKey.objects.all():
    print(f'  id={k.id} key={k.api_key[:20]}... active={k.is_active} created_by={k.created_by_id}')

print('\nAPIKeys entries:')
for k in APIKeys.objects.all():
    print(f'  id={k.id} key={k.api_key[:20]}... user={k.user_id}')

# Check if the key we've been using exists in either table
OUR_KEY = '2e3157c4eb252b7aa7b52502ea1c794bbabc1cfb877861be14c099445c54c81f'
ok1 = OrgAPIKey.objects.filter(api_key=OUR_KEY).first()
ok2 = APIKeys.objects.filter(api_key=OUR_KEY).first()
print(f'\nOur key in OrgAPIKey: {ok1 is not None}')
print(f'Our key in APIKeys: {ok2 is not None}')
