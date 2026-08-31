import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from archeryapi.models import OrgAPIKey
from user_management.models import UserProfile

admin = UserProfile.objects.filter(is_superuser=True).first()
print(f'Admin: {admin.email} id={admin.id} org={admin.organization_id}')

# Create new API key for admin
import hashlib, secrets
key = secrets.token_hex(32)
org_key = OrgAPIKey.objects.create(
    api_key=key,
    created_by=admin,
    is_active=True,
    organization=admin.organization,
)
print(f'Created OrgAPIKey: {key}')
print(f'Active: {org_key.is_active}')
print(f'Org: {org_key.organization_id}')
