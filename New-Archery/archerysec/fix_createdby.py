import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from user_management.models import UserProfile
from webscanners.models import WebScansDb

user = UserProfile.objects.get(email='immah@gmail.com')
updated = WebScansDb.objects.filter(created_by__isnull=True).update(created_by=user)
print(f'Updated {updated} WebScansDb records with created_by={user.email}')
