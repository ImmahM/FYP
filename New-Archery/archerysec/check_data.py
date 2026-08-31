import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.production')
import django
django.setup()

from user_management.models import UserProfile
from projects.models import ProjectDb
from webscanners.models import WebScanResultsDb, WebScansDb

print(f'Users: {UserProfile.objects.count()}')
print(f'Projects: {ProjectDb.objects.count()}')
print(f'WebScansDb: {WebScansDb.objects.count()}')
print(f'WebScanResultsDb: {WebScanResultsDb.objects.count()}')

# Check enrichment fields exist in DB schema
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'webscanResultsdb'
        AND column_name IN ('cvss_score', 'mitre_techniques', 'risk_score')
        ORDER BY column_name
    """)
    cols = [r[0] for r in cursor.fetchall()]
    print(f'\nEnrichment fields in DB: {cols}')

    cursor.execute("SELECT app, name FROM django_migrations WHERE name LIKE '%0038%' OR name LIKE '%0029%'")
    migs = cursor.fetchall()
    print(f'Migrations 0029/0038: {migs}')
