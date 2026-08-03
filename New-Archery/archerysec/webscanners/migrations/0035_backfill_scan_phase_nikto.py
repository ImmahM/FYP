from django.db import migrations


def set_nikto_phase(apps, schema_editor):
    WebScanResultsDb = apps.get_model('webscanners', 'WebScanResultsDb')
    WebScanResultsDb.objects.filter(scanner='Nikto', scan_phase__isnull=True).update(scan_phase='Nikto')


class Migration(migrations.Migration):
    dependencies = [
        ("webscanners", "0034_webscanresultsdb_scan_phase"),
    ]

    operations = [
        migrations.RunPython(set_nikto_phase, migrations.RunPython.noop),
    ]

