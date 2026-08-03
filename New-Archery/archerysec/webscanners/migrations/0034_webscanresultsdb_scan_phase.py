from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("webscanners", "0033_webscansdb_scan_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="webscanresultsdb",
            name="scan_phase",
            field=models.CharField(max_length=16, null=True, blank=True),
        ),
    ]

