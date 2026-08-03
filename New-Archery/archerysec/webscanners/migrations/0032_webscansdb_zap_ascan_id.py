from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webscanners', '0031_backfill_failure_reason'),
    ]

    operations = [
        migrations.AddField(
            model_name='webscansdb',
            name='zap_ascan_id',
            field=models.TextField(blank=True, null=True),
        ),
    ]
