from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('networkscanners', '0026_auto_20230506_1302'),
    ]

    operations = [
        migrations.AddField(
            model_name='networkscandb',
            name='failure_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networkscandb',
            name='updated_time',
            field=models.DateTimeField(auto_now=True, blank=True, null=True),
        ),
    ]

