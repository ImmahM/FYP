from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        # Replace '000Y_previous_migration' with the latest migration filename for archerysettings
        # e.g. ('archerysettings', '0003_auto_20250101_1234')
        ('archerysettings', '000Y_previous_migration'),
    ]

    operations = [
        migrations.AddField(
            model_name='emaildb',
            name='smtp_host',
            field=models.CharField(max_length=255, blank=True, null=True),
        ),
        migrations.AddField(
            model_name='emaildb',
            name='smtp_port',
            field=models.PositiveIntegerField(blank=True, null=True, default=587),
        ),
        migrations.AddField(
            model_name='emaildb',
            name='smtp_use_tls',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='emaildb',
            name='smtp_user',
            field=models.CharField(max_length=255, blank=True, null=True),
        ),
        migrations.AddField(
            model_name='emaildb',
            name='smtp_password',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='emaildb',
            name='sender_email',
            field=models.EmailField(max_length=254, blank=True, null=True),
        ),
    ]