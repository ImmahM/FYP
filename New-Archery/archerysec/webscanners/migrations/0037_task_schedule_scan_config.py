from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webscanners", "0036_task_schedule_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="task_schedule_db",
            name="scan_config",
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
        migrations.AddField(
            model_name="task_schedule_db",
            name="scan_type",
            field=models.TextField(blank=True, null=True),
        ),
    ]
