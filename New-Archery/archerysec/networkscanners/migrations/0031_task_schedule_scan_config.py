from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("networkscanners", "0030_task_schedule_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="taskscheduledb",
            name="scan_config",
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
        migrations.AddField(
            model_name="taskscheduledb",
            name="scan_type",
            field=models.TextField(blank=True, null=True),
        ),
    ]
