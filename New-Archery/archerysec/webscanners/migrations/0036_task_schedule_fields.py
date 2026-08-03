from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webscanners", "0035_backfill_scan_phase_nikto"),
    ]

    operations = [
        migrations.AddField(
            model_name="task_schedule_db",
            name="last_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="task_schedule_db",
            name="schedule_time_utc",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
