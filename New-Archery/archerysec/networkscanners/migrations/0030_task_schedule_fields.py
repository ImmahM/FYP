from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("networkscanners", "0029_networkscandb_runner_pid"),
    ]

    operations = [
        migrations.AddField(
            model_name="taskscheduledb",
            name="last_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="taskscheduledb",
            name="schedule_time_utc",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
