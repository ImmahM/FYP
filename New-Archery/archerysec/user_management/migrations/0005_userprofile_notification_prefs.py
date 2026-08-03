from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user_management", "0004_userprofile_created_time"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="notify_critical_only",
            field=models.BooleanField(
                default=False,
                help_text="Only notify for critical/high severity findings",
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="notify_email",
            field=models.BooleanField(
                default=True, help_text="Receive email notifications"
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="notify_in_app",
            field=models.BooleanField(
                default=True, help_text="Receive in-app notifications"
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="notify_on_scan_complete",
            field=models.BooleanField(
                default=True, help_text="Notify when a scan completes"
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="notify_on_scan_fail",
            field=models.BooleanField(
                default=True, help_text="Notify when a scan fails"
            ),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="notify_on_scan_start",
            field=models.BooleanField(
                default=False, help_text="Notify when a scan starts"
            ),
        ),
    ]
