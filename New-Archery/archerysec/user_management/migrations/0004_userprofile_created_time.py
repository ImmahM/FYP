from django.db import migrations, models
from django.utils import timezone


def populate_created_time(apps, schema_editor):
    UserProfile = apps.get_model("user_management", "UserProfile")

    for user in UserProfile.objects.filter(created_time__isnull=True):
        fallback = user.password_updt_time or user.last_login or timezone.now()
        user.created_time = fallback
        user.save(update_fields=["created_time"])


def reset_created_time(apps, schema_editor):
    UserProfile = apps.get_model("user_management", "UserProfile")
    UserProfile.objects.update(created_time=None)


class Migration(migrations.Migration):

    dependencies = [
        ("user_management", "0003_alter_userprofile_token_time"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="created_time",
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.RunPython(populate_created_time, reset_created_time),
    ]
