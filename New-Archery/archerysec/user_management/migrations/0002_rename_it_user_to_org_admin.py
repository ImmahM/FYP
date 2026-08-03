from django.db import migrations


def forwards(apps, schema_editor):
    UserRoles = apps.get_model('user_management', 'UserRoles')
    UserProfile = apps.get_model('user_management', 'UserProfile')
    it_role = UserRoles.objects.filter(role='IT User').first()
    org_role = UserRoles.objects.filter(role='Organization Admin').first()
    if it_role and org_role:
        UserProfile.objects.filter(role=it_role).update(role=org_role)
        try:
            it_role.delete()
        except Exception:
            pass
    elif it_role and not org_role:
        # Rename the legacy role in-place
        it_role.role = 'Organization Admin'
        try:
            it_role.save()
        except Exception:
            pass


def backwards(apps, schema_editor):
    # No-op: we do not re-create legacy role
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('user_management', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]

