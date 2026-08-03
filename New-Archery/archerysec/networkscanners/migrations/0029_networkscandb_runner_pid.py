from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("networkscanners", "0028_networkscandb_scan_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkscandb",
            name="runner_pid",
            field=models.TextField(blank=True, null=True),
        ),
    ]

