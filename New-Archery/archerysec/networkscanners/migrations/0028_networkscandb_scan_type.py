from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("networkscanners", "0027_networkscandb_failure_updated"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkscandb",
            name="scan_type",
            field=models.TextField(blank=True, null=True),
        ),
    ]

