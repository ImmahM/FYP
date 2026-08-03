from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tools", "0002_auto_20230506_1302"),
    ]

    operations = [
        migrations.AddField(
            model_name="niktoresultdb",
            name="pid",
            field=models.IntegerField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name="niktoresultdb",
            name="pgid",
            field=models.IntegerField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name="nmapscandb",
            name="pid",
            field=models.IntegerField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name="nmapscandb",
            name="pgid",
            field=models.IntegerField(null=True, blank=True),
        ),
    ]
