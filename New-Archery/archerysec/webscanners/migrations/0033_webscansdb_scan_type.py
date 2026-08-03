# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webscanners", "0032_webscansdb_zap_ascan_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="webscansdb",
            name="scan_type",
            field=models.TextField(blank=True, null=True),
        ),
    ]

