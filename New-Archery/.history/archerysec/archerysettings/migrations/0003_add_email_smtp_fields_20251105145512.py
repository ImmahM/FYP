# Generated manually to add SMTP fields to EmailDb

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("archerysettings", "0002_auto_20230506_1302"),
    ]

    operations = [
        migrations.AddField(
            model_name="emaildb",
            name="smtp_host",
            field=models.CharField(
                max_length=255,
                blank=True,
                null=True,
                help_text="SMTP server hostname, e.g. smtp.gmail.com",
            ),
        ),
        migrations.AddField(
            model_name="emaildb",
            name="smtp_port",
            field=models.PositiveIntegerField(
                blank=True,
                null=True,
                default=587,
                help_text="SMTP port (587 for STARTTLS, 465 for SSL)",
            ),
        ),
        migrations.AddField(
            model_name="emaildb",
            name="smtp_use_tls",
            field=models.BooleanField(
                default=True,
                help_text="Use STARTTLS (recommended with port 587)",
            ),
        ),
        migrations.AddField(
            model_name="emaildb",
            name="smtp_user",
            field=models.CharField(
                max_length=255,
                blank=True,
                null=True,
                help_text="SMTP username / login",
            ),
        ),
        migrations.AddField(
            model_name="emaildb",
            name="smtp_password",
            field=models.TextField(
                blank=True,
                null=True,
                help_text="Encrypted via django.core.signing before save",
            ),
        ),
        migrations.AddField(
            model_name="emaildb",
            name="sender_email",
            field=models.EmailField(
                max_length=254,
                blank=True,
                null=True,
                help_text="From address shown to recipients",
            ),
        ),
    ]
