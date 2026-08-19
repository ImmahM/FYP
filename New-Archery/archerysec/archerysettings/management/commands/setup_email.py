from django.core.management.base import BaseCommand
from django.core import signing
import uuid

from archerysettings.models import EmailDb, SettingsDb
from user_management.models import Organization


class Command(BaseCommand):
    help = 'Configure Gmail SMTP email settings'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Gmail address')
        parser.add_argument('--app-password', type=str, help='Google App Password')
        parser.add_argument('--recipient', type=str, help='Default recipient email')

    def handle(self, *args, **options):
        gmail = options['email'] or 'immahkali939@gmail.com'
        app_password = options['app-password'] or 'cyfhdwpoujgrtxei'
        recipient = options['recipient'] or gmail

        if not app_password:
            self.stdout.write(self.style.ERROR('Please provide --app-password argument'))
            return

        # Remove spaces from app password
        app_password = app_password.replace(' ', '')

        # Get or create organization
        org = Organization.objects.first()
        if not org:
            org = Organization.objects.create(
                name='Default Organization',
                description='Auto-created for email setup',
                logo='',
                contact='',
                address=''
            )
            self.stdout.write(self.style.SUCCESS(f'Created organization: {org.name}'))

        # Encrypt password
        encrypted_password = signing.dumps(app_password)

        # Delete existing email settings for this org
        EmailDb.objects.filter(organization=org).delete()

        # Create new email setting with Gmail SMTP
        setting_id = uuid.uuid4()
        email_setting = EmailDb(
            setting_id=setting_id,
            subject='ArcherySec Notification',
            message='',
            recipient_list=recipient,
            smtp_host='smtp.gmail.com',
            smtp_port=587,
            smtp_use_tls=True,
            smtp_user=gmail,
            smtp_password=encrypted_password,
            sender_email=gmail,
            organization=org,
        )
        email_setting.save()

        # Also create/update SettingsDb entry
        SettingsDb.objects.filter(setting_scanner='Email', organization=org).delete()
        setting_dat = SettingsDb(
            setting_id=setting_id,
            setting_scanner='Email',
            organization=org,
            setting_status=False,
        )
        setting_dat.save()

        self.stdout.write(self.style.SUCCESS('Email settings configured successfully!'))
        self.stdout.write(f'  Gmail: {gmail}')
        self.stdout.write(f'  SMTP Host: smtp.gmail.com')
        self.stdout.write(f'  SMTP Port: 587')
        self.stdout.write(f'  Use TLS: True')
        self.stdout.write(f'  Recipient: {recipient}')
        self.stdout.write(self.style.WARNING('\nPlease restart the server and test the email.'))
