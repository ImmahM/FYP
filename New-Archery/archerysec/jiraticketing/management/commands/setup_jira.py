from django.core.management.base import BaseCommand
from django.core import signing
import uuid

from jiraticketing.models import jirasetting
from archerysettings.models import SettingsDb
from user_management.models import Organization


class Command(BaseCommand):
    help = 'Configure JIRA integration settings'

    def add_arguments(self, parser):
        parser.add_argument('--url', type=str, help='JIRA server URL')
        parser.add_argument('--username', type=str, help='JIRA username/email')
        parser.add_argument('--token', type=str, help='JIRA API token')

    def handle(self, *args, **options):
        jira_url = options['url'] or 'https://my-fyp-org.atlassian.net'
        jira_username = options['username'] or 'tp077928@mail.apu.edu.my'
        jira_token = options['token']

        if not jira_token:
            self.stdout.write(self.style.ERROR('Please provide --token argument'))
            return

        # Get or create organization
        org = Organization.objects.first()
        if not org:
            org = Organization.objects.create(
                name='Default Organization',
                description='Auto-created for JIRA setup',
                logo='',
                contact='',
                address=''
            )
            self.stdout.write(self.style.SUCCESS(f'Created organization: {org.name}'))

        # Encrypt credentials
        encrypted_username = signing.dumps(jira_username)
        encrypted_password = signing.dumps(jira_token)

        # Delete existing JIRA settings for this org
        jirasetting.objects.filter(organization=org).delete()

        # Create new JIRA setting
        setting_id = uuid.uuid4()
        jira_setting = jirasetting(
            setting_id=setting_id,
            jira_server=jira_url,
            jira_username=encrypted_username,
            jira_password=encrypted_password,
            organization=org,
        )
        jira_setting.save()

        # Also create SettingsDb entry
        SettingsDb.objects.filter(setting_scanner='Jira', organization=org).delete()
        setting_dat = SettingsDb(
            setting_id=setting_id,
            setting_scanner='Jira',
            organization=org,
            setting_status=False,
        )
        setting_dat.save()

        self.stdout.write(self.style.SUCCESS('JIRA settings configured successfully!'))
        self.stdout.write(f'  URL: {jira_url}')
        self.stdout.write(f'  Username: {jira_username}')
        self.stdout.write(f'  Organization: {org.name}')
        self.stdout.write(self.style.WARNING('\nPlease restart the server and test the connection.'))
