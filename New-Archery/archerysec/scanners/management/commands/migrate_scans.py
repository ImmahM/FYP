"""
Management command to run data migration
"""
from django.core.management.base import BaseCommand
from django.db import transaction

from scanners.migration_utils import ScanResultMigrator


class Command(BaseCommand):
    help = 'Migrate legacy scan data to unified models'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            type=str,
            choices=['web', 'network', 'static', 'cloud', 'compliance', 'all'],
            default='all',
            help='Type of scan to migrate'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Batch size for migration'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without actually migrating'
        )

    def handle(self, *args, **options):
        scan_type = options['type']
        batch_size = options['batch_size']
        dry_run = options['dry_run']
        
        migrator = ScanResultMigrator()
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN - No changes will be made'))
            return
        
        if scan_type == 'all':
            self.stdout.write('Starting full migration...')
            results = migrator.migrate_all(batch_size)
            
            for stype, stats in results.items():
                self.stdout.write(
                    f"  {stype}: {stats['migrated']}/{stats['total']} migrated, "
                    f"{stats['skipped']} skipped, {stats['errors']} errors"
                )
        else:
            method_name = f'migrate_{scan_type}scans'
            if hasattr(migrator, method_name):
                method = getattr(migrator, method_name)
                stats = method(batch_size)
                self.stdout.write(
                    f"{scan_type}: {stats['migrated']}/{stats['total']} migrated, "
                    f"{stats['skipped']} skipped, {stats['errors']} errors"
                )
            else:
                self.stdout.write(self.style.ERROR(f'Unknown scan type: {scan_type}'))
        
        self.stdout.write(self.style.SUCCESS('Migration complete!'))