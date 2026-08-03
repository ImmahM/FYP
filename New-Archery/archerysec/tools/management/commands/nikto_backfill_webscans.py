from django.core.management.base import BaseCommand
from django.db import transaction
import os

from tools.models import NiktoResultDb
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser


class Command(BaseCommand):
    help = "Re-parse stored Nikto HTML reports into WebScansDb/WebScanResultsDb"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=0, help="Limit number of scans to backfill")

    def handle(self, *args, **options):
        limit = options.get("limit") or 0
        qs = NiktoResultDb.objects.all().order_by("-created_time")
        if limit > 0:
            qs = qs[:limit]
        count = 0
        missing = 0
        for row in qs:
            scan_id = row.scan_id
            project_id = getattr(row, "project_id", None)
            try:
                from django.conf import settings as _settings
                _res_dir = getattr(_settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result"))
            except Exception:
                _res_dir = os.path.join(os.getcwd(), "nikto_result")
            path = os.path.join(_res_dir, f"{scan_id}.html")
            if not os.path.exists(path):
                missing += 1
                self.stdout.write(self.style.WARNING(f"Missing file for scan {scan_id}: {path}"))
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    html = fh.read()
                # request=None -> parser resolves organization from NiktoResultDb
                with transaction.atomic():
                    nikto_html_parser(html, project_id, scan_id, request=None)
                count += 1
                self.stdout.write(self.style.SUCCESS(f"Backfilled scan {scan_id}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Failed backfill for {scan_id}: {e}"))
        self.stdout.write(self.style.SUCCESS(f"Backfill complete. Parsed: {count}, Missing files: {missing}"))
