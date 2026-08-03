import hashlib
from typing import Dict, List

from django.core.management.base import BaseCommand, CommandError

from webscanners.models import WebScanResultsDb


def _dedup_key(title: str, severity: str, url: str) -> str:
    """Match the normalization used by check_false_positive for stable dedup."""
    t = (title or "").strip().lower()
    s = (severity or "").strip().lower()
    u = (url or "").strip().lower()
    return hashlib.sha256("|".join([t, s, u]).encode("utf-8")).hexdigest()


class Command(BaseCommand):
    help = "Mark or delete duplicate webscan findings for a scan_id (optional: restrict by scanner)."

    def add_arguments(self, parser):
        parser.add_argument("scan_id", help="Scan UUID to clean duplicates for.")
        parser.add_argument(
            "--scanner",
            dest="scanner",
            default=None,
            help="Optional scanner name filter (e.g., Zap, Arachni).",
        )
        parser.add_argument(
            "--delete",
            action="store_true",
            dest="delete",
            default=False,
            help="Delete duplicate rows instead of just marking vuln_duplicate='Yes'.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            dest="dry_run",
            default=False,
            help="Do not write changes; just report what would happen.",
        )

    def handle(self, *args, **options):
        scan_id = options.get("scan_id")
        scanner = options.get("scanner")
        delete = bool(options.get("delete"))
        dry_run = bool(options.get("dry_run"))

        if not scan_id:
            raise CommandError("scan_id is required")

        qs = WebScanResultsDb.objects.filter(scan_id=scan_id)
        if scanner:
            qs = qs.filter(scanner__iexact=scanner)

        total = qs.count()
        if total == 0:
            self.stdout.write(self.style.WARNING("No findings found for this scan_id."))
            return

        buckets: Dict[str, List[WebScanResultsDb]] = {}
        for row in qs.order_by("created_time", "id"):
            key = _dedup_key(row.title, row.severity, row.url)
            buckets.setdefault(key, []).append(row)

        to_mark = []
        to_delete = []

        for key, rows in buckets.items():
            if len(rows) <= 1:
                continue
            keeper = rows[0]
            dupes = rows[1:]
            for dup in dupes:
                if delete:
                    to_delete.append(dup)
                else:
                    to_mark.append(dup)

        self.stdout.write(f"Scanned {total} findings; found {len(to_mark) + len(to_delete)} duplicates.")

        if dry_run:
            if to_mark:
                self.stdout.write(f"[dry-run] Would mark {len(to_mark)} duplicates (vuln_duplicate='Yes').")
            if to_delete:
                self.stdout.write(f"[dry-run] Would delete {len(to_delete)} duplicates.")
            return

        if to_mark:
            ids = [d.pk for d in to_mark]
            WebScanResultsDb.objects.filter(pk__in=ids).update(vuln_duplicate="Yes")
            self.stdout.write(self.style.SUCCESS(f"Marked {len(to_mark)} duplicates."))

        if to_delete:
            deleted_count = WebScanResultsDb.objects.filter(pk__in=[d.pk for d in to_delete]).delete()[0]
            self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} duplicates."))

