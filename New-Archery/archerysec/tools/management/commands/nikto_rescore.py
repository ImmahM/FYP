from django.core.management.base import BaseCommand

from scanners.scanner_parser.tools.nikto_htm_parser import nikto_risk, nikto_sev_color
from webscanners.models import WebScanResultsDb, WebScansDb


class Command(BaseCommand):
    help = "Re-rate existing Nikto findings using the calibrated rule engine and refresh parent counts"

    def add_arguments(self, parser):
        parser.add_argument("--scan_id", type=str, default="", help="Only rescore a single scan")

    def handle(self, *args, **options):
        scan_id = options.get("scan_id") or ""
        qs = WebScanResultsDb.objects.filter(scanner="Nikto")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        total = qs.count()
        updated = 0
        affected_scans = set()
        for row in qs:
            uri = ""
            try:
                instances = row.instance or []
                if instances and isinstance(instances[0], dict):
                    uri = instances[0].get("uri", "") or ""
            except Exception:
                uri = ""
            new_risk = nikto_risk(row.description or "", uri)
            new_color = nikto_sev_color(new_risk)
            changed = (new_risk != row.severity) or (new_color != row.severity_color)
            if changed:
                try:
                    WebScanResultsDb.objects.filter(pk=row.pk).update(
                        severity=new_risk, severity_color=new_color
                    )
                    updated += 1
                    affected_scans.add(row.scan_id)
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Failed to update {row.pk}: {e}"))
            else:
                affected_scans.add(row.scan_id)

        # Refresh parent scan counts for every affected scan
        for sid in affected_scans:
            q = WebScanResultsDb.objects.filter(scan_id=sid, scanner="Nikto")
            counts = {
                "total_vul": q.count(),
                "critical_vul": q.filter(severity__iexact="Critical").count(),
                "high_vul": q.filter(severity__iexact="High").count(),
                "medium_vul": q.filter(severity__iexact="Medium").count(),
                "low_vul": q.filter(severity__iexact="Low").count(),
                "info_vul": q.filter(severity__istartswith="Info").count(),
            }
            WebScansDb.objects.filter(scan_id=sid).update(**counts)

        self.stdout.write(
            self.style.SUCCESS(
                f"Rescored {total} rows, changed {updated}, refreshed {len(affected_scans)} scans."
            )
        )