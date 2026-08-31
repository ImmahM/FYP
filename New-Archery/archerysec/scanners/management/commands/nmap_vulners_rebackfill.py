import os
import subprocess
import tempfile

from django.core.management.base import BaseCommand

from networkscanners.models import NetworkScanDb, NetworkScanResultsDb


class Command(BaseCommand):
    help = "Re-run nmap --script vulners against stored open ports and add CVSS-rated findings to existing Nmap scans"

    def add_arguments(self, parser):
        parser.add_argument("--scan_id", type=str, default="", help="Only re-enrich a single scan")
        parser.add_argument("--dry-run", action="store_true", help="Print what would be scanned without running nmap")

    def handle(self, *args, **options):
        scan_id = options.get("scan_id") or ""
        dry_run = options.get("dry_run") or False

        scans = NetworkScanDb.objects.filter(scanner="Nmap", scan_status="100")
        if scan_id:
            scans = scans.filter(scan_id=scan_id)

        refreshed = 0
        for scan in scans:
            org = getattr(scan, "organization", None)
            if org is None:
                self.stdout.write(self.style.WARNING(f"Skip {scan.scan_id}: no organization"))
                continue
            results = NetworkScanResultsDb.objects.filter(
                scan_id=scan.scan_id, scanner="Nmap", organization=org
            )
            rows = list(results.exclude(ip__isnull=True).exclude(port=""))
            targets = {}
            for r in rows:
                targets.setdefault(r.ip, []).append(str(r.port))
            if not targets:
                self.stdout.write(self.style.WARNING(f"Skip {scan.scan_id}: no mapped ip/port rows"))
                continue

            user = getattr(scan, "created_by", None)
            if user is None:
                from django.contrib.auth import get_user_model
                user = get_user_model().objects.filter(is_superuser=True).first()

            for ip, ports in targets.items():
                port_list = ",".join(sorted(set(ports)))
                cmd = [
                    "nmap", "-Pn", "-sT", "-sV", "--script",
                    "/usr/share/nmap/scripts/vulners.nse", "-T4",
                    "-p", port_list, str(ip),
                ]
                self.stdout.write(f"[{scan.scan_id}] {ip} ports {port_list}")
                if dry_run:
                    continue
                xml_path = os.path.join(tempfile.gettempdir(), f"nmap_rv_{scan.scan_id}.xml")
                try:
                    if os.path.exists(xml_path):
                        os.remove(xml_path)
                except Exception:
                    pass
                final_cmd = cmd + ["-oX", xml_path]
                try:
                    with open(os.devnull, "w") as dn:
                        proc = subprocess.Popen(final_cmd, stdout=dn, stderr=subprocess.STDOUT)
                        try:
                            proc.wait(timeout=300)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            self.stdout.write(self.style.ERROR(f"  nmap timeout for {ip}"))
                            continue
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"  nmap failed for {ip}: {e}"))
                    continue
                if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
                    self.stdout.write(self.style.WARNING(f"  no XML output for {ip}"))
                    continue
                try:
                    import defusedxml.ElementTree as ET
                    root = ET.parse(xml_path).getroot()
                    from networkscanners.views import _nmap_vulners_to_network, _update_nmap_totals
                    added = _nmap_vulners_to_network(
                        root, scan.scan_id, getattr(scan, "project_id", None), org, user
                    )
                    _update_nmap_totals(scan.scan_id, org)
                    self.stdout.write(self.style.SUCCESS(f"  added {added} CVE findings"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"  parse failed: {e}"))
                    continue
            refreshed += 1

        self.stdout.write(self.style.SUCCESS(f"Backfill complete. Scans refreshed: {refreshed}"))