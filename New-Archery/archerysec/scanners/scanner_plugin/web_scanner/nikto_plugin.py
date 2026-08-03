# -*- coding: utf-8 -*-
# Minimal Nikto plugin to launch scans from Web Scans API

import os
import threading

from django.conf import settings


class Nikto:
    """Thin wrapper used by Web Scans API.

    Expected usage in webscanners/views.py:
        nikto = nikto_plugin.Nikto()
        nikto.setup(scan_id, target_url)
        nikto.run()
    """

    def __init__(self):
        self.scan_id = None
        self.target_url = None

    def setup(self, scan_id, target_url):
        self.scan_id = str(scan_id)
        self.target_url = str(target_url)

    def run(self):
        """Spawn the same background Nikto runner used by Tools flow."""
        if not self.scan_id or not self.target_url:
            return

        # Resolve organization and project from the WebScansDb row created by the caller
        try:
            from webscanners.models import WebScansDb
            ws = WebScansDb.objects.filter(scan_id=self.scan_id).first()
            org = getattr(ws, "organization", None)
            project_id = getattr(ws, "project_id", None)
        except Exception:
            ws = None
            org = None
            project_id = None

        # Compute result path
        nikto_res_dir = getattr(settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result"))
        try:
            os.makedirs(nikto_res_dir, exist_ok=True)
        except Exception:
            pass
        nikto_res_path = os.path.join(nikto_res_dir, f"{self.scan_id}.html")

        # Ensure a NiktoResultDb row exists so status/log UI can bind to it
        try:
            from tools.models import NiktoResultDb
            from django.utils import timezone as _tz
            nr, _created = NiktoResultDb.objects.get_or_create(
                scan_id=self.scan_id,
                defaults=dict(
                    scan_url=self.target_url,
                    project_id=project_id,
                    nikto_status="Scan Started",
                    organization=getattr(org, "id", getattr(org, "pk", 1)) or 1,
                    created_time=_tz.now(),
                ),
            )
            # Attach org if row existed without it
            if org and getattr(nr, "organization_id", None) is None:
                try:
                    NiktoResultDb.objects.filter(id=nr.id).update(organization=org)
                except Exception:
                    pass
        except Exception:
            pass

        # Import late to avoid import cycles
        from tools.views import _run_nikto_scan

        # Launch the background thread with conservative defaults
        t = threading.Thread(
            target=_run_nikto_scan,
            kwargs=dict(
                scans_url=self.target_url,
                scan_id=self.scan_id,
                project_id=project_id,
                profile_tuning=None,
                request=None,
                user=None,
                org=org,
                nikto_res_path=nikto_res_path,
                force_cgi=False,
                plugins_all=False,
                maxtime_min=None,
                pause_sec=None,
                evasion=None,
                user_agent=None,
                config_path=None,
                extra_flags=None,
                timeout_s=15,
            ),
        )
        t.daemon = True
        t.start()

