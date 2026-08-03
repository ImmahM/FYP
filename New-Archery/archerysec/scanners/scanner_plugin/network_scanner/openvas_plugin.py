# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import datetime
import hashlib
import os
import time
import uuid

from django.utils import timezone
from openvas_lib import VulnscanException, VulnscanManager

from archerysettings.models import OpenvasSettingDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from scanners.scanner_parser.network_scanner import OpenVas_Parser
from scanners.scanner_parser.network_scanner.OpenVas_Parser import \
    updated_xml_parser

name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""
vuln_color = None
false_positive = ""
duplicate_hash = ""
duplicate_vuln = ""
ov_host = ""
ov_user = ""
ov_pass = ""
ov_port = ""


class OpenVAS_Plugin:
    """
    OpenVAS plugin Class
    """

    def __init__(self, scan_ip, project_id, sel_profile, request, organization=None):
        """

        :param scan_ip:
        :param project_id:
        :param sel_profile:
        """

        self.scan_ip = scan_ip
        self.project_id = project_id
        self.sel_profile = sel_profile
        self.request = request
        try:
            self.organization = organization or getattr(request.user, "organization", None)
        except Exception:
            self.organization = organization

    def connect(self):
        """
        Connecting with OpenVAS
        :return:
        """

        global ov_host, ov_user, ov_pass, ov_port
        all_openvas = OpenvasSettingDb.objects.filter(
            organization=self.organization
        )

        for openvas in all_openvas:
            ov_user = openvas.user
            ov_pass = openvas.password
            ov_host = openvas.host
            ov_port = openvas.port

        scanner = VulnscanManager(
            str(ov_host), str(ov_user), str(ov_pass), int(ov_port)
        )
        time.sleep(5)

        return scanner

    def scan_launch(self, scanner):
        """
        Scan Launch Plugin
        :param scanner:
        :return:
        """
        # Use the selected OpenVAS scan profile if provided; otherwise default
        # to a sensible built-in profile available on most managers.
        profile = self.sel_profile or "Full and fast"
        scan_id, target_id = scanner.launch_scan(
            target=str(self.scan_ip), profile=str(profile)
        )
        return scan_id, target_id

    def scan_status(self, scanner, scan_id, max_secs=3600):
        """
        Get the scan status.
        :param scanner:
        :param scan_id:
        :return:
        """

        previous = ""
        # Prepare per-scan log file
        try:
            import os as _os
            _dir = _os.path.join(_os.getcwd(), 'logs', 'openvas')
            _os.makedirs(_dir, exist_ok=True)
            _logpath = _os.path.join(_dir, f"{scan_id}.log")
            # Disable app-maintained global stream log; rely on container-native logs via OPENVAS_SECONDARY_LOG volume mapping
            _glog = None
            _gext = None
        except Exception:
            _logpath = None
            _glog = None
            _gext = None
        start_ts = time.time()
        while float(scanner.get_progress(str(scan_id))) < 100.0:
            try:
                # If user requested stop, bail out early and try to stop/cancel upstream
                from networkscanners.models import NetworkScanDb as _NS
                row = _NS.objects.filter(scan_id=scan_id, organization=self.organization).only('failure_reason', 'scan_status').first()
                if row and getattr(row, 'failure_reason', '') == 'Stopped by user':
                    try:
                        try:
                            scanner.stop_scan(str(scan_id))
                        except Exception:
                            scanner.cancel_scan(str(scan_id))
                    except Exception:
                        pass
                    NetworkScanDb.objects.filter(
                        scan_id=scan_id, organization=self.organization
                    ).update(updated_time=timezone.now())
                    break
            except Exception:
                pass
            # Enforce maximum scan runtime
            if time.time() - start_ts > max_secs:
                try:
                    try:
                        scanner.stop_scan(str(scan_id))
                    except Exception:
                        scanner.cancel_scan(str(scan_id))
                except Exception:
                    pass
                NetworkScanDb.objects.filter(
                    scan_id=scan_id, organization=self.organization
                ).update(
                    scan_status="100",
                    failure_reason="Timed out after 1 hour",
                    updated_time=timezone.now(),
                )
                return "100"
            current = str(scanner.get_scan_status(str(scan_id))) + str(
                scanner.get_progress(str(scan_id))
            )
            if current != previous:
                print(
                    "[Scan ID "
                    + str(scan_id)
                    + "]("
                    + str(scanner.get_scan_status(str(scan_id)))
                    + ") Scan progress: "
                    + str(scanner.get_progress(str(scan_id)))
                    + " %"
                )
                try:
                    line = (
                        f"[Scan ID {scan_id}]({scanner.get_scan_status(str(scan_id))}) "
                        f"Scan progress: {scanner.get_progress(str(scan_id))} %\n"
                    )
                    if _logpath:
                        with open(_logpath, 'a', encoding='utf-8', errors='ignore') as _lf:
                            _lf.write(line)
                    # No writes to global/external OpenVAS logs; those come from the container's own log files mounted via compose
                except Exception:
                    pass
                status = float(scanner.get_progress(str(scan_id)))
                NetworkScanDb.objects.filter(
                    scan_id=scan_id, organization=self.organization
                ).update(scan_status=status, updated_time=timezone.now())
                previous = current
            time.sleep(5)

        status = "100"
        NetworkScanDb.objects.filter(
            scan_id=scan_id, organization=self.organization
        ).update(scan_status=status, updated_time=timezone.now())
        try:
            if _logpath:
                with open(_logpath, 'a', encoding='utf-8', errors='ignore') as _lf2:
                    _lf2.write("Completed.\n")
            # No writes to global/external OpenVAS logs from app
        except Exception:
            pass

        return status


def vuln_an_id(scan_id, project_id, request, organization=None):
    """
    The function is filtering all data from OpenVAS and dumping to Archery database.
    :param scan_id:
    :return:
    """
    ov_ip = ""
    ov_user = ""
    ov_pass = ""
    ov_port = None
    try:
        effective_org = organization or getattr(request.user, "organization", None)
    except Exception:
        effective_org = organization
    all_openvas = OpenvasSettingDb.objects.filter(
        organization=effective_org
    )

    scan_status = "100"
    # Use timezone-aware timestamps to avoid warnings
    date_time = timezone.now()

    for openvas in all_openvas:
        ov_user = openvas.user
        ov_pass = openvas.password
        ov_ip = openvas.host
        ov_port = openvas.port

    # Include port if available; default to 9390
    try:
        port = int(ov_port) if ov_port else 9390
    except Exception:
        port = 9390
    scanner = VulnscanManager(str(ov_ip), str(ov_user), str(ov_pass), int(port))
    openvas_results = scanner.get_raw_xml(str(scan_id))

    hosts = OpenVas_Parser.get_hosts(openvas_results) or []

    # Remember previous values before possibly replacing rows
    prev_row = NetworkScanDb.objects.filter(
        scan_id=scan_id, organization=effective_org
    ).first()
    prev_scan_type = getattr(prev_row, "scan_type", None) if prev_row else None
    prev_created_by = getattr(prev_row, "created_by", None) if prev_row else None
    prev_updated_by = getattr(prev_row, "updated_by", None) if prev_row else None

    # If no hosts were returned by the manager (e.g., host down), do NOT delete
    # the existing row; instead, mark it completed with an explanatory reason
    # so it remains visible in the list for the user.
    if not hosts:
        try:
            from django.utils import timezone as _tz
            NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=effective_org
            ).update(
                scan_status="100",
                failure_reason="Completed: target unreachable or no hosts detected by OpenVAS.",
                updated_time=_tz.now(),
            )
        except Exception:
            pass
        # Still run the parser to allow any side-effects, but guard exceptions
        try:
            OpenVas_Parser.updated_xml_parser(
                project_id=project_id, scan_id=scan_id, root=openvas_results, request=request, organization=effective_org
            )
        except Exception:
            pass
        return

    # Keep the single parent NetworkScanDb row created at launch; do not
    # split it into multiple rows by host. Import results only.
    OpenVas_Parser.updated_xml_parser(
        project_id=project_id, scan_id=scan_id, root=openvas_results, request=request, organization=effective_org
    )
