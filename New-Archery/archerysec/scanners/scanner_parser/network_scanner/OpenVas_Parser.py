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

import hashlib
import uuid
from datetime import datetime
from django.utils import timezone

from archeryapi.models import OrgAPIKey
from dashboard.views import trend_update
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from utility.email_notify import email_network_scan_summary

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


def updated_xml_parser(root, project_id, scan_id, request, organization=None):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :param username:
    :return:
    """
    global host, name, severity, port, threat, creation_time, modification_time, description, family, cvss_base, cve
    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if organization is None:
        if str(request.user) == 'AnonymousUser':
            organization = key_object.organization if key_object else None
        else:
            organization = getattr(request.user, "organization", None)
    
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "name":
                global name
                if r.text is None:
                    name = "NA"
                else:
                    name = r.text
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text
            if r.tag == "port":
                global port
                if r.text is None:
                    port = "NA"
                else:
                    port = r.text
            if r.tag == "threat":
                global threat
                if r.text is None:
                    threat = "NA"
                else:
                    threat = r.text
            if r.tag == "severity":
                global severity
                if r.text is None:
                    severity = "NA"
                else:
                    severity = r.text
            if r.tag == "description":
                global description
                if r.text is None:
                    description = "NA"
                else:
                    description = r.text
        # Use timezone-aware timestamps to avoid warnings with USE_TZ
        date_time = timezone.now()
        vuln_id = uuid.uuid4()
        dup_data = name + host + severity + port
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        # Normalize severity and color early so we can reuse for updates
        _sev = 'Info' if str(threat).strip().lower() == 'log' else threat
        if threat == "Critical":
            vuln_color = "critical"
        elif threat == "High":
            vuln_color = "danger"
        elif threat == "Medium":
            vuln_color = "warning"
        else:
            vuln_color = "info"

        # Per-scan de-dup: if a row with this hash already exists for the scan,
        # update/enrich it instead of inserting a new duplicate record.
        existing = NetworkScanResultsDb.objects.filter(
            dup_hash=duplicate_hash, scan_id=scan_id, organization=organization
        ).first()
        if existing:
            updates = {}
            if _sev and _sev != getattr(existing, "severity", None):
                updates["severity"] = _sev
            if vuln_color and vuln_color != getattr(existing, "severity_color", None):
                updates["severity_color"] = vuln_color
            if description and description != getattr(existing, "description", None):
                updates["description"] = description
            if port and port != getattr(existing, "port", None):
                updates["port"] = port
            if host and host != getattr(existing, "ip", None):
                updates["ip"] = host
            updates["date_time"] = date_time
            if updates:
                NetworkScanResultsDb.objects.filter(pk=existing.pk).update(**updates)
            continue

        # No existing row for this scan/hash: create a fresh finding
        false_p = NetworkScanResultsDb.objects.filter(
            false_positive_hash=duplicate_hash,
            organization=organization,
        )
        fp_lenth_match = len(false_p)
        if fp_lenth_match == 1:
            false_positive = "Yes"
        else:
            false_positive = "No"

        save_all = NetworkScanResultsDb(
            scan_id=scan_id,
            project_id=project_id,
            vuln_id=vuln_id,
            title=name,
            date_time=date_time,
            severity=_sev,
            description=description,
            port=port,
            ip=host,
            vuln_status="Open",
            dup_hash=duplicate_hash,
            vuln_duplicate="No",
            severity_color=vuln_color,
            false_positive=false_positive,
            scanner="Openvas",
            organization=organization,
        )
        save_all.save()

        # Update totals for the whole scan (across all hosts) so a single
        # parent row reflects aggregate counts.
        openvas_all = NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=organization)
        total_critical = openvas_all.filter(severity="Critical").count()
        total_high = openvas_all.filter(severity="High").count()
        total_medium = openvas_all.filter(severity="Medium").count()
        total_low = openvas_all.filter(severity="Low").count()
        total_info = openvas_all.filter(severity__iexact="Info").count()
        # We skip inserting duplicate rows, so total_duplicate is effectively zero
        total_duplicate = 0
        total_vul = total_high + total_medium + total_low + total_info
        NetworkScanDb.objects.filter(scan_id=scan_id, organization=organization).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_duplicate,
        )
    trend_update()
    email_network_scan_summary(
        subject="Archery Tool Scan Status - OpenVAS Report Uploaded",
        scan_id=scan_id,
        target_url="",
        organization_id=getattr(organization, "id", None),
    )


def get_hosts(root):
    hosts = []
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text
                    if host not in hosts:
                        hosts.append(host)
    return hosts


parser_header_dict = {
    "openvas": {
        "displayName": "OpenVAS",
        "dbtype": "NetworkScan",
        "dbname": "Openvas",
        "type": "XML",
        "parserFunction": updated_xml_parser,
        "icon": "/static/tools/openvas.png",
    }
}
