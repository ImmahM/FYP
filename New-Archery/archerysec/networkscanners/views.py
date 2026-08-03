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
""" Author: Anand Tiwari """

from __future__ import unicode_literals

import hashlib
import signal
import json
import os
import threading
import time
import uuid
from datetime import datetime
import subprocess
import tempfile
import ipaddress
import pytz
import defusedxml.ElementTree as ET
from django.utils import timezone
import re

from django.conf import settings
from django.contrib import messages
from django.core import signing
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from django.db.models import OuterRef, Subquery, IntegerField, Count, Max
from django.db.models.functions import Coalesce
from notifications.models import Notification
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archerysettings import load_settings, save_settings
from archerysettings.models import EmailDb, SettingsDb
from jiraticketing.models import jirasetting
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb,
                                    TaskScheduleDb)
from networkscanners.serializers import (NetworkScanDbSerializer,
                                         NetworkScanResultsDbSerializer,
                                         OpenvasScansSerializer,
                                         OpenvasSettingsSerializer)
from projects.models import ProjectDb
from scanners.scanner_plugin.network_scanner.openvas_plugin import (
    OpenVAS_Plugin, vuln_an_id)
from scanners.scanner_parser.network_scanner import nmap_parser
from scheduler import background_tasks as scheduler
from user_management import permissions
from scanners.analysis import enrich_scan_result
from scanners.audit import log_action
from django.utils import timezone

LOCAL_TZ = pytz.timezone(getattr(settings, "DEF_TIME_ZONE", "Asia/Kuala_Lumpur"))


def _parse_local_datetime(value):
    if not value:
        return None
    cleaned = value.strip()
    formats = ["%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S %p", "%d/%m/%Y %H:%M:%S"]
    for fmt in formats:
        try:
            naive = datetime.strptime(cleaned, fmt)
            return LOCAL_TZ.localize(naive)
        except ValueError:
            continue
    return None


def _format_local(dt):
    return dt.astimezone(LOCAL_TZ).strftime("%d/%m/%Y %I:%M:%S %p")


def _bool_from_value(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    try:
        val = str(value).strip().lower()
    except Exception:
        return default
    if val == "":
        return default
    return val in ("1", "true", "on", "yes")


OPENVAS_PROFILE_TOKENS = {
    "full_fast": "Full and fast",
    "full_deep": "Full and very deep",
    "full_fast_ultimate": "Full and fast ultimate",
    "host_disc": "Host Discovery",
    "system_disc": "System Discovery",
}


def _normalize_openvas_profile(value, fallback="Full and fast"):
    if value is None:
        return fallback
    token = str(value).strip()
    if not token:
        return fallback
    return OPENVAS_PROFILE_TOKENS.get(token, token)


def _attach_schedule_metadata(schedules, project_lookup):
    items = []
    for entry in schedules:
        key = str(getattr(entry, "project_id", "") or "").strip()
        entry.project_obj = project_lookup.get(key)
        scanner = str(entry.scanner or "").strip()
        if scanner == "open_vas":
            entry.scanner_display = "Openvas"
        elif scanner.lower() == "openvas":
            entry.scanner_display = "Openvas"
        elif scanner.lower() == "nmap":
            entry.scanner_display = "Nmap"
        else:
            entry.scanner_display = scanner or "Network Scan"
        items.append(entry)
    return items

api_data = os.getcwd() + "/" + "apidata.json"

# status = ""
name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
page = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""


def email_notify(user, subject, message):
    from scanners.notification import _send_email as _notify_send_email
    all_emails = EmailDb.objects.filter(is_active=True)
    recipients = []
    for email in all_emails:
        if email.recipient_list:
            parts = [r.strip() for r in email.recipient_list.split(",") if r.strip()]
            recipients.extend(parts)
    recipients = list(dict.fromkeys(recipients))
    if not recipients:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        return
    org_id = getattr(getattr(user, "organization", None), "id", None)
    ok = _notify_send_email(recipients, subject, message, organization_id=org_id)
    if not ok:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")


# Helpers: per‑scan OpenVAS log path + writer
def _ov_log_path(scan_id):
    try:
        base = os.path.join(os.getcwd(), "logs", "openvas")
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, f"{scan_id}.log")
    except Exception:
        return os.path.join(os.getcwd(), f"{scan_id}.log")


def _ov_log(scan_id, msg):
    try:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with open(_ov_log_path(scan_id), "a", encoding="utf-8", errors="ignore") as fh:
            fh.write(f"[{ts} UTC] {msg}\n")
    except Exception:
        pass


def _safe_remove(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _delete_network_scan_artifacts(scan_id, organization, created_by=None):
    """
    Remove all persisted data, tool rows, and per-scan log files for a network scan.
    """
    NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=organization).delete()

    # Remove tool-backed artifacts (Nmap, Vulners, etc.) keyed by the same scan id
    try:
        from tools.models import NmapResultDb, NmapScanDb, NmapVulnersPortResultDb

        nmap_filter = {"scan_id": str(scan_id), "organization": organization}
        if created_by:
            nmap_filter["created_by"] = created_by
        NmapResultDb.objects.filter(**nmap_filter).delete()
        NmapVulnersPortResultDb.objects.filter(**nmap_filter).delete()
        NmapScanDb.objects.filter(**nmap_filter).delete()
    except Exception:
        pass

    # Remove any per-scan logs we emit during execution
    _safe_remove(os.path.join(os.getcwd(), "logs", "nmap", f"{scan_id}.log"))
    _safe_remove(os.path.join(tempfile.gettempdir(), f"nmap_{scan_id}.xml"))
    _safe_remove(os.path.join(os.getcwd(), "logs", "openvas", f"{scan_id}.log"))


_NETWORK_IP_ERROR = "Network scans only support IP addresses (e.g., 192.168.1.1)."


def _parse_ip_targets(raw_value):
    """Split the raw input into unique, validated IP/CIDR targets."""
    tokens = re.split(r"[\s,]+", str(raw_value or "").strip())
    targets = []
    invalid = []
    seen = set()
    for token in tokens:
        tok = (token or "").strip()
        if not tok:
            continue
        if tok.lower() in ("localhost", "127.0.0.1", "::1"):
            invalid.append(tok)
            continue
        try:
            # Accept single IPs or CIDR blocks; reject hostnames/URLs
            ipaddress.ip_network(tok, strict=False)
            if tok not in seen:
                targets.append(tok)
                seen.add(tok)
        except ValueError:
            invalid.append(tok)
    return targets, invalid


def _ip_error_message(invalid_targets):
    if invalid_targets:
        uniq = list(dict.fromkeys(invalid_targets))
        preview = ", ".join(uniq[:3])
        if len(uniq) > 3:
            preview += f" (+{len(uniq) - 3} more)"
        return f"{_NETWORK_IP_ERROR} Invalid input: {preview}"
    return _NETWORK_IP_ERROR


def openvas_scanner(scan_ip, project_id, sel_profile, user, request, organization=None, owner=None):
    """
    The function is launch the OpenVAS scans.
    :param scan_ip:
    :param project_id:
    :param sel_profile:
    :return:
    """
    effective_org = organization or getattr(request.user, "organization", None)
    actor = user or getattr(request, "user", None)
    owner_user = owner or actor or getattr(request, "user", None)
    if actor is None:
        actor = owner_user
    if effective_org is None:
        notify.send(actor, recipient=actor, verb="OpenVAS Setting not configured for your organization")
        return

    # Ensure org-level OpenVAS connector is configured/enabled; users rely on admin's connector
    try:
        from archerysettings.models import SettingsDb as _SettingsDb
        has_connector = _SettingsDb.objects.filter(
            setting_scanner="Openvas",
            organization=effective_org,
            setting_status=True,
        ).exists()
    except Exception:
        has_connector = False
    if not has_connector:
        notify.send(actor, recipient=actor, verb="OpenVAS Setting not configured for your organization")
        return

    openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request, organization=effective_org)
    try:
        scanner = openvas.connect()
    except Exception:
        notify.send(actor, recipient=actor, verb="OpenVAS Setting not configured")
        subject = "Archery Tool Notification"
        message = "OpenVAS Scanner failed due to setting not found "
        email_notify(user=actor, subject=subject, message=message)
        return

    notify.send(actor, recipient=actor, verb="Network scan started")
    subject = "Archery Tool Notification"
    message = "Network scan started"
    email_notify(user=actor, subject=subject, message=message)

    # Launch scan and create DB row immediately so it appears in UI
    try:
        scan_id, target_id = openvas.scan_launch(scanner)
    except Exception:
        notify.send(actor, recipient=actor, verb="Network scan launch failed")
        return
    date_time = timezone.now()
    # Write initial launch line + mirror to global log
    try:
        _ov_log(scan_id, f"Launch: target={str(scan_ip).strip()} profile={sel_profile or 'Full and fast'} target_id={target_id}")
        try:
            _gpath = os.path.join(os.getcwd(), "logs", "customarcherysecopenvas.log")
            with open(_gpath, "a", encoding="utf-8", errors="ignore") as _glf:
                _glf.write(
                    f"Launch: scan_id={scan_id} target_id={target_id} target={str(scan_ip).strip()} profile={sel_profile or 'Full and fast'}\n"
                )
            _gext = os.getenv("OPENVAS_SECONDARY_LOG")
            if _gext:
                try:
                    os.makedirs(os.path.dirname(_gext), exist_ok=True)
                except Exception:
                    pass
                try:
                    with open(_gext, "a", encoding="utf-8", errors="ignore") as _ge:
                        _ge.write(
                            f"Launch: scan_id={scan_id} target_id={target_id} target={str(scan_ip).strip()} profile={sel_profile or 'Full and fast'}\n"
                        )
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    ip_clean = str(scan_ip).strip()
    try:
        NetworkScanDb.objects.update_or_create(
            scan_id=str(scan_id),
            organization=effective_org,
            defaults=dict(
                project_id=str(project_id),
                ip=ip_clean,
                date_time=date_time,
                scan_status=0.0,
                scanner="Openvas",
                scan_type=str(sel_profile or "Full and fast"),
                failure_reason=None,
                created_by=owner_user,
                updated_by=owner_user,
            ),
        )
    except Exception:
        pass

    # Defer long-running status + parse to a monitor thread for responsiveness
    def _monitor():
        failure_msg = None
        try:
            # Reconnect manager (fresh client) and monitor progress
            _ov_log(scan_id, "Status polling: connecting to manager")
            mgr = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request, organization=effective_org).connect()
            _ov_log(scan_id, "Status polling: started")
            OpenVAS_Plugin(scan_ip, project_id, sel_profile, request, organization=effective_org).scan_status(scanner=mgr, scan_id=scan_id)
            _ov_log(scan_id, "Status polling: completed")
        except Exception as e:
            failure_msg = f"OpenVAS status error: {str(e)[:200]}"
            _ov_log(scan_id, failure_msg)
            try:
                from django.utils import timezone as _tz
                NetworkScanDb.objects.filter(scan_id=scan_id, organization=effective_org).update(
                    failure_reason=failure_msg, updated_time=_tz.now()
                )
            except Exception:
                pass
        # Parse results
        try:
            _ov_log(scan_id, "Result import: starting")
            vuln_an_id(scan_id=scan_id, project_id=project_id, request=request, organization=effective_org)
            # Summarize basic counts post-import for visibility
            try:
                qs = NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=effective_org)
                total = qs.count()
                crit = qs.filter(severity__iexact='Critical').count()
                high = qs.filter(severity__iexact='High').count()
                med = qs.filter(severity__iexact='Medium').count()
                low = qs.filter(severity__iexact='Low').count()
                info = qs.filter(severity__istartswith='Info').count()
                _ov_log(scan_id, f"Result import: completed - total={total}, Critical={crit}, High={high}, Medium={med}, Low={low}, Info={info}")
                # Host distribution (top 5)
                try:
                    from collections import Counter as _Counter
                    ips = [str(x or '') for x in qs.values_list('ip', flat=True) if x]
                    if ips:
                        cnt = _Counter(ips)
                        _ov_log(scan_id, f"Hosts affected: {len(cnt)} (top 5)")
                        for ip, c in cnt.most_common(5):
                            _ov_log(scan_id, f"  - {ip}: {c} finding(s)")
                except Exception:
                    pass
                # Port distribution (top 10)
                try:
                    ports = [str(x or '') for x in qs.values_list('port', flat=True) if x]
                    if ports:
                        pc = _Counter(ports)
                        _ov_log(scan_id, "Ports (top 10):")
                        for p, c in pc.most_common(10):
                            _ov_log(scan_id, f"  - {p}: {c}")
                except Exception:
                    pass
                # Findings (all, grouped by severity)
                try:
                    groups = [
                        ('Critical', qs.filter(severity__iexact='Critical')),
                        ('High', qs.filter(severity__iexact='High')),
                        ('Medium', qs.filter(severity__iexact='Medium')),
                        ('Low', qs.filter(severity__iexact='Low')),
                        ('Informational', qs.filter(severity__istartswith='Info')),
                    ]
                    _ov_log(scan_id, "Findings (all):")
                    for label, q in groups:
                        cnt = q.count()
                        _ov_log(scan_id, f"{label} findings: {cnt}")
                        for row in q.only('severity','title','ip','port').iterator(chunk_size=500):
                            ip = getattr(row, 'ip', '') or ''
                            port = getattr(row, 'port', '') or ''
                            sep = (":"+str(port)) if port else ''
                            _ov_log(scan_id, f"  - {getattr(row,'severity','')} | {ip}{sep} | {getattr(row,'title','')}")
                except Exception:
                    pass
            except Exception:
                _ov_log(scan_id, "Result import: completed")
        except Exception as e:
            failure_msg = failure_msg or f"OpenVAS result error: {str(e)[:200]}"
            _ov_log(scan_id, failure_msg)
            try:
                from django.utils import timezone as _tz
                NetworkScanDb.objects.filter(scan_id=scan_id, organization=effective_org).update(
                    failure_reason=failure_msg, updated_time=_tz.now()
                )
            except Exception:
                pass
        # No results safety net
        try:
            from django.utils import timezone as _tz
            rc = NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=effective_org).count()
            if rc == 0:
                NetworkScanDb.objects.filter(
                    scan_id=scan_id,
                    organization=effective_org,
                    failure_reason__isnull=True,
                ).update(
                    failure_reason="No results saved for this run (check OpenVAS logs for details).",
                    updated_time=_tz.now(),
                )
        except Exception:
            pass
        notify.send(actor, recipient=actor, verb="Network scan completed (results imported)")
        _ov_log(scan_id, "Scan completed")
        # Mirror completion to the consolidated app log if available
        try:
            _gpath = os.path.join(os.getcwd(), "logs", "customarcherysecopenvas.log")
            with open(_gpath, "a", encoding="utf-8", errors="ignore") as _glf:
                _glf.write(
                    f"Completed: scan_id={scan_id} target={str(scan_ip).strip()} profile={sel_profile or 'Full and fast'}\n"
                )
            _gext = os.getenv("OPENVAS_SECONDARY_LOG")
            if _gext:
                try:
                    os.makedirs(os.path.dirname(_gext), exist_ok=True)
                except Exception:
                    pass
                try:
                    with open(_gext, "a", encoding="utf-8", errors="ignore") as _ge:
                        _ge.write(
                            f"Completed: scan_id={scan_id} target={str(scan_ip).strip()} profile={sel_profile or 'Full and fast'}\n"
                        )
                except Exception:
                    pass
        except Exception:
            pass

    threading.Thread(target=_monitor, daemon=True).start()

    all_openvas = NetworkScanDb.objects.filter()
    all_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for openvas in all_openvas:
        all_vuln = openvas.total_vul
        total_high = openvas.high_vul
        total_medium = openvas.medium_vul
        total_low = openvas.low_vul

    subject = "Archery Tool Notification"
    message = (
        "OpenVAS Scan Completed  <br>"
        "Total: %s  <br>Total High: %s <br>"
        "Total Medium: %s  <br>Total Low %s"
        % (all_vuln, total_high, total_medium, total_low)
    )

    email_notify(user=actor, subject=subject, message=message)

    return HttpResponse(status=201)


class OpenvasLaunchScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        all_ip = NetworkScanDb.objects.filter(organization=request.user.organization)

        # Fix: pass the request to render()
        return render(request, "networkscanners/openvas_vuln_list.html", {"all_ip": all_ip})

    def post(self, request):
        user = request.user
        if request.path[:4] == "/api":
            serializer = OpenvasScansSerializer(data=request.data)
            if serializer.is_valid():
                scan_ip = request.data.get(
                    "scan_ip",
                )

                project_uu_id = request.data.get(
                    "project_id",
                )
            else:
                return Response({"message": "Invalid data"})
        else:
            scan_ip = request.POST.get("ip")
            project_uu_id = request.POST.get("project_id")
        # Resolve project safely: accept UUID or fallback to a recent project in org
        from uuid import UUID as _UUID
        base_projects = ProjectDb.objects.filter(organization=request.user.organization)
        proj_row = None
        if project_uu_id:
            try:
                proj_row = base_projects.filter(uu_id=_UUID(str(project_uu_id))).values("id").first()
            except Exception:
                proj_row = None
        if not proj_row:
            # Fallback to most recently updated project in the org
            proj_row = base_projects.order_by("-updated_time", "-created_time").values("id").first()
        if not proj_row:
            msg = "No project available. Please create a project first."
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
            from django.contrib import messages as _msgs
            try:
                _msgs.error(request, msg)
            except Exception:
                pass
            return HttpResponse(msg, status=400)
        project_id = proj_row["id"]
        # Quick preflight: ensure org-level OpenVAS connector exists and is enabled
        try:
            has_connector = SettingsDb.objects.filter(
                setting_scanner="Openvas",
                organization=request.user.organization,
                setting_status=True,
            ).exists()
        except Exception:
            has_connector = False
        if not has_connector:
            msg = "Network scan connector is missing or disabled for your organization. Contact an admin."
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
            from django.contrib import messages as _msgs
            try:
                _msgs.warning(request, msg)
            except Exception:
                pass
            return HttpResponse(msg, status=400)

        # Optional: OpenVAS scan profile (aka scan type). Supports UI and API callers.
        def _norm_profile(val):
            mapping = {
                # UI toggle tokens
                "full_fast": "Full and fast",
                "full_deep": "Full and very deep",
                "full_fast_ultimate": "Full and fast ultimate",
                "host_disc": "Host Discovery",
                "system_disc": "System Discovery",
            }
            if not val:
                return None
            v = str(val).strip()
            return mapping.get(v, v)

        if request.path[:4] == "/api":
            sel_profile = _norm_profile(request.data.get("scan_profile"))
        else:
            sel_profile = _norm_profile(request.POST.get("scan_profile"))
        targets, invalid_targets = _parse_ip_targets(scan_ip)
        if (not targets) or invalid_targets:
            msg = _ip_error_message(invalid_targets)
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
            return HttpResponse(msg, status=400)

        for target in targets:
            # Always launch in a background thread for responsiveness.
            # The scanner itself will create the DB row after obtaining the scan_id.
            thread = threading.Thread(
                target=openvas_scanner,
                args=(target, project_id, sel_profile, user, request),
            )
            thread.daemon = True
            thread.start()

        log_action(request, "scan_start", "openvas_scan", ",".join(targets), {"profile": sel_profile})
        if request.path[:4] == "/api":
            # Return quickly; background thread continues launching
            return Response({"message": "OpenVAS scan launch initiated"}, status=202)
        else:
            # For UI callers, redirect immediately to the list; live refresh will append the row when ready
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScan(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/ipscan.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        all_scans = NetworkScanDb.objects.filter(organization=request.user.organization)
        all_proj = ProjectDb.objects.filter(organization=request.user.organization)

        all_notify = Notification.objects.unread()

        return render(
            request,
            "networkscanners/ipscan.html",
            {
                "all_scans": all_scans,
                "all_proj": all_proj,
                "message": all_notify,
            },
        )


class OpenvasDetails(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        return render(
            request,
            "networkscanners/setting_form.html",
        )

    def post(self, request):
        setting_id = uuid.uuid4()
        save_openvas_setting = save_settings.SaveSettings(
            api_data,
        )
        # Determine target organization (supports superuser org switching via hidden field)
        from user_management.models import Organization as _Org
        org = getattr(request.user, "organization", None)
        _org_id = request.POST.get("org") or request.GET.get("org")
        if getattr(request.user, "is_superuser", False) and _org_id:
            try:
                org = _Org.objects.get(pk=_org_id)
            except Exception:
                pass

        if request.POST.get("openvas_enabled") == "on":
            openvas_enabled = True
        else:
            openvas_enabled = False

        if request.path[:4] == "/api":
            serializer = OpenvasSettingsSerializer(data=request.data)
            if serializer.is_valid():
                openvas_host = request.data.get(
                    "openvas_host",
                )
                openvas_port = request.data.get(
                    "openvas_port",
                )
                openvas_user = request.data.get(
                    "openvas_user",
                )
                openvas_password = request.data.get(
                    "openvas_password",
                )
                openvas_enabled = request.data.get(
                    "openvas_enabled",
                )
            else:
                return Response({"message": "Invalid Data"})
        else:
            openvas_host = request.POST.get("openvas_host")
            openvas_port = request.POST.get("openvas_port")
            openvas_user = request.POST.get("openvas_user")
            openvas_password = request.POST.get("openvas_password")
            # Checkbox yields 'on' when checked; coerce to boolean
            openvas_enabled = True if str(request.POST.get("openvas_enabled")).lower() in ("on","true","1","yes") else False

        save_openvas_setting.openvas_settings(
            openvas_host=openvas_host,
            openvas_port=openvas_port,
            openvas_enabled=openvas_enabled,
            openvas_user=openvas_user,
            openvas_password=openvas_password,
            setting_id=setting_id,
            organization=org,
        )

        save_settings_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Openvas",
            organization=org,
        )
        save_settings_data.save()

        sel_profile = ""

        openvas = OpenVAS_Plugin(
            openvas_host,
            setting_id,
            sel_profile,
            request
        )
        try:
            openvas.connect()
            openvas_info = True
            SettingsDb.objects.filter(
                setting_id=setting_id, organization=org
            ).update(setting_status=openvas_info)
        except Exception:
            openvas_info = False
            SettingsDb.objects.filter(
                setting_id=setting_id, organization=org
            ).update(setting_status=openvas_info)
            if request.path[:4] == "/api":
                return Response({"message": "Openvas Not Working"})

        if request.path[:4] == "/api":
            return Response(
                {
                    "message": "Openvas Scanner setting updated !!!",
                }
            )
        else:
            redirect_url = reverse("archerysettings:settings")
            if getattr(request.user, "is_superuser", False) and getattr(org, "id", None):
                redirect_url = f"{redirect_url}?org={org.id}"
            return HttpResponseRedirect(redirect_url)


class OpenvasSetting(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        load_openvas_setting = load_settings.ArcherySettings(
            api_data,
        )
        openvas_host = load_openvas_setting.openvas_host()
        openvas_port = load_openvas_setting.openvas_port()
        openvas_enabled = load_openvas_setting.openvas_enabled()
        if openvas_enabled:
            openvas_enabled = "True"
        else:
            openvas_enabled = "False"
        openvas_user = load_openvas_setting.openvas_username()
        openvas_password = load_openvas_setting.openvas_pass()
        if request.path[:4] == "/api":
            return Response(
                {
                    "openvas_host": openvas_host,
                    "openvas_port": openvas_port,
                    "openvas_enabled": openvas_enabled,
                    "openvas_user": openvas_user,
                    "openvas_password": openvas_password,
                }
            )
        else:
            return render(
                request,
                "networkscanners/setting_form.html",
                {
                    "openvas_host": openvas_host,
                    "openvas_port": openvas_port,
                    "openvas_enabled": openvas_enabled,
                    "openvas_user": openvas_user,
                    "openvas_password": openvas_password,
                },
            )



class NetworkScanSchedule(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/network_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        all_scans_db = ProjectDb.objects.filter(
            organization=request.user.organization
        ).order_by("project_name")
        project_lookup = {str(p.id): p for p in all_scans_db}
        schedules_qs = TaskScheduleDb.objects.filter(
            organization=request.user.organization, created_by=request.user
        ).order_by("schedule_time_utc", "id")
        all_scheduled_scans = _attach_schedule_metadata(list(schedules_qs), project_lookup)
        return render(
            request,
            "networkscanners/network_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )

    def post(self, request):
        scan_ip = (request.POST.get("ip") or "").strip()
        scan_schedule_time = request.POST.get("datetime")
        periodic_task_value = request.POST.get("periodic_task_value")

        project_obj = None
        project_raw = request.POST.get("project_id") or ""
        if project_raw:
            try:
                project_obj = ProjectDb.objects.filter(
                    organization=request.user.organization, id=int(project_raw)
                ).first()
            except (TypeError, ValueError):
                project_obj = None

        local_dt = _parse_local_datetime(scan_schedule_time)
        if not local_dt:
            messages.error(
                request, "Invalid schedule time. Please select a valid date and time."
            )
            return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))
        schedule_utc = local_dt.astimezone(timezone.utc)

        targets, invalid_targets = _parse_ip_targets(scan_ip)
        if (not targets) or invalid_targets:
            messages.error(request, _ip_error_message(invalid_targets))
            return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))

        role_name = str(getattr(request.user, "role", "") or "")
        is_openvas_admin = request.user.is_superuser or role_name in (
            "Admin",
            "Organization Admin",
        )
        is_nmap_admin = request.user.is_superuser or role_name == "Admin"
        schedule_entries = []
        openvas_selected = True
        if is_openvas_admin:
            openvas_selected = _bool_from_value(request.POST.get("openvas_enable")) or bool(
                request.POST.getlist("ov_profile")
            )
        if openvas_selected:
            profile_tokens = [token for token in request.POST.getlist("ov_profile") if token]
            selected_token = profile_tokens[0] if profile_tokens else None
            profile_name = _normalize_openvas_profile(selected_token, fallback="Full and fast")
            if is_openvas_admin and not profile_tokens and not _bool_from_value(request.POST.get("openvas_enable")):
                messages.error(
                    request,
                    "Select exactly one OpenVAS profile before saving the schedule.",
                )
                return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))
            schedule_entries.append(
                {
                    "scanner": "open_vas",
                    "scan_type": f"Network - {profile_name}",
                    "scan_config": {"openvas_profile": profile_name},
                }
            )

        nmap_selected = False
        nmap_profile = "quick"
        nmap_os_guess = False
        if is_nmap_admin:
            profile_values = [val for val in request.POST.getlist("nmap_profile") if val]
            if profile_values:
                nmap_profile = profile_values[0].strip().lower()
            if nmap_profile not in ("quick", "full"):
                nmap_profile = "quick"
            nmap_os_guess = _bool_from_value(request.POST.get("nmap_os_guess"))
            nmap_selected = (
                _bool_from_value(request.POST.get("nmap_enable"))
                or bool(profile_values)
                or nmap_os_guess
            )
        if is_nmap_admin and nmap_selected:
            schedule_entries.append(
                {
                    "scanner": "nmap",
                    "scan_type": "Nmap - " + ("Full" if nmap_profile == "full" else "Quick") + (" + OS" if nmap_os_guess else ""),
                    "scan_config": {
                        "nmap_profile": nmap_profile,
                        "nmap_os_guess": nmap_os_guess,
                    },
                }
            )

        if not schedule_entries:
            messages.error(
                request,
                "Select at least one scanner to schedule.",
            )
            return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))

        project_id_value = None
        if project_obj:
            project_id_value = str(project_obj.id)

        created = 0
        for target in targets:
            for entry in schedule_entries:
                schedule = TaskScheduleDb.objects.create(
                    target=target,
                    schedule_time=_format_local(schedule_utc),
                    schedule_time_utc=schedule_utc,
                    last_run_at=None,
                    project_id=project_id_value,
                    scanner=entry["scanner"],
                    scan_type=entry["scan_type"],
                    scan_config=entry["scan_config"],
                    periodic_task=periodic_task_value,
                    created_by=request.user,
                    updated_by=request.user,
                    organization=request.user.organization,
                )
                schedule.task_id = str(schedule.id)
                schedule.save(update_fields=["task_id"])
                scheduler.register_network_schedule(schedule)
                created += 1

        if created:
            messages.success(
                request,
                f"Scheduled {created} network scan{'s' if created != 1 else ''}.",
            )
        return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))


class NetworkScanScheduleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/network_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        for i in range(0, split_length):
            entry_id = target_split.__getitem__(i)
            schedules = TaskScheduleDb.objects.filter(
                task_id=entry_id, organization=request.user.organization
            )
            for schedule in schedules:
                scheduler.cancel_schedule("net", schedule.id)
            schedules.delete()

        return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))


class OpenvasSettingEnable(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/nv_settings.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        load_nv_setting = load_settings.ArcherySettings(
            api_data,
        )
        nv_enabled = str(load_nv_setting.nv_enabled())
        nv_online = str(load_nv_setting.nv_enabled())
        nv_version = str(load_nv_setting.nv_enabled())
        nv_timing = load_nv_setting.nv_timing()

        return render(
            request,
            "networkscanners/nv_settings.html",
            {
                "nv_enabled": nv_enabled,
                "nv_online": nv_online,
                "nv_version": nv_version,
                "nv_timing": nv_timing,
            },
        )


class OpenvasSettingEnableDetails(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/nv_settings.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def get(self, request):
        return render(
            request,
            "networkscanners/nv_settings.html",
            {
                "messages": messages,
            },
        )

    def post(self, request):
        save_nv_setting = save_settings.SaveSettings(
            api_data,
        )
        if str(request.POST.get("nv_enabled")) == "on":
            nv_enabled = True
        else:
            nv_enabled = False
        if str(request.POST.get("nv_online")) == "on":
            nv_online = True
        else:
            nv_online = False
        if str(request.POST.get("nv_version")) == "on":
            nv_version = True
        else:
            nv_version = False
        nv_timing = int(str(request.POST.get("nv_timing")))
        if nv_timing > 5:
            nv_timing = 5
        elif nv_timing < 0:
            nv_timing = 0

        save_nv_setting.nmap_vulners(
            enabled=nv_enabled, version=nv_version, online=nv_online, timing=nv_timing
        )

        return HttpResponseRedirect(reverse("archerysettings:settings"))


class NetworkScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        # Only show current user's own scans in their org (admin sees own scans here)
        user_org = getattr(request.user, "organization", None)
        from user_management.models import Organization as _Org
        org_qs = _Org.objects.filter(pk=getattr(user_org, "id", None)) if user_org else _Org.objects.none()
        try:
            is_admin = (
                str(getattr(request.user, "role", "")) == "Admin"
            ) or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False

        # Annotate each scan with result counts and last update time, mirroring web scans list
        base_results = NetworkScanResultsDb.objects.filter(scan_id=OuterRef("scan_id"), organization__in=org_qs)
        res_count_sq = (
            base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        )
        crit_count_sq = (
            base_results.filter(severity__iexact="Critical")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        high_count_sq = (
            base_results.filter(severity__iexact="High")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        med_count_sq = (
            base_results.filter(severity__iexact="Medium")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        low_count_sq = (
            base_results.filter(severity__iexact="Low")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        info_count_sq = (
            base_results.filter(severity__istartswith="Info")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        dup_count_sq = (
            base_results.filter(vuln_duplicate="Yes")
            .values("scan_id")
            .annotate(cnt=Count("id"))
            .values("cnt")[:1]
        )
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]
        # Scope by organization; admins see own scans only (per privacy requirement)
        base_qs = NetworkScanDb.objects.filter(organization__in=org_qs, created_by=request.user)
        scan_list = (
            base_qs
            .annotate(
                result_count=Coalesce(Subquery(res_count_sq, output_field=IntegerField()), 0),
                res_critical=Coalesce(Subquery(crit_count_sq, output_field=IntegerField()), 0),
                res_high=Coalesce(Subquery(high_count_sq, output_field=IntegerField()), 0),
                res_medium=Coalesce(Subquery(med_count_sq, output_field=IntegerField()), 0),
                res_low=Coalesce(Subquery(low_count_sq, output_field=IntegerField()), 0),
                res_info=Coalesce(Subquery(info_count_sq, output_field=IntegerField()), 0),
                res_dup=Coalesce(Subquery(dup_count_sq, output_field=IntegerField()), 0),
                latest_result_time=Subquery(latest_result_dt_sq),
            )
        )

        # Compute UI flags for stalled/stopped like web list
        from django.utils import timezone
        STALLED_AFTER_MINUTES = 15
        cutoff_seconds = STALLED_AFTER_MINUTES * 60
        scans_list = list(scan_list)

        def _to_int(val):
            try:
                s = str(val).strip()
                if not s:
                    return 0
                return int(float(s))
            except Exception:
                return 0

        now = timezone.now()
        for row in scans_list:
            percent = _to_int(getattr(row, "scan_status", 0))
            last_times = [
                getattr(row, "latest_result_time", None),
                getattr(row, "updated_time", None),
                getattr(row, "created_time", None),
            ]
            last_times = [t for t in last_times if t]
            last_update = max(last_times) if last_times else None
            stopped = (
                (getattr(row, "failure_reason", "") == "Stopped by user") or
                (percent < 100 and last_update is not None and (now - last_update).total_seconds() > cutoff_seconds)
            )
            setattr(row, "ui_stopped", stopped)
            setattr(row, "ui_last_update", last_update)
        all_notify = Notification.objects.unread()
        if request.path[:4] == "/api":
            serialized_data = NetworkScanDbSerializer(scan_list, many=True)
            return Response(serialized_data.data)
        else:
            ctx = {"all_scans": scans_list, "message": all_notify}
            return render(request, "networkscanners/scans/list_scans.html", ctx)


class AdminNetworkScanExplorer(APIView):
    """Admin explorer for network scans across organizations.

    - Admin/superuser can see scans for all organizations.
    - Supports filtering by organizations and owners (users).
    - Passes owner column flag to the shared list template.
    """
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        from user_management.models import Organization as _Org, UserProfile as _UP

        is_admin = getattr(request.user, "is_superuser", False) or str(getattr(request.user, "role", "")) in ("Admin", "Organization Admin")

        selected_org_ids = [oid for oid in request.GET.getlist("org") if oid]
        selected_owner_ids = [uid for uid in request.GET.getlist("owner") if uid]

        # Build organizations list (for filter UI)
        orgs_qs = _Org.objects.all() if is_admin else _Org.objects.filter(pk=getattr(getattr(request.user, "organization", None), "id", None)).distinct()

        # Owners list depends on selected orgs; if none selected, show all owners for admin, else restricted
        if selected_org_ids:
            owners_qs = _UP.objects.filter(organization_id__in=selected_org_ids)
        else:
            owners_qs = _UP.objects.all() if is_admin else _UP.objects.filter(organization=request.user.organization)

        # Subqueries for result counts
        base_results = NetworkScanResultsDb.objects.filter(scan_id=OuterRef("scan_id"))
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]

        # Base queryset: all scans for admin; otherwise current org
        base_qs = NetworkScanDb.objects.all() if is_admin else NetworkScanDb.objects.filter(organization=request.user.organization)
        if selected_org_ids:
            base_qs = base_qs.filter(organization_id__in=selected_org_ids)
        
        if selected_owner_ids:
            base_qs = base_qs.filter(created_by_id__in=selected_owner_ids)

        scan_list = (
            base_qs
            .annotate(
                result_count=Coalesce(Subquery(res_count_sq, output_field=IntegerField()), 0),
                res_critical=Coalesce(Subquery(crit_count_sq, output_field=IntegerField()), 0),
                res_high=Coalesce(Subquery(high_count_sq, output_field=IntegerField()), 0),
                res_medium=Coalesce(Subquery(med_count_sq, output_field=IntegerField()), 0),
                res_low=Coalesce(Subquery(low_count_sq, output_field=IntegerField()), 0),
                res_info=Coalesce(Subquery(info_count_sq, output_field=IntegerField()), 0),
                res_dup=Coalesce(Subquery(dup_count_sq, output_field=IntegerField()), 0),
                latest_result_time=Subquery(latest_result_dt_sq),
            )
        )

        # Build org->users mapping for dynamic owner list in template when orgs filter is visible
        org_user_map = {}
        try:
            from django.forms.models import model_to_dict as _m2d
            for org in orgs_qs:
                users = _UP.objects.filter(organization=org).values("id", "name", "email")
                org_user_map[str(org.id)] = [
                    {"id": u["id"], "name": u["name"] or u["email"]} for u in users
                ]
        except Exception:
            org_user_map = {}

        all_notify = Notification.objects.unread()
        ctx = {
            "all_scans": list(scan_list),
            "message": all_notify,
            "owners": owners_qs,
            "selected_owner_ids": selected_owner_ids,
            "show_owner": True,
            "orgs": orgs_qs if is_admin else None,
            "selected_org_ids": selected_org_ids,
            "org_user_map": json.dumps(org_user_map),
        }
        return render(request, "networkscanners/scans/list_scans.html", ctx)


class NetworkScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        jira_url = None
        jira = jirasetting.objects.filter(organization=request.user.organization)
        for d in jira:
            jira_url = d.jira_server
        if uu_id is None:
            scan_id = request.GET["scan_id"]
            # Ensure the user has access to this scan
            is_admin = getattr(request.user, 'is_superuser', False) or str(getattr(request.user, 'role', '')) in ('Admin', 'Organization Admin')
            scan_qs = NetworkScanDb.objects.filter(scan_id=scan_id)
            if not is_admin:
                scan_qs = scan_qs.filter(organization=request.user.organization).filter(created_by=request.user)
            if not scan_qs.exists():
                return HttpResponseRedirect(reverse("networkscanners:list_scans"))
            vuln_filter = {"scan_id": scan_id}
            if not is_admin:
                vuln_filter["organization"] = request.user.organization
            vuln_data = NetworkScanResultsDb.objects.filter(**vuln_filter)
        else:
            try:
                is_admin = getattr(request.user, 'is_superuser', False) or str(getattr(request.user, 'role', '')) in ('Admin', 'Organization Admin')
                vuln_filter = {"scan_id": uu_id}
                if not is_admin:
                    vuln_filter["organization"] = request.user.organization
                vuln_data = NetworkScanResultsDb.objects.filter(**vuln_filter)
                scan_id = uu_id
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        # Determine scanner name for this scan id (used to control auto-refresh in template)
        try:
            is_admin = getattr(request.user, 'is_superuser', False) or str(getattr(request.user, 'role', '')) in ('Admin', 'Organization Admin')
            scan_db_qs = NetworkScanDb.objects.filter(scan_id=scan_id)
            if not is_admin:
                scan_db_qs = scan_db_qs.filter(organization=request.user.organization)
            scanner_name = scan_db_qs.values_list('scanner', flat=True).first() or ''
        except Exception:
            scanner_name = ''
        if request.path[:4] == "/api":
            serialized_data = NetworkScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data)
        else:
            vuln_data = list(vuln_data)
            from scanners.analysis.cvss_calculator import CvssCalculator
            _calc = CvssCalculator()
            mitre_techniques_set = set()
            for row in vuln_data:
                sev = getattr(row, "severity", None) or ""
                cvss = _calc.compute(severity=sev)
                row.cvss_score = cvss["score"]
                row.cvss_severity = cvss["severity"]
                enrich_scan_result(row)
                if getattr(row, "mitre_has_data", False):
                    for t in getattr(row, "mitre_techniques", []):
                        mitre_techniques_set.add((t["id"], t["name"], t["tactic"]))
            mitre_facets = sorted(mitre_techniques_set, key=lambda x: x[0])
            return render(
                request,
                "networkscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url, "scan_id": str(scan_id), "scanner_name": scanner_name, "mitre_facets": mitre_facets},
            )


class NetworkScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")
        notes = request.POST.get("note")
        NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id,
            scan_id=scan_id,
            scanner=scanner,
            organization=request.user.organization,
        ).update(false_positive=false_positive, vuln_status=status, note=notes)

        if false_positive == "Yes":
            vuln_info = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id,
                vuln_id=vuln_id,
                scanner=scanner,
                organization=request.user.organization,
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.ip
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                NetworkScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id,
                    scanner=scanner,
                    organization=request.user.organization,
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                    note=notes,
                )

        all_vuln = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
            vuln_status="Open",
            scanner=scanner,
            organization=request.user.organization,
        )

        # Consistent, case-insensitive severity counts for totals
        total_high = all_vuln.filter(severity__iexact="High").count()
        total_medium = all_vuln.filter(severity__iexact="Medium").count()
        total_low = all_vuln.filter(severity__iexact="Low").count()
        total_info = all_vuln.filter(severity__istartswith="Info").count()
        total_dup = all_vuln.filter(vuln_duplicate="Yes").count()
        total_vul = total_high + total_medium + total_low + total_info

        # Persist update time and clear failure if applicable
        from django.utils import timezone as _tz
        result_count = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        ).count()
        failure_msg = None if result_count > 0 else "Scan appears failed: empty results (no results saved)."
        NetworkScanDb.objects.filter(
            scan_id=scan_id, scanner=scanner, organization=request.user.organization
        ).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
            failure_reason=failure_msg,
            updated_time=_tz.now(),
        )
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln_info") + "?scan_id=%s" % (scan_id)
        )


class NetworkScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]
        scanner = request.GET["scanner"]
        jira_setting = jirasetting.objects.filter(
            organization=request.user.organization
        )
        # user = request.user

        for jira in jira_setting:
            jira_server = jira.jira_server
            jira_username = jira.jira_username
            jira_password = jira.jira_password

        if jira_username is not None:
            jira_username = signing.loads(jira_username)

        if jira_password is not None:
            jira_password = signing.loads(jira_password)

        options = {"server": jira_server}
        try:
            if jira_username is not None and jira_username != "":
                jira_ser = JIRA(
                    options,
                    basic_auth=(jira_username, jira_password),
                    max_retries=0,
                    timeout=30,
                )
            else:
                jira_ser = JIRA(
                    options, token_auth=jira_password, max_retries=0, timeout=30
                )
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            jira_projects = None
            # notify.send(user, recipient=user, verb="Jira settings not found")

        vul_dat = list(NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id, scanner=scanner, organization=request.user.organization
        ).order_by("vuln_id"))

        for row in vul_dat:
            enrich_scan_result(row)

        return render(
            request,
            "networkscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
        )


class NetworkScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_scans.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsViewer,
    )

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            # Non-admins can delete only their own scans
            item_qs = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False
            if not is_admin:
                item_qs = item_qs.filter(created_by=request.user)
            # Keep a copy of the row for cleanup
            row = item_qs.first()
            deleted_count, _ = item_qs.delete()
            # Filesystem and process cleanup
            try:
                import signal, time
                scanner = (str(getattr(row, 'scanner', '') or '')).strip().lower() if row else ''
                # Kill running nmap if we have a PID
                if row and getattr(row, 'runner_pid', None):
                    try:
                        pid = int(str(row.runner_pid))
                        os.kill(pid, signal.SIGTERM)
                        time.sleep(0.5)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except Exception:
                            pass
                    except Exception:
                        pass
                # Try to stop any still-running OpenVAS job
                if scanner in ('openvas', 'openvas-scanner', 'openvasscanner'):
                    try:
                        mgr = OpenVAS_Plugin('', None, None, request).connect()
                        try:
                            mgr.stop_scan(str(scan_id))
                        except Exception:
                            try:
                                mgr.cancel_scan(str(scan_id))
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass

            if deleted_count:
                _delete_network_scan_artifacts(scan_id, request.user.organization)
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = NetworkScanResultsDb.objects.filter(
                vuln_id=vuln_id, organization=request.user.organization
            )
            delete_vuln.delete()
        all_vuln = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        total_vul = all_vuln.count()
        total_critical = all_vuln.filter(severity__iexact="Critical").count()
        total_high = all_vuln.filter(severity__iexact="High").count()
        total_medium = all_vuln.filter(severity__iexact="Medium").count()
        total_low = all_vuln.filter(severity__iexact="Low").count()
        total_info = all_vuln.filter(severity__istartswith="Info").count()
        total_dup = all_vuln.filter(vuln_duplicate="Yes").count()

        from django.utils import timezone as _tz2
        result_count2 = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        ).count()
        failure_msg2 = None if result_count2 > 0 else "Scan appears failed: empty results (no results saved)."
        NetworkScanDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
            organization=request.user.organization,
            failure_reason=failure_msg2,
            updated_time=_tz2.now(),
        )
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkRescan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        import uuid as _uuid
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        base_qs = NetworkScanDb.objects.filter(scan_id=scan_id)
        if not is_admin:
            base_qs = base_qs.filter(organization=request.user.organization)
        try:
            ns = base_qs.get()
        except Exception:
            return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        # Only Admin/superuser or owner may rescan
        if not is_admin and getattr(ns, "created_by_id", None) != getattr(request.user, "id", None):
            return Response({"message": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        target = ns.ip
        project_id = ns.project_id
        target_org = getattr(ns, "organization", None) or getattr(request.user, "organization", None)
        owner_user = getattr(ns, "created_by", None) or request.user
        user = owner_user
        # Reuse previous scan_type if present; fall back to default in plugin
        sel_profile = getattr(ns, "scan_type", None)

        # Remove the existing row so the rescan replaces it (keeps a single row visible)
        try:
            NetworkScanDb.objects.filter(scan_id=scan_id, organization=target_org).delete()
            NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=target_org).delete()
        except Exception:
            pass

        thread = threading.Thread(
            target=openvas_scanner,
            args=(target, project_id, sel_profile, user, request),
            kwargs=dict(organization=target_org, owner=owner_user),
        )
        thread.daemon = True
        thread.start()

        if request.path[:4] == "/api":
            return Response({"message": "Rescan launched"}, status=status.HTTP_200_OK)
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


def _nmap_results_to_network(scan_id, project_id, request):
    """Map rows from tools.NmapResultDb into NetworkScanResultsDb for unified listing.

    Updates parent totals after inserting all records (including OS guess),
    so the list view doesn't show a false failure.
    """
    from tools.models import NmapResultDb
    from django.utils import timezone as _tz
    org = request.user.organization
    rows = NmapResultDb.objects.filter(scan_id=str(scan_id), organization=org)
    count = 0
    # Track best OS guess across rows
    best_os = None
    best_acc = -1
    for r in rows:
        try:
            state = (r.state or '').strip()
            state_l = state.lower()
            port_s = str(r.port or '').strip()
            proto = (r.protocol or '').strip()
            # Title reflects state; open ports say "Open port", others include state
            if state_l == 'open' or state_l.startswith('open'):
                title = f"Open port {port_s}/{proto}"
            else:
                human_state = state.title() if state else 'Unknown'
                title = f"Port {port_s}/{proto} - {human_state}"
            svc = (r.name or '').strip()
            ver = (r.version or '').strip()
            if svc or ver:
                title += ' - ' + ' '.join(p for p in [svc, ver] if p)
            desc_lines = []
            for k in ['state','reason','name','version','extrainfo','cpe','osfamily','vendor','osgen','accuracy']:
                val = getattr(r, k, None)
                if val:
                    desc_lines.append(f"{k}: {val}")
            description = "\n".join(desc_lines)
            from networkscanners.models import NetworkScanResultsDb
            NetworkScanResultsDb.objects.create(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=uuid.uuid4(),
                title=title,
                date_time=_tz.now(),
                severity='Info',
                severity_color='info',
                description=description,
                port=port_s,
                ip=r.ip_address or '',
                vuln_status=('Open' if (state_l == 'open' or state_l.startswith('open')) else (state.title() if state else 'Info')),
                scanner='Nmap',
                organization=org,
                created_by=request.user,
                updated_by=request.user,
            )
            count += 1
        except Exception:
            pass
        # Consider OS fields for a separate OS guess entry
        try:
            acc = int(str(getattr(r, 'accuracy', '') or '0').strip() or '0')
        except Exception:
            acc = 0
        fam = (r.osfamily or '').strip()
        ven = (r.vendor or '').strip()
        gen = (r.osgen or '').strip()
        if fam or ven or gen:
            if acc > best_acc:
                best_acc = acc
                best_os = (fam, ven, gen, acc)
    # Add a single OS guess record if available
    if best_os:
        fam, ven, gen, acc = best_os
        title = "OS guess: " + " ".join([p for p in [fam, gen, ven] if p])
        desc = f"family: {fam}\nvendor: {ven}\ngeneration: {gen}\naccuracy: {acc}"
        try:
            NetworkScanResultsDb.objects.create(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=uuid.uuid4(),
                title=title,
                date_time=_tz.now(),
                severity='Info',
                severity_color='info',
                description=desc,
                port='',
                ip='',
                vuln_status='Open',
                scanner='Nmap',
                organization=org,
                created_by=request.user,
                updated_by=request.user,
            )
        except Exception:
            pass
    # Update parent totals AFTER inserts
    from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
    qs = NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=org)
    total = qs.count()
    crit = qs.filter(severity__iexact='Critical').count()
    high = qs.filter(severity__iexact='High').count()
    med = qs.filter(severity__iexact='Medium').count()
    low = qs.filter(severity__iexact='Low').count()
    info = qs.filter(severity__istartswith='Info').count()
    try:
        from django.utils import timezone as _tz2
    except Exception:
        _tz2 = None
    msg = None if total > 0 else "Completed: no open ports detected (no findings mapped)."
    NetworkScanDb.objects.filter(scan_id=scan_id, organization=org).update(
        total_vul=total, critical_vul=crit, high_vul=high, medium_vul=med, low_vul=low, info_vul=info,
        updated_time=_tz2.now() if _tz2 else None,
        failure_reason=msg,
    )


def _run_nmap(scan_id, target, project_id, profile, os_guess, request):
    """Execute nmap, parse XML, import to DBs, and map into NetworkScanResultsDb.

    Tries SYN scan first; if XML is missing (e.g., insufficient privileges),
    falls back to TCP connect scan (-sT). Saves a failure_reason if nothing could be imported.
    """
    from django.utils import timezone as _tz
    org = request.user.organization

    import os as _os
    privileged = False
    try:
        privileged = (_os.geteuid() == 0)
    except Exception:
        privileged = False
    os_detection_enabled = os_guess and privileged

    def build_cmd(use_syn=True):
        base = ["nmap", "-Pn", "-sV"]
        base.insert(2, "-sS" if use_syn else "-sT")
        if profile == 'full':
            base += ["-p", "1-65535", "-T3"]
        else:
            base += ["-T4"]
        if os_detection_enabled:
            base += ["-O"]
        return base

    xml_path = os.path.join(tempfile.gettempdir(), f"nmap_{scan_id}.xml")
    # Prepare per-scan log path (similar to Nikto logs)
    log_dir = os.path.join(os.getcwd(), "logs", "nmap")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        pass
    log_path = os.path.join(log_dir, f"{scan_id}.log")

    def run_once(use_syn=True, max_secs=3600):
        try:
            if os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass
        cmd = build_cmd(use_syn) + ["-oX", xml_path, str(target)]
        try:
            # Append command and stream output into the log file
            with open(log_path, "a", encoding="utf-8", errors="ignore") as lf:
                try:
                    lf.write("$ "+" ".join(cmd)+"\n")
                    if os_guess and not os_detection_enabled:
                        lf.write("[archerysec] Note: OS detection (-O) disabled because container lacks root/capabilities.\n")
                except Exception:
                    pass
                proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT)
            NetworkScanDb.objects.filter(scan_id=scan_id, organization=org).update(runner_pid=str(proc.pid), updated_time=_tz.now())
            try:
                proc.wait(timeout=max_secs)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    with open(log_path, "a", encoding="utf-8", errors="ignore") as lf2:
                        lf2.write("\n[archerysec] Timeout reached: 1 hour. Process killed.\n")
                except Exception:
                    pass
                return False, "nmap timed out after 1 hour"
        except Exception as e:
            try:
                with open(log_path, "a", encoding="utf-8", errors="ignore") as lf3:
                    lf3.write(f"[archerysec] Failed to start nmap: {e}\n")
            except Exception:
                pass
            return False, f"nmap failed to start: {e}"
        try:
            return os.path.exists(xml_path) and os.path.getsize(xml_path) > 0, None
        except Exception:
            return False, "nmap produced no XML output"

    ok, reason = run_once(use_syn=True)
    if not ok:
        ok, reason2 = run_once(use_syn=False)
        if not ok:
            NetworkScanDb.objects.filter(scan_id=scan_id, organization=org).update(
                scan_status='100', failure_reason=(reason2 or reason or "nmap run failed"), runner_pid=None, updated_time=_tz.now(),
            )
            return

    # Parse XML
    try:
        tree = ET.parse(xml_path)
        root_xml = tree.getroot()
        nmap_parser.xml_parser(root=root_xml, project_id=project_id, scan_id=scan_id, request=request)
        _nmap_results_to_network(scan_id, project_id, request)
        NetworkScanDb.objects.filter(scan_id=scan_id, organization=org).update(scan_status='100', failure_reason=None, runner_pid=None, updated_time=_tz.now())
    except Exception as e:
        try:
            with open(log_path, "a", encoding="utf-8", errors="ignore") as lf4:
                lf4.write(f"[archerysec] Parse error: {e}\n")
        except Exception:
            pass
        NetworkScanDb.objects.filter(scan_id=scan_id, organization=org).update(
            scan_status='100', failure_reason=f"nmap parse error: {str(e)[:180]}", runner_pid=None, updated_time=_tz.now(),
        )


class NmapLaunch(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        # Inputs
        scan_ip = request.POST.get("ip")
        project_uu_id = request.POST.get("project_id")
        profile = request.POST.get("nmap_profile") or 'quick'  # quick|full
        os_guess = (str(request.POST.get("nmap_os_guess")).lower() in ('1','true','on','yes'))
        # Resolve project safely: accept UUID or fallback to a recent project in org
        from uuid import UUID as _UUID
        base_projects = ProjectDb.objects.filter(organization=request.user.organization)
        proj_row = None
        if project_uu_id:
            try:
                proj_row = base_projects.filter(uu_id=_UUID(str(project_uu_id))).values("id").first()
            except Exception:
                proj_row = None
        if not proj_row:
            proj_row = base_projects.order_by("-updated_time", "-created_time").values("id").first()
        if not proj_row:
            return HttpResponse("No project available. Please create a project first.", status=400)
        project_id = proj_row["id"]
        targets, invalid_targets = _parse_ip_targets(scan_ip)
        if (not targets) or invalid_targets:
            msg = _ip_error_message(invalid_targets)
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        for target in targets:
            scan_id = uuid.uuid4()
            from django.utils import timezone as _tz
            NetworkScanDb.objects.create(
                scan_id=str(scan_id),
                project_id=str(project_id),
                ip=str(target),
                date_time=_tz.now(),
                scan_status='0',
                scanner='Nmap',
                scan_type='Nmap ' + ('Full' if profile=='full' else 'Quick') + (' + OS' if os_guess else ''),
                organization=request.user.organization,
                created_by=request.user,
                updated_by=request.user,
            )
            thread = threading.Thread(target=_run_nmap, args=(scan_id, target, project_id, profile, os_guess, request))
            thread.daemon = True
            thread.start()
        return HttpResponse(status=200)


class NetworkStop(APIView):
    permission_classes = (IsAuthenticated, permissions.IsViewer)

    def post(self, request):
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        base_qs = NetworkScanDb.objects.filter(scan_id=scan_id)
        if not is_admin:
            base_qs = base_qs.filter(organization=request.user.organization)
        row = base_qs.first()
        if not row:
            return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        if (not is_admin) and getattr(row, "created_by_id", None) != getattr(request.user, "id", None):
            return Response({"message": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        target_org = getattr(row, "organization", None) or getattr(request.user, "organization", None)

        # If this is an Nmap task, kill the runner process by PID
        if row and str(getattr(row, 'scanner', '')).lower() == 'nmap':
            pid = None
            try:
                pid = int((row.runner_pid or '').strip()) if (row.runner_pid or '').strip() else None
            except Exception:
                pid = None
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
        # Best-effort: also try to stop the OpenVAS task using the manager
        try:
            # Reuse configured settings via plugin
            sel_profile = None
            dummy_target = "127.0.0.1"
            ov = OpenVAS_Plugin(dummy_target, None, sel_profile, request, organization=target_org)
            scanner = ov.connect()
            try:
                # openvas_lib may expose stop_scan
                scanner.stop_scan(str(scan_id))
            except Exception:
                try:
                    scanner.cancel_scan(str(scan_id))
                except Exception:
                    pass
        except Exception:
            pass

        from django.utils import timezone as _tz
        NetworkScanDb.objects.filter(scan_id=scan_id, organization=target_org).update(
            failure_reason="Stopped by user",
            scan_status=NetworkScanDb.objects.filter(scan_id=scan_id, organization=target_org).values_list('scan_status', flat=True).first() or '0',
            runner_pid=None,
            updated_time=_tz.now(),
        )

        if request.path[:4] == "/api":
            return Response({"message": "Stop requested"}, status=status.HTTP_200_OK)
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScanSummaries(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        ids = request.GET.get("ids", "").split(",")
        ids = [i.strip() for i in ids if i.strip()]
        if not ids:
            return Response({}, status=status.HTTP_200_OK)
        base_results = NetworkScanResultsDb.objects.filter(
            scan_id=OuterRef("scan_id"), organization=request.user.organization
        )
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]
        base_qs = NetworkScanDb.objects.filter(organization=request.user.organization, scan_id__in=ids)
        try:
            role_name = str(getattr(request.user, "role", ""))
            is_admin = (role_name == "Admin") or getattr(request.user, "is_superuser", False)
            is_org_admin = (role_name == "Organization Admin")
        except Exception:
            is_admin = False
            is_org_admin = False
        if not is_admin:
            if is_org_admin:
                # Org Admin: allow polling any scan within their organization
                base_qs = base_qs.filter(organization=request.user.organization)
            else:
                # Regular users: only own scans
                base_qs = base_qs.filter(created_by=request.user)
        qs = (
            base_qs
            .annotate(
                result_count=Coalesce(Subquery(res_count_sq, output_field=IntegerField()), 0),
                res_critical=Coalesce(Subquery(crit_count_sq, output_field=IntegerField()), 0),
                res_high=Coalesce(Subquery(high_count_sq, output_field=IntegerField()), 0),
                res_medium=Coalesce(Subquery(med_count_sq, output_field=IntegerField()), 0),
                res_low=Coalesce(Subquery(low_count_sq, output_field=IntegerField()), 0),
                res_info=Coalesce(Subquery(info_count_sq, output_field=IntegerField()), 0),
                res_dup=Coalesce(Subquery(dup_count_sq, output_field=IntegerField()), 0),
                latest_result_time=Subquery(latest_result_dt_sq),
            )
        )
        from django.utils import timezone as _tz
        now = _tz.now()
        data = {}
        for row in qs:
            def _to_int(val):
                try:
                    s = str(val).strip()
                    return int(float(s)) if s else 0
                except Exception:
                    return 0
            percent = _to_int(getattr(row, "scan_status", 0))
            last_times = [getattr(row, "latest_result_time", None), getattr(row, "updated_time", None), getattr(row, "created_time", None)]
            last_times = [t for t in last_times if t]
            last_update = max(last_times) if last_times else None
            stopped = (
                (getattr(row, 'failure_reason', '') == 'Stopped by user') or
                (percent < 100 and last_update is not None and (now - last_update).total_seconds() > 15*60)
            )
            data[str(row.scan_id)] = {
                "scan_status": str(row.scan_status),
                "result_count": row.result_count,
                "res_critical": row.res_critical,
                "res_high": row.res_high,
                "res_medium": row.res_medium,
                "res_low": row.res_low,
                "res_info": row.res_info,
                "res_dup": row.res_dup,
                "total_vul": (row.critical_vul or 0) + (row.high_vul or 0) + (row.medium_vul or 0) + (row.low_vul or 0) + (row.info_vul or 0),
                "critical_vul": row.critical_vul or 0,
                "high_vul": row.high_vul or 0,
                "medium_vul": row.medium_vul or 0,
                "low_vul": row.low_vul or 0,
                "info_vul": row.info_vul or 0,
                "total_dup": int(row.total_dup or 0),
                "ui_stopped": stopped,
                "failure_reason": row.failure_reason or "",
            }
        from rest_framework.response import Response as _Resp
        resp = _Resp(data, status=200)
        try:
            resp['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp['Pragma'] = 'no-cache'
        except Exception:
            pass
        return resp


class NetworkScanRecent(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        from django.utils.dateparse import parse_datetime
        since_raw = request.GET.get("since")
        since = None
        if since_raw:
            try:
                since = parse_datetime(since_raw)
            except Exception:
                since = None
        from django.utils import timezone as _tz
        if since is None:
            since = _tz.now() - _tz.timedelta(minutes=10)

        # Build queryset unsliced, then apply any role filters, then slice
        base_qs = NetworkScanDb.objects.filter(
            organization=request.user.organization,
            updated_time__gt=since,
        ).order_by("-updated_time")
        try:
            role_name = str(getattr(request.user, "role", ""))
            is_admin = (role_name == "Admin") or getattr(request.user, "is_superuser", False)
            is_org_admin = (role_name == "Organization Admin")
        except Exception:
            is_admin = False
            is_org_admin = False
        if not is_admin:
            if is_org_admin:
                # Already org-scoped above; no extra filter required
                pass
            else:
                base_qs = base_qs.filter(created_by=request.user)

        # Limit AFTER all filters to avoid slicing-then-filtering assertion
        base_qs = base_qs[:100]

        # Icon path mapping via parser_dict
        try:
            from scanners.scanner_parser.scanner_parser import icon_dict as _icons
        except Exception:
            _icons = {}

        items = []
        for row in base_qs:
            icon = _icons.get(getattr(row, "scanner", ""), {}).get("icon", "/static/tools/unknown.png")
            items.append({
                "scan_id": str(row.scan_id),
                "scanner": row.scanner or "",
                "scan_type": getattr(row, "scan_type", "") or "",
                "ip": getattr(row, "ip", "") or "",
                "date_time": getattr(row, "date_time", None).isoformat() if getattr(row, "date_time", None) else None,
                "updated_time": getattr(row, "updated_time", None).isoformat() if getattr(row, "updated_time", None) else None,
                "scan_status": str(getattr(row, "scan_status", "0")),
                "icon": icon,
            })
        from rest_framework.response import Response as _Resp
        resp2 = _Resp({"items": items, "since": _tz.now().isoformat()}, status=200)
        try:
            resp2['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp2['Pragma'] = 'no-cache'
        except Exception:
            pass
        return resp2


class NetworkScanRow(APIView):
    """Return rendered HTML for a single scan row (used for live row refresh)."""
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        sid = request.GET.get("scan_id")
        if not sid:
            return Response({"error": "scan_id required"}, status=400)
        try:
            # Build base queryset (org-scoped); reduce complexity to avoid DB-specific subquery issues
            qs = NetworkScanDb.objects.filter(organization=request.user.organization, scan_id=sid)
            try:
                role_name = str(getattr(request.user, "role", ""))
                is_admin = (role_name == "Admin") or getattr(request.user, "is_superuser", False)
                is_org_admin = (role_name == "Organization Admin")
            except Exception:
                is_admin = False
                is_org_admin = False
            if not is_admin:
                if is_org_admin:
                    # Org Admin can refresh rows within org
                    qs = qs.filter(organization=request.user.organization)
                else:
                    qs = qs.filter(created_by=request.user)
            row = qs.first()
            if not row:
                return Response({"error": "not found"}, status=404)
            # Compute related counts with a single aggregate to avoid subqueries
            from django.db.models import Q
            agg = NetworkScanResultsDb.objects.filter(
                scan_id=sid, organization=request.user.organization
            ).aggregate(
                result_count=Count('id'),
                res_critical=Count('id', filter=Q(severity__iexact='Critical')),
                res_high=Count('id', filter=Q(severity__iexact='High')),
                res_medium=Count('id', filter=Q(severity__iexact='Medium')),
                res_low=Count('id', filter=Q(severity__iexact='Low')),
                res_info=Count('id', filter=Q(severity__istartswith='Info')),
                res_dup=Count('id', filter=Q(vuln_duplicate='Yes')),
                latest_result_time=Max('date_time'),
            )
            for k, v in agg.items():
                setattr(row, k, v or 0)
            # Compute flags
            from django.utils import timezone as _tz
            def _to_int(val):
                try:
                    s = str(val).strip(); return int(float(s)) if s else 0
                except Exception:
                    return 0
            percent = _to_int(getattr(row, "scan_status", 0))
            last_times = [getattr(row, "latest_result_time", None), getattr(row, "updated_time", None), getattr(row, "created_time", None)]
            last_times = [t for t in last_times if t]
            last_update = max(last_times) if last_times else None
            stopped = ((getattr(row, 'failure_reason', '') == 'Stopped by user') or (percent < 100 and last_update is not None and (_tz.now() - last_update).total_seconds() > 15*60))
            setattr(row, 'ui_stopped', stopped)
            setattr(row, 'ui_last_update', last_update)

            # Render the partial row template
            try:
                from scanners.scanner_parser.scanner_parser import icon_dict as _icons
            except Exception:
                _icons = {}
            html = render(request, "networkscanners/scans/_row.html", {"data": row, "orgs": None, "PARSER_DICT": _icons}).content.decode("utf-8")
            from rest_framework.response import Response as _Resp
            resp = _Resp({"html": html}, status=200)
            try:
                resp['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                resp['Pragma'] = 'no-cache'
            except Exception:
                pass
            return resp
        except Exception as e:
            return Response({"error": str(e)[:200]}, status=500)


class NmapLog(APIView):
    # Allow all authenticated users (Admin, Organization Admin, Normal User)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET.get("scan_id")
        if not scan_id:
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))
        # Ensure the user has access to this scan id
        is_admin = getattr(request.user, 'is_superuser', False) or str(getattr(request.user, 'role', '')) in ('Admin', 'Organization Admin')
        if is_admin:
            exists = NetworkScanDb.objects.filter(scan_id=scan_id).exists()
        else:
            exists = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            ).exists()
        if not exists:
            return HttpResponse("Log not found or access denied", status=404)

        log_path = os.path.join(os.getcwd(), "logs", "nmap", f"{scan_id}.log")
        raw = request.GET.get("raw") == "1"
        # Optional: tail only last N KB to reduce payload (default 200KB)
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200
        full = request.GET.get("full") == "1"
        if not os.path.exists(log_path):
            if raw:
                return HttpResponse("", status=202, content_type="text/plain")
            return render(
                request,
                "networkscanners/nmap_log.html",
                {"scan_id": scan_id, "has_log": False, "initial": ""},
            )
        try:
            if full:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            else:
                # Tail last N KB
                size = os.path.getsize(log_path)
                start = max(0, size - (max_kb * 1024))
                with open(log_path, "rb") as fhb:
                    fhb.seek(start)
                    chunk = fhb.read()
                content = chunk.decode("utf-8", errors="ignore")
        except Exception as e:
            if raw:
                return HttpResponse(f"Failed to read log: {e}", status=500, content_type="text/plain")
            return render(
                request,
                "networkscanners/nmap_log.html",
                {"scan_id": scan_id, "has_log": True, "initial": f"Failed to read log: {e}"},
            )
        if raw:
            return HttpResponse(content, content_type="text/plain")
        return render(
            request,
            "networkscanners/nmap_log.html",
            {"scan_id": scan_id, "has_log": True, "initial": content},
        )


class NmapLatestLog(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        raw = request.GET.get("raw") == "1"
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200
        log_dir = os.path.join(os.getcwd(), "logs", "nmap")
        if not os.path.isdir(log_dir):
            return HttpResponse("", content_type="text/plain") if raw else HttpResponse("No Nmap logs found", status=200)
        # pick newest .log file
        candidates = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.log')]
        if not candidates:
            return HttpResponse("", content_type="text/plain") if raw else HttpResponse("No Nmap logs found", status=200)
        latest = max(candidates, key=lambda p: os.path.getmtime(p))
        try:
            size = os.path.getsize(latest)
            start = max(0, size - (max_kb * 1024))
            with open(latest, 'rb') as fh:
                fh.seek(start)
                chunk = fh.read()
            content = chunk.decode('utf-8', errors='ignore')
        except Exception as e:
            content = f"Failed to read log: {e}"
        return HttpResponse(content, content_type="text/plain") if raw else HttpResponse(content, status=200)


class OpenVASLog(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        role = str(getattr(request.user, 'role', ''))
        if not (getattr(request.user, 'is_superuser', False) or role in ('Admin', 'Organization Admin')):
            return HttpResponse("Forbidden", status=403)

        scan_id = request.GET.get("scan_id")
        if not scan_id:
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))
        is_admin = getattr(request.user, 'is_superuser', False) or str(getattr(request.user, 'role', '')) in ('Admin', 'Organization Admin')
        if is_admin:
            exists = NetworkScanDb.objects.filter(scan_id=scan_id).exists()
        else:
            exists = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            ).exists()
        if not exists:
            return HttpResponse("Log not found or access denied", status=404)

        # Primary per-scan log
        log_path = os.path.join(os.getcwd(), "logs", "openvas", f"{scan_id}.log")
        raw = request.GET.get("raw") == "1"
        native = request.GET.get("native") == "1"  # include container/native logs only when requested
        full = request.GET.get("full") == "1"
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200

        def _read(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    return fh.read()
            except Exception:
                return None

        content_parts = []
        # Prefer per-scan log and tail by default
        if os.path.exists(log_path):
            if full:
                primary = _read(log_path)
            else:
                try:
                    size = os.path.getsize(log_path)
                    start = max(0, size - (max_kb * 1024))
                    with open(log_path, "rb") as fhb:
                        fhb.seek(start)
                        chunk = fhb.read()
                    primary = chunk.decode("utf-8", errors="ignore")
                except Exception:
                    primary = _read(log_path)
        else:
            primary = None

        # Build candidate list for native OpenVAS logs (may include multiple files)
        sec_candidates = []
        env_path = os.getenv("OPENVAS_SECONDARY_LOG")
        if env_path:
            sec_candidates.append(env_path)
        sec_candidates.extend([
            "/shared-ov/openvasmd.log",
            "/shared-ov/openvassd.messages",
            "/shared-ov/gvmd.log",
            "/shared-ov/openvas.log",
            "/var/log/openvas/openvasmd.log",
            "/var/log/openvas/openvassd.messages",
            "/var/log/gvm/gvmd.log",
        ])
        # Legacy app-side stream path (only as last resort)
        sec_candidates.append(os.path.join(os.getcwd(), "logs", "customarcherysecopenvas.log"))

        native_logs = []
        if native:
            for cand in sec_candidates:
                try:
                    if cand and os.path.exists(cand):
                        data = _read(cand)
                        if data is not None:
                            # Tail container logs as well unless full requested
                            if not full and len(data) > max_kb * 1024:
                                data = data[-max_kb * 1024 :]
                            native_logs.append((cand, data))
                except Exception:
                    continue

        # Prefer native logs; only fall back to per-scan file when explicitly requested via ?fallback=1
        allow_fallback = request.GET.get("fallback", "0") == "1"
        if native_logs:
            # If we have container-native files (mounted under /shared-ov or /var/log),
            # hide the legacy app stream file (customarcherysecopenvas.log)
            has_container_native = any(
                p.startswith("/shared-ov/") or p.startswith("/var/log/") for p, _ in native_logs
            )
            if has_container_native:
                native_logs = [
                    (p, d) for (p, d) in native_logs if not p.endswith("customarcherysecopenvas.log")
                ]
            for path, data in native_logs:
                header = f"----- Native: {os.path.basename(path)} -----\n"
                content_parts.append(header + (data or ""))
        elif primary is not None:
            # Explicit fallback to per-scan file if requested via ?fallback=1
            content_parts.append(f"----- Scan {scan_id}.log -----\n" + primary)

        if not content_parts:
            # No files found: quick, non-blocking message with guidance
            tips = [
                "No OpenVAS native log visible to the app.",
                "Ensure the openvas service log directory is mounted to the web container (ovlogs),",
                "and OPENVAS_SECONDARY_LOG points to the correct file (often /shared-ov/openvasmd.log or /shared-ov/openvassd.messages).",
                "Checked locations:",
            ] + [f"  - {p}" for p in sec_candidates] + [
                "Per-scan file:",
                f"  - {os.path.join(os.getcwd(), 'logs', 'openvas', f'{scan_id}.log')}",
            ]
            msg = "\n".join(tips)
            if raw:
                return HttpResponse(msg + "\n", content_type="text/plain")
            return render(
                request,
                "networkscanners/openvas_log.html",
                {"scan_id": scan_id, "has_log": False, "initial": msg},
            )

        combined = "".join(content_parts)
        if raw:
            return HttpResponse(combined, content_type="text/plain")
        return render(
            request,
            "networkscanners/openvas_log.html",
            {"scan_id": scan_id, "has_log": True, "initial": combined},
        )


class OpenVASServiceLog(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        raw = request.GET.get("raw") == "1"
        full = request.GET.get("full") == "1"
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200

        def _read(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    return fh.read()
            except Exception:
                return None

        candidates = []
        env_path = os.getenv("OPENVAS_SECONDARY_LOG")
        if env_path:
            candidates.append(env_path)
        candidates.extend([
            "/shared-ov/openvasmd.log",
            "/shared-ov/openvassd.messages",
            "/shared-ov/gvmd.log",
            "/shared-ov/openvas.log",
            "/var/log/openvas/openvasmd.log",
            "/var/log/openvas/openvassd.messages",
            "/var/log/gvm/gvmd.log",
        ])

        native_logs = []
        for cand in candidates:
            try:
                if cand and os.path.exists(cand):
                    data = _read(cand)
                    if data is not None:
                        if not full and len(data) > max_kb * 1024:
                            data = data[-max_kb * 1024:]
                        native_logs.append((cand, data))
            except Exception:
                continue

        if not native_logs:
            msg = "\n".join(["No OpenVAS native logs visible. Checked:"] + [f"  - {p}" for p in candidates])
            return HttpResponse(msg + "\n", content_type="text/plain") if raw else HttpResponse(msg, status=200)

        combined = []
        for path, data in native_logs:
            header = f"----- {os.path.basename(path)} -----\n"
            combined.append(header + (data or ""))
        payload = "".join(combined)
        return HttpResponse(payload, content_type="text/plain") if raw else HttpResponse(payload, status=200)






