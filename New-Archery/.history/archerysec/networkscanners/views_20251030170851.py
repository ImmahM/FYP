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
from django.db.models import OuterRef, Subquery, IntegerField, Count
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
from user_management import permissions

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
    to_mail = ""
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        pass


def openvas_scanner(scan_ip, project_id, sel_profile, user, request):
    """
    The function is launch the OpenVAS scans.
    :param scan_ip:
    :param project_id:
    :param sel_profile:
    :return:
    """
    # Ensure org-level OpenVAS connector is configured/enabled; users rely on admin's connector
    try:
        from archerysettings.models import SettingsDb as _SettingsDb
        has_connector = _SettingsDb.objects.filter(
            setting_scanner="Openvas",
            organization=request.user.organization,
            setting_status=True,
        ).exists()
    except Exception:
        has_connector = False
    if not has_connector:
        notify.send(user, recipient=user, verb="OpenVAS Setting not configured for your organization")
        return

    openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request)
    try:
        scanner = openvas.connect()
    except Exception:
        notify.send(user, recipient=user, verb="OpenVAS Setting not configured")
        subject = "Archery Tool Notification"
        message = "OpenVAS Scanner failed due to setting not found "
        email_notify(user=user, subject=subject, message=message)
        return

    notify.send(user, recipient=user, verb="OpenVAS Scan Started")
    subject = "Archery Tool Notification"
    message = "OpenVAS Scan Started"
    email_notify(user=user, subject=subject, message=message)

    # Launch scan and create DB row immediately so it appears in UI
    try:
        scan_id, target_id = openvas.scan_launch(scanner)
    except Exception:
        notify.send(user, recipient=user, verb="OpenVAS scan launch failed")
        return
    date_time = timezone.now()
    ip_clean = str(scan_ip).strip()
    try:
        NetworkScanDb.objects.update_or_create(
            scan_id=str(scan_id),
            organization=request.user.organization,
            defaults=dict(
                project_id=str(project_id),
                ip=ip_clean,
                date_time=date_time,
                scan_status=0.0,
                scanner="Openvas",
                scan_type=str(sel_profile or "Full and fast"),
                failure_reason=None,
                created_by=request.user,
                updated_by=request.user,
            ),
        )
    except Exception:
        pass

    # Defer long-running status + parse to a monitor thread for responsiveness
    def _monitor():
        failure_msg = None
        try:
            # Reconnect manager (fresh client) and monitor progress
            mgr = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request).connect()
            OpenVAS_Plugin(scan_ip, project_id, sel_profile, request).scan_status(scanner=mgr, scan_id=scan_id)
        except Exception as e:
            failure_msg = f"OpenVAS status error: {str(e)[:200]}"
            try:
                from django.utils import timezone as _tz
                NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                    failure_reason=failure_msg, updated_time=_tz.now()
                )
            except Exception:
                pass
        # Parse results
        try:
            vuln_an_id(scan_id=scan_id, project_id=project_id, request=request)
        except Exception as e:
            failure_msg = failure_msg or f"OpenVAS result error: {str(e)[:200]}"
            try:
                from django.utils import timezone as _tz
                NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                    failure_reason=failure_msg, updated_time=_tz.now()
                )
            except Exception:
                pass
        # No results safety net
        try:
            from django.utils import timezone as _tz
            rc = NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=request.user.organization).count()
            if rc == 0:
                NetworkScanDb.objects.filter(
                    scan_id=scan_id,
                    organization=request.user.organization,
                    failure_reason__isnull=True,
                ).update(
                    failure_reason="No results saved for this run (check OpenVAS logs for details).",
                    updated_time=_tz.now(),
                )
        except Exception:
            pass
        notify.send(user, recipient=user, verb="OpenVAS Scan Completed")

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

    email_notify(user=user, subject=subject, message=message)

    return HttpResponse(status=201)


class OpenvasLaunchScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id, organization=request.user.organization
            )
            .values("id")
            .get()["id"]
        )
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
            msg = "OpenVAS settings are missing or disabled for your organization. Configure it under Settings → Add Connector → OpenVAS."
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
        # Split on commas or any whitespace and strip each token
        tokens = re.split(r"[\s,]+", str(scan_ip or "").strip())
        def _bad_target(t):
            tl = (t or '').strip().lower()
            return (not tl) or tl in ('localhost','127.0.0.1','::1')
        targets = [t for t in tokens if not _bad_target(t)]
        print(len(targets))

        for target in targets:
            # Launch synchronously to get scan_id, then monitor in background.
            try:
                openvas_scanner(target, project_id, sel_profile, user, request)
            except Exception:
                # If synchronous launch path fails, fall back to background attempt
                thread = threading.Thread(
                    target=openvas_scanner,
                    args=(target, project_id, sel_profile, user, request),
                )
                thread.daemon = True
                thread.start()

        if request.path[:4] == "/api":
            return Response({"message": "Openvas scan launched"})
        else:
            return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScan(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/ipscan.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        # task_id = ""

        all_scans_db = ProjectDb.objects.filter(organization=request.user.organization)
        all_scheduled_scans = TaskScheduleDb.objects.filter(
            organization=request.user.organization
        )
        return render(
            request,
            "networkscanners/network_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )

    def post(self, request):
        scan_ip = request.POST.get("ip")
        scan_schedule_time = request.POST.get("datetime")
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        periodic_task_value = request.POST.get("periodic_task_value")

        if periodic_task_value == "HOURLY":
            periodic_time = Task.HOURLY
        elif periodic_task_value == "DAILY":
            periodic_time = Task.DAILY
        elif periodic_task_value == "WEEKLY":
            periodic_time = Task.WEEKLY
        elif periodic_task_value == "EVERY_2_WEEKS":
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == "EVERY_4_WEEKS":
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None

        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y %H:%M:%S %p")

        # task(scan_ip, project_id, schedule=dt_obj)
        ip = scan_ip.replace(" ", "")
        target__split = ip.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == "open_vas":
                if periodic_task_value == "None":
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id
                else:
                    my_task = task(
                        target,
                        project_id,
                        scanner,
                        repeat=periodic_time,
                        repeat_until=None,
                    )
                    task_id = my_task.id
                    print("Savedddddd taskid"), task_id

            save_scheadule = TaskScheduleDb(
                task_id=task_id,
                target=target,
                schedule_time=scan_schedule_time,
                project_id=project_id,
                scanner=scanner,
                periodic_task=periodic_task_value,
            )
            save_scheadule.save()


class NetworkScanScheduleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/network_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = TaskScheduleDb.objects.filter(
                task_id=task_id, organization=request.user.organization
            )
            del_task.delete()
            del_task_schedule = Task.objects.filter(
                id=task_id, organization=request.user.organization
            )
            del_task_schedule.delete()

        return HttpResponseRedirect(reverse("networkscanners:net_scan_schedule"))


class OpenvasSettingEnable(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/nv_settings.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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
        # Scope by organization; admins see all org scans, others see own scans
        base_qs = NetworkScanDb.objects.filter(organization__in=org_qs)
        if not is_admin:
            base_qs = base_qs.filter(created_by=request.user)
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
    """Admin-only explorer for network scans with org/owner filters"""
    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        from user_management.models import Organization as _Org, UserProfile as _UP
        selected_org_ids = [oid for oid in request.GET.getlist("org") if oid]
        selected_owner_ids = [uid for uid in request.GET.getlist("owner") if uid]
        org_qs = _Org.objects.all() if not selected_org_ids else _Org.objects.filter(pk__in=selected_org_ids)
        owners_qs = _UP.objects.filter(organization__in=org_qs)

        # Preload org -> users map for client-side owner dropdown filtering
        org_user_map = {}
        try:
            for _o in _Org.objects.all():
                org_user_map[str(_o.id)] = [
                    {"id": str(u.id), "name": (u.name or u.email or str(u.id))}
                    for u in _UP.objects.filter(organization=_o)
                ]
        except Exception:
            org_user_map = {}

        base_results = NetworkScanResultsDb.objects.filter(scan_id=OuterRef("scan_id"), organization__in=org_qs)
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]

        base_qs = NetworkScanDb.objects.filter(organization__in=org_qs)
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

        all_notify = Notification.objects.unread()
        ctx = {
            "all_scans": list(scan_list),
            "message": all_notify,
            "orgs": _Org.objects.all(),
            "owners": owners_qs,
            "selected_org_ids": selected_org_ids,
            "selected_owner_ids": selected_owner_ids,
            "org_user_map": org_user_map,
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
            scan_qs = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False
            if not is_admin:
                scan_qs = scan_qs.filter(created_by=request.user)
            if not scan_qs.exists():
                return HttpResponseRedirect(reverse("networkscanners:list_scans"))
            vuln_data = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
        else:
            try:
                vuln_data = NetworkScanResultsDb.objects.filter(
                    scan_id=uu_id, organization=request.user.organization
                )
                scan_id = uu_id
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        if request.path[:4] == "/api":
            serialized_data = NetworkScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "networkscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url, "scan_id": str(scan_id)},
            )


class NetworkScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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

        vul_dat = NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id, scanner=scanner, organization=request.user.organization
        ).order_by("vuln_id")

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
        permissions.IsAnalyst,
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
            item = item_qs
            item.delete()
            item_results = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item_results.delete()
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

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
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        import uuid as _uuid
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            ns = NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).get()
        except Exception:
            return Response({"message": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        target = ns.ip
        project_id = ns.project_id
        user = request.user
        # Reuse previous scan_type if present; fall back to default in plugin
        sel_profile = getattr(ns, "scan_type", None)

        # Remove the existing row so the rescan replaces it (keeps a single row visible)
        try:
            NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).delete()
            NetworkScanResultsDb.objects.filter(scan_id=scan_id, organization=request.user.organization).delete()
        except Exception:
            pass

        thread = threading.Thread(
            target=openvas_scanner,
            args=(target, project_id, sel_profile, user, request),
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

    def build_cmd(use_syn=True):
        base = ["nmap", "-Pn", "-sV"]
        base.insert(2, "-sS" if use_syn else "-sT")
        if profile == 'full':
            base += ["-p", "1-65535", "-T3"]
        else:
            base += ["-T4"]
        if os_guess:
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
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        # Inputs
        scan_ip = request.POST.get("ip")
        project_uu_id = request.POST.get("project_id")
        profile = request.POST.get("nmap_profile") or 'quick'  # quick|full
        os_guess = (str(request.POST.get("nmap_os_guess")).lower() in ('1','true','on','yes'))
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id, organization=request.user.organization
            ).values("id").get()["id"]
        )
        # Split targets
        tokens = re.split(r"[\s,]+", str(scan_ip or "").strip())
        def _bad_target2(t):
            tl = (t or '').strip().lower()
            return (not tl) or tl in ('localhost','127.0.0.1','::1')
        targets = [t for t in tokens if not _bad_target2(t)]
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
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)

        # If this is an Nmap task, kill the runner process by PID
        try:
            row = NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).first()
        except Exception:
            row = None
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
            ov = OpenVAS_Plugin(dummy_target, None, sel_profile, request)
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
        NetworkScanDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
            failure_reason="Stopped by user",
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
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        if not is_admin:
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

        base_qs = NetworkScanDb.objects.filter(
            organization=request.user.organization,
            updated_time__gt=since,
        ).order_by("-updated_time")[:100]
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        if not is_admin:
            base_qs = base_qs.filter(created_by=request.user)

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
            # Scope to user's org; non-admin only their own scans
            base_results = NetworkScanResultsDb.objects.filter(scan_id=OuterRef("scan_id"), organization=request.user.organization)
            res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
            latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]

            qs = NetworkScanDb.objects.filter(organization=request.user.organization, scan_id=sid)
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False
            if not is_admin:
                qs = qs.filter(created_by=request.user)
            qs = qs.annotate(
                result_count=Coalesce(Subquery(res_count_sq, output_field=IntegerField()), 0),
                res_critical=Coalesce(Subquery(crit_count_sq, output_field=IntegerField()), 0),
                res_high=Coalesce(Subquery(high_count_sq, output_field=IntegerField()), 0),
                res_medium=Coalesce(Subquery(med_count_sq, output_field=IntegerField()), 0),
                res_low=Coalesce(Subquery(low_count_sq, output_field=IntegerField()), 0),
                res_info=Coalesce(Subquery(info_count_sq, output_field=IntegerField()), 0),
                res_dup=Coalesce(Subquery(dup_count_sq, output_field=IntegerField()), 0),
                latest_result_time=Subquery(latest_result_dt_sq),
            )
            row = qs.first()
            if not row:
                return Response({"error": "not found"}, status=404)
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
            html = render(request, "networkscanners/scans/_row.html", {"data": row, "orgs": None}).content.decode("utf-8")
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
        exists = NetworkScanDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        ).exists()
        if not exists:
            return HttpResponse("Log not found or access denied", status=404)

        log_path = os.path.join(os.getcwd(), "logs", "nmap", f"{scan_id}.log")
        raw = request.GET.get("raw") == "1"
        if not os.path.exists(log_path):
            if raw:
                return HttpResponse("", status=202, content_type="text/plain")
            return render(
                request,
                "networkscanners/nmap_log.html",
                {"scan_id": scan_id, "has_log": False, "initial": ""},
            )
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
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





