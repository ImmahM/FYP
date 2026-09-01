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

import json
import os
import threading
import time
import uuid
from datetime import datetime

import defusedxml.ElementTree as ET
import pytz
from django.conf import settings
from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.utils import timezone
from lxml import etree
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from projects.models import ProjectDb
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from scheduler import background_tasks as scheduler
from user_management import permissions
from webscanners.models import (
    WebScansDb,
    cookie_db,
    excluded_db,
    task_schedule_db,
)
from webscanners.zapscanner.views import _build_zap_scan_type

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
    try:
        val = str(value).strip().lower()
    except Exception:
        return default
    return val in ("1", "true", "on", "yes")


def _summarize_nikto(flags):
    if flags.get("nikto_comprehensive"):
        return "Nikto Comprehensive"
    labels = []
    if flags.get("nikto_baseline"):
        labels.append("Baseline")
    if flags.get("nikto_injection"):
        labels.append("Injection")
    if flags.get("nikto_broad"):
        labels.append("Broad")
    return "Nikto " + (" + ".join(labels) if labels else "Default")


def _build_nikto_schedule_config(flags):
    """Return the derived Nikto options used by the runtime launcher."""
    config = dict(flags)
    profile_tuning = None
    pause_sec = None
    evasion = None
    # Match the runtime presets used by the on-demand Nikto launch
    if flags.get("nikto_comprehensive"):
        profile_tuning = "57"
        evasion = "248"
        pause_sec = 10
    elif flags.get("nikto_injection"):
        profile_tuning = "49a"
        evasion = "17"
        pause_sec = 7
    elif flags.get("nikto_baseline"):
        profile_tuning = "3b"
        pause_sec = 5
    elif flags.get("nikto_broad"):
        profile_tuning = "x6"
        pause_sec = 6
    config.update(
        profile_tuning=profile_tuning,
        pause_sec=pause_sec,
        evasion=evasion,
        plugins_all=False,
        force_cgi=False,
        maxtime_min=None,
        user_agent=None,
        extra_flags=None,
        timeout_s=15,
    )
    return config


def error_404_view(request):
    return render(request, "error/404.html")


class DeleteNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        notify_id = request.GET["notify_id"]
        # Only delete current user's own notifications
        notify_del = Notification.objects.filter(id=notify_id, recipient=request.user)
        notify_del.delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))


class DeleteAllNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # Only clear current user's notifications
        Notification.objects.filter(recipient=request.user).delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))


class NotificationFeed(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        limit = request.GET.get("limit", "6")
        try:
            limit = max(1, min(int(limit), 20))
        except Exception:
            limit = 6
        notifications = (
            Notification.objects.filter(recipient=request.user)
            .order_by("-timestamp")[:limit]
        )
        items = []
        for note in notifications:
            timestamp = note.timestamp
            if timestamp:
                timestamp = (
                    timestamp.astimezone(LOCAL_TZ).strftime("%d %b %Y %I:%M %p")
                )
            items.append(
                {
                    "id": note.id,
                    "verb": note.verb,
                    "timestamp": timestamp or "",
                    "unread": note.unread,
                }
            )
        unread_count = Notification.objects.filter(
            recipient=request.user, unread=True
        ).count()
        return JsonResponse({"unread": unread_count, "items": items})


class Index(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/webscanner.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        # Only show own scans for non-admins
        try:
            is_admin = (
                str(getattr(request.user, "role", "")) in ("Admin", "Organization Admin")
            ) or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        all_scans = WebScansDb.objects.filter(organization=request.user.organization)
        if not is_admin:
            all_scans = all_scans.filter(created_by=request.user)
        all_excluded_url = excluded_db.objects.filter()
        all_cookies = cookie_db.objects.filter()

        all_scans_db = ProjectDb.objects.filter(organization=request.user.organization)

        all_notify = Notification.objects.unread()

        return render(
            request,
            "webscanners/webscanner.html",
            {
                "all_scans": all_scans,
                "all_excluded_url": all_excluded_url,
                "all_cookies": all_cookies,
                "all_scans_db": all_scans_db,
                "message": all_notify,
            },
        )



class WebScanSchedule(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_scans_db = ProjectDb.objects.filter(
            organization=request.user.organization
        ).order_by("project_name")
        all_scheduled_scans = (
            task_schedule_db.objects.filter(
                organization=request.user.organization, created_by=request.user
            )
            .select_related("project")
            .order_by("schedule_time_utc", "id")
        )
        project_lookup = {str(p.id): p for p in all_scans_db}
        for s in all_scheduled_scans:
            try:
                key = str(getattr(s, "project_id", "") or "")
                s.project_obj = project_lookup.get(key)
            except Exception:
                s.project_obj = None
        project_lookup = {str(p.id): p for p in all_scans_db}
        for s in all_scheduled_scans:
            try:
                key = str(getattr(s, "project_id", "") or "")
                s.project_obj = project_lookup.get(key)
            except Exception:
                s.project_obj = None
        return render(
            request,
            "webscanners/web_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )

    def post(self, request):
        all_scans_db = ProjectDb.objects.filter(
            organization=request.user.organization
        ).order_by("project_name")
        all_scheduled_scans = (
            task_schedule_db.objects.filter(
                organization=request.user.organization, created_by=request.user
            )
            .select_related("project")
            .order_by("schedule_time_utc", "id")
        )
        project_lookup = {str(p.id): p for p in all_scans_db}
        for s in all_scheduled_scans:
            try:
                key = str(getattr(s, "project_id", "") or "")
                s.project_obj = project_lookup.get(key)
            except Exception:
                s.project_obj = None
        scan_url = (request.POST.get("url") or "").strip()
        scan_schedule_time = request.POST.get("datetime")
        project_id = request.POST.get("project_id") or None
        if project_id:
            try:
                project_id = int(project_id)
            except (TypeError, ValueError):
                project_id = None
        periodic_task_value = request.POST.get("periodic_task_value")
        user_role = str(getattr(request.user, "role", "") or "")
        is_scanner_admin = request.user.is_superuser or user_role in ("Admin", "Organization Admin")

        local_dt = _parse_local_datetime(scan_schedule_time)
        if not local_dt:
            messages.error(
                request,
                "Invalid schedule time. Please pick a valid date/time (24h + AM/PM).",
            )
            return render(
                request,
                "webscanners/web_scan_schedule.html",
                {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
            )
        schedule_utc = local_dt.astimezone(timezone.utc)

        zap_flags = {
            "zap_spider": _bool_from_value(request.POST.get("zap_spider")),
            "zap_ajax_spider": _bool_from_value(request.POST.get("zap_ajax_spider")),
            "zap_pscan_wait": _bool_from_value(request.POST.get("zap_pscan_wait")),
            "zap_active_scan": _bool_from_value(request.POST.get("zap_active_scan")),
            "zap_forced_browse": _bool_from_value(request.POST.get("zap_forced_browse")),
        }
        nikto_flags = {
            "nikto_baseline": _bool_from_value(request.POST.get("ws_baseline")),
            "nikto_injection": _bool_from_value(request.POST.get("ws_injection")),
            "nikto_comprehensive": _bool_from_value(
                request.POST.get("ws_comprehensive")
            ),
            "nikto_broad": _bool_from_value(request.POST.get("ws_broad")),
        }
        schedule_entries = []
        # Non-admins cannot toggle individual ZAP steps, so default to spider + active.
        if not is_scanner_admin:
            if not any(zap_flags.values()):
                zap_flags["zap_spider"] = True
                zap_flags["zap_active_scan"] = True
        zap_selected = (
            (is_scanner_admin and (
                _bool_from_value(request.POST.get("run_zap")) or any(zap_flags.values())
            ))
            or (not is_scanner_admin)
        )
        if zap_selected:
            if not any(zap_flags.values()):
                messages.error(request, "Select at least one ZAP scan step to schedule.")
                return render(
                    request,
                    "webscanners/web_scan_schedule.html",
                    {
                        "all_scans_db": all_scans_db,
                        "all_scheduled_scans": all_scheduled_scans,
                    },
                )
            zap_summary = _build_zap_scan_type(
                zap_flags["zap_spider"],
                zap_flags["zap_ajax_spider"],
                zap_flags["zap_pscan_wait"],
                zap_flags["zap_active_scan"],
                zap_flags["zap_forced_browse"],
            )
            if not is_scanner_admin:
                zap_summary = zap_summary.replace("ZAP", "Web", 1)
            schedule_entries.append(
                {
                    "scanner": "zap_scan",
                    "scan_type": zap_summary,
                    "scan_config": zap_flags,
                }
            )
        nikto_selected = False
        nikto_selected = _bool_from_value(request.POST.get("run_ws")) or any(
            nikto_flags.values()
        )
        if nikto_selected:
            if not any(nikto_flags.values()):
                messages.error(request, "Pick at least one Nikto profile to schedule.")
                return render(
                    request,
                    "webscanners/web_scan_schedule.html",
                    {
                        "all_scans_db": all_scans_db,
                        "all_scheduled_scans": all_scheduled_scans,
                    },
                )
            schedule_entries.append(
                {
                    "scanner": "nikto_scan",
                    "scan_type": _summarize_nikto(nikto_flags),
                    "scan_config": _build_nikto_schedule_config(nikto_flags),
                }
            )
        if not schedule_entries:
            messages.error(
                request,
                "Select at least one scanner (ZAP or Nikto) before saving a schedule.",
            )
            return render(
                request,
                "webscanners/web_scan_schedule.html",
                {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
            )

        created = 0
        target__split = scan_url.replace("\n", ",").split(",")
        for target in target__split:
            target = (target or "").strip()
            if not target:
                continue
            for entry in schedule_entries:
                schedule = task_schedule_db.objects.create(
                    target=target,
                    schedule_time=_format_local(schedule_utc),
                    schedule_time_utc=schedule_utc,
                    last_run_at=None,
                    project_id=project_id,
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
                scheduler.register_web_schedule(schedule)
                created += 1
        if created:
            messages.success(
                request,
                f"Scheduled {created} scan{'s' if created != 1 else ''} successfully.",
            )

        all_scheduled_scans = (
            task_schedule_db.objects.filter(
                organization=request.user.organization, created_by=request.user
            )
            .select_related("project")
            .order_by("schedule_time_utc", "id")
        )
        return render(
            request,
            "webscanners/web_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )


class WebScanScheduleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        for i in range(0, split_length):
            entry_id = target_split.__getitem__(i)
            schedules = task_schedule_db.objects.filter(
                task_id=entry_id, organization=request.user.organization
            )
            for schedule in schedules:
                scheduler.cancel_schedule("web", schedule.id)
            schedules.delete()

        return HttpResponseRedirect(reverse("webscanners:web_scan_schedule"))


class AddCookies(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(request, "webscanners/cookie_add.html")

    def post(self, request):
        target_url = request.POST.get("url")
        target_cookies = request.POST.get("cookies")
        all_cookie_url = cookie_db.objects.filter(Q(url__icontains=target_url))
        for da in all_cookie_url:
            global cookies
            cookies = da.url

        if cookies == target_url:
            cookie_db.objects.filter(Q(url__icontains=target_url)).update(
                cookie=target_cookies
            )
            return HttpResponseRedirect(reverse("webscanners:index"))
        else:
            data_dump = cookie_db(url=target_url, cookie=target_cookies)
            data_dump.save()
            return HttpResponseRedirect(reverse("webscanners:index"))
