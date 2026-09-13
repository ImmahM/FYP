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

import datetime
import json
import calendar
from zoneinfo import ZoneInfo
from itertools import chain

from django.contrib.auth import user_logged_in
from django.contrib.auth.models import User
from django.db.models import OuterRef, Q, Subquery, Sum, Value, TextField
from django.db.models.functions import Coalesce
from django.shortcuts import HttpResponse, HttpResponseRedirect, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework.permissions import AllowAny, IsAuthenticated

from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from compliance.models import DockleScanDb, InspecScanDb
from dashboard.scans_data import scans_query
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from pentest.models import PentestScanDb, PentestScanResultsDb
from projects.models import Month, MonthDb, MonthSqlite, ProjectDb
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management import permissions
from webscanners.models import WebScanResultsDb, WebScansDb
from webscanners.resources import AllResource

# Create your views here.
chart = []
all_high_stat = ""
data = ""


def trend_update():
    current_month = ""

    all_project = ProjectDb.objects.filter()

    for project in all_project:
        proj_id = project.uu_id
        project_id = project.id
        all_date_data = (
            ProjectDb.objects.annotate(month=Month("date_time"))
            .values("month")
            .annotate(total_critical=Sum("total_critical"))
            .annotate(total_high=Sum("total_high"))
            .annotate(total_medium=Sum("total_medium"))
            .annotate(total_low=Sum("total_low"))
            .order_by("month")
        )

        try:
            critical = all_date_data.first()["total_critical"] or 0
            high = all_date_data.first()["total_high"] or 0
            medium = all_date_data.first()["total_medium"] or 0
            low = all_date_data.first()["total_low"] or 0
        except:
            all_date_data = (
                ProjectDb.objects.annotate(month=MonthSqlite("date_time"))
                .values("month")
                .annotate(total_critical=Sum("total_critical"))
                .annotate(total_high=Sum("total_high"))
                .annotate(total_medium=Sum("total_medium"))
                .annotate(total_low=Sum("total_low"))
                .order_by("month")
            )
            critical = all_date_data.first()["total_critical"] or 0
            high = all_date_data.first()["total_high"] or 0
            medium = all_date_data.first()["total_medium"] or 0
            low = all_date_data.first()["total_low"] or 0

        all_month_data_display = MonthDb.objects.all()

        # Clean up records with invalid month values
        MonthDb.objects.filter(month__in=['', 'None', None]).delete()

        if len(all_month_data_display) == 0:
            add_data = MonthDb(
                project_id=project_id,
                month=current_month,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
            )
            add_data.save()

        for data in all_month_data_display:
            current_month = datetime.datetime.now().month
            if int(current_month) == 1:
                MonthDb.objects.filter(project_id=project_id, month="2").delete()
                MonthDb.objects.filter(project_id=project_id, month="3").delete()
                MonthDb.objects.filter(project_id=project_id, month="4").delete()
                MonthDb.objects.filter(project_id=project_id, month="5").delete()
                MonthDb.objects.filter(project_id=project_id, month="6").delete()
                MonthDb.objects.filter(project_id=project_id, month="7").delete()
                MonthDb.objects.filter(project_id=project_id, month="8").delete()
                MonthDb.objects.filter(project_id=project_id, month="9").delete()
                MonthDb.objects.filter(project_id=project_id, month="10").delete()
                MonthDb.objects.filter(project_id=project_id, month="11").delete()
                MonthDb.objects.filter(project_id=project_id, month="12").delete()

            # Skip records with invalid month values
            try:
                data_month = int(data.month)
            except (ValueError, TypeError):
                continue

            match_data = MonthDb.objects.filter(
                project_id=project_id, month=current_month
            )
            if len(match_data) == 0:
                add_data = MonthDb(
                    project_id=project_id,
                    month=current_month,
                    critical=critical,
                    high=high,
                    medium=medium,
                    low=low,
                )
                add_data.save()

            elif data_month == int(current_month):
                MonthDb.objects.filter(month=current_month).update(
                    critical=critical, high=high, medium=medium, low=low
                )

        total_vuln = scans_query.all_vuln(project_id=proj_id, query="total")
        total_critical = scans_query.all_vuln(project_id=proj_id, query="critical")
        total_high = scans_query.all_vuln(project_id=proj_id, query="high")
        total_medium = scans_query.all_vuln(project_id=proj_id, query="medium")
        total_low = scans_query.all_vuln(project_id=proj_id, query="low")

        total_open = scans_query.all_vuln_count_data(project_id=proj_id, query="Open")
        total_close = scans_query.all_vuln_count_data(
            project_id=proj_id, query="Closed"
        )
        total_false = scans_query.all_vuln_count_data(project_id=proj_id, query="false")

        total_net = scans_query.all_net(project_id=proj_id, query="total")
        total_web = scans_query.all_web(project_id=proj_id, query="total")
        total_static = scans_query.all_static(project_id=proj_id, query="total")
        total_cloud = scans_query.all_cloud(project_id=proj_id, query="total")

        critical_net = scans_query.all_net(proj_id, query="critical")
        critical_web = scans_query.all_web(proj_id, query="critical")
        critical_static = scans_query.all_static(proj_id, query="critical")
        critical_cloud = scans_query.all_cloud(proj_id, query="critical")

        high_net = scans_query.all_net(proj_id, query="high")
        high_web = scans_query.all_web(proj_id, query="high")
        high_static = scans_query.all_static(proj_id, query="high")
        high_cloud = scans_query.all_cloud(proj_id, query="high")

        medium_net = scans_query.all_net(proj_id, query="medium")
        medium_web = scans_query.all_web(proj_id, query="medium")
        medium_static = scans_query.all_static(proj_id, query="medium")
        medium_cloud = scans_query.all_cloud(proj_id, query="medium")

        low_net = scans_query.all_net(proj_id, query="low")
        low_web = scans_query.all_web(proj_id, query="low")
        low_static = scans_query.all_static(proj_id, query="low")
        low_cloud = scans_query.all_cloud(proj_id, query="low")

        ProjectDb.objects.filter(uu_id=proj_id).update(
            total_vuln=total_vuln,
            total_open=total_open,
            total_close=total_close,
            total_false=total_false,
            total_net=total_net,
            total_web=total_web,
            total_static=total_static,
            total_cloud=total_cloud,
            total_critical=total_critical,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            critical_net=critical_net,
            critical_web=critical_web,
            critical_static=critical_static,
            critical_cloud=critical_cloud,
            high_net=high_net,
            high_web=high_web,
            high_static=high_static,
            high_cloud=high_cloud,
            medium_net=medium_net,
            medium_web=medium_web,
            medium_static=medium_static,
            medium_cloud=medium_cloud,
            low_net=low_net,
            low_web=low_web,
            low_static=low_static,
            low_cloud=low_cloud,
        )


def dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """
    scanners = "vscanners"

    trend_update()
    # Enforce owner isolation for non-admins: redirect to My Dashboard
    # Route everyone to the owner-scoped dashboard to avoid cross-user aggregation
    from django.http import HttpResponseRedirect
    from django.urls import reverse
    return HttpResponseRedirect(reverse("dashboard:my_dashboard"))

    all_project = ProjectDb.objects.filter(organization=request.user.organization)

    tz = ZoneInfo("Asia/Singapore")
    now = datetime.datetime.now(tz=tz)
    current_year = now.year
    current_month = now.month

    all_notify = Notification.objects.unread()

    all_month_data_display = (
        MonthDb.objects.all()
        .values("month", "critical", "high", "medium", "low")
        .distinct()
    )
    # print(MonthDb.objects.filter().values('month', 'high', 'medium', 'low').distinct())

    return render(
        request,
        "dashboard/index.html",
        {
            "all_project": all_project,
            "scanners": scanners,
            "total_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_vuln")),
            "open_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_open")),
            "close_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_close")),
            "false_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_false")),
            "net_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_net")),
            "web_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_web")),
            "static_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_static")),
            "cloud_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_cloud")),
            "critical_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_critical")),
            "high_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_high")),
            "medium_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_medium")),
            "low_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("total_low")),
            "critical_net_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("critical_net")),
            "critical_web_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("critical_web")),
            "critical_static_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("critical_static")),
            "critical_cloud_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("critical_cloud")),
            "high_net_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("high_net")),
            "high_web_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("high_web")),
            "high_static_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("high_static")),
            "high_cloud_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("high_cloud")),
            "medium_net_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("medium_net")),
            "medium_web_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("medium_web")),
            "medium_static_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("medium_static")),
            "medium_cloud_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("medium_cloud")),
            "low_net_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("low_net")),
            "low_web_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("low_web")),
            "low_static_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("low_static")),
            "low_cloud_count_project": ProjectDb.objects.filter(
                organization=request.user.organization
            ).aggregate(Sum("low_cloud")),
            "all_month_data_display": all_month_data_display,
            "current_year": current_year,
            "message": all_notify,
        },
    )


def my_dashboard(request):
    """
    Owner-scoped dashboard: show only the current user's scans and aggregates.
    """
    trend_update()

    user = request.user
    org = getattr(user, "organization", None)

    from django.db.models import Sum

    tz = ZoneInfo("Asia/Singapore")
    now = datetime.datetime.now(tz=tz)
    current_year = now.year
    current_month = now.month

    web_qs = WebScansDb.objects.filter(organization=org, created_by=user)
    net_qs = NetworkScanDb.objects.filter(organization=org, created_by=user)
    try:
        from staticscanners.models import StaticScansDb, StaticScanResultsDb
    except Exception:
        StaticScansDb = None
        StaticScanResultsDb = None
    try:
        from cloudscanners.models import CloudScansDb, CloudScansResultsDb
    except Exception:
        CloudScansDb = None
        CloudScansResultsDb = None

    static_qs = StaticScansDb.objects.filter(organization=org, created_by=user) if StaticScansDb else WebScansDb.objects.none()
    cloud_qs = CloudScansDb.objects.filter(organization=org, created_by=user) if CloudScansDb else WebScansDb.objects.none()

    def _severity_totals(qs):
        return {
            "critical": int((qs.aggregate(v=Sum("critical_vul")) or {}).get("v") or 0),
            "high": int((qs.aggregate(v=Sum("high_vul")) or {}).get("v") or 0),
            "medium": int((qs.aggregate(v=Sum("medium_vul")) or {}).get("v") or 0),
            "low": int((qs.aggregate(v=Sum("low_vul")) or {}).get("v") or 0),
            "info": int((qs.aggregate(v=Sum("info_vul")) or {}).get("v") or 0),
        }

    web_tot = _severity_totals(web_qs)
    net_tot = _severity_totals(net_qs)
    static_tot = _severity_totals(static_qs)
    cloud_tot = _severity_totals(cloud_qs)

    total_web = sum(web_tot.values())
    total_net = sum(net_tot.values())
    total_static = sum(static_tot.values())
    total_cloud = sum(cloud_tot.values())

    # Results-level counts (false positive, closed)
    web_res = WebScanResultsDb.objects.filter(organization=org, created_by=user)
    net_res = NetworkScanResultsDb.objects.filter(organization=org, created_by=user)
    static_res = StaticScanResultsDb.objects.filter(organization=org, created_by=user) if StaticScanResultsDb else WebScanResultsDb.objects.none()
    cloud_res = CloudScansResultsDb.objects.filter(organization=org, created_by=user) if CloudScansResultsDb else WebScanResultsDb.objects.none()

    def _count_false(qs):
        return int(qs.filter(false_positive__iexact="Yes").count())

    def _count_closed(qs):
        return int(qs.filter(vuln_status__iexact="Closed").count())

    total_false = _count_false(web_res) + _count_false(net_res) + _count_false(static_res) + _count_false(cloud_res)
    total_close = _count_closed(web_res) + _count_closed(net_res) + _count_closed(static_res) + _count_closed(cloud_res)

    # Build dicts matching keys expected by index.html
    total_count_project = {"total_vuln__sum": total_web + total_net + total_static + total_cloud}
    false_count_project = {"total_false__sum": total_false}
    close_count_project = {"total_close__sum": total_close}
    net_count_project = {"total_net__sum": total_net}
    web_count_project = {"total_web__sum": total_web}
    static_count_project = {"total_static__sum": total_static}
    cloud_count_project = {"total_cloud__sum": total_cloud}

    critical_count_project = {"total_critical__sum": web_tot["critical"] + net_tot["critical"] + static_tot["critical"] + cloud_tot["critical"]}
    high_count_project = {"total_high__sum": web_tot["high"] + net_tot["high"] + static_tot["high"] + cloud_tot["high"]}
    medium_count_project = {"total_medium__sum": web_tot["medium"] + net_tot["medium"] + static_tot["medium"] + cloud_tot["medium"]}
    low_count_project = {"total_low__sum": web_tot["low"] + net_tot["low"] + static_tot["low"] + cloud_tot["low"]}

    critical_net_count_project = {"critical_net__sum": net_tot["critical"]}
    critical_web_count_project = {"critical_web__sum": web_tot["critical"]}
    critical_static_count_project = {"critical_static__sum": static_tot["critical"]}
    critical_cloud_count_project = {"critical_cloud__sum": cloud_tot["critical"]}

    high_net_count_project = {"high_net__sum": net_tot["high"]}
    high_web_count_project = {"high_web__sum": web_tot["high"]}
    high_static_count_project = {"high_static__sum": static_tot["high"]}
    high_cloud_count_project = {"high_cloud__sum": cloud_tot["high"]}

    medium_net_count_project = {"medium_net__sum": net_tot["medium"]}
    medium_web_count_project = {"medium_web__sum": web_tot["medium"]}
    medium_static_count_project = {"medium_static__sum": static_tot["medium"]}
    medium_cloud_count_project = {"medium_cloud__sum": cloud_tot["medium"]}

    low_net_count_project = {"low_net__sum": net_tot["low"]}
    low_web_count_project = {"low_web__sum": web_tot["low"]}
    low_static_count_project = {"low_static__sum": static_tot["low"]}
    low_cloud_count_project = {"low_cloud__sum": cloud_tot["low"]}

    # Project list limited to projects where this user owns scans
    proj_ids = set(list(web_qs.values_list("project_id", flat=True)) + list(net_qs.values_list("project_id", flat=True)))
    proj_ids |= set(list(static_qs.values_list("project_id", flat=True))) if StaticScansDb else set()
    proj_ids |= set(list(cloud_qs.values_list("project_id", flat=True))) if CloudScansDb else set()
    proj_ids = [pid for pid in proj_ids if pid]
    all_project = ProjectDb.objects.filter(id__in=proj_ids)

    all_month_data_display = (
        MonthDb.objects.filter(project_id__in=proj_ids)
        .values("month", "critical", "high", "medium", "low")
        .order_by("month")
        .distinct()
    )

    # Daily trend for current month/year (UTC+8)
    daily_counts = {}

    def _bump_daily(qs):
        seen = set()
        for row in qs.values("vuln_id", "title", "severity", "date_time", "created_time", "scan_id", "project_id"):
            dt = row.get("date_time") or row.get("created_time")
            if not dt:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            dt = dt.astimezone(tz)
            if dt.year != current_year or dt.month != current_month:
                continue
            day = dt.day
            severity = (row.get("severity") or "").lower()
            unique_key = (
                severity,
                str(row.get("vuln_id") or "").strip()
                or str(row.get("title") or "").strip()
                or str(row.get("scan_id") or "").strip(),
                str(row.get("project_id") or "").strip(),
                dt.date(),
            )
            if unique_key in seen:
                continue
            seen.add(unique_key)
            daily_counts.setdefault(day, {}).setdefault(severity, 0)
            daily_counts[day][severity] += 1

    _bump_daily(web_res)
    _bump_daily(net_res)

    days_in_month = calendar.monthrange(current_year, current_month)[1]
    day_labels = list(range(1, days_in_month + 1))

    def _series(sev):
        return [daily_counts.get(d, {}).get(sev, 0) for d in day_labels]

    trend_daily_data = {
        "labels": day_labels,
        "critical": _series("critical"),
        "high": _series("high"),
        "medium": _series("medium"),
        "low": _series("low"),
    }

    # --- Dashboard Widgets: Recent scans, scan status counts, recent findings ---
    from itertools import chain

    def _annotate_scanner(qs, scanner_label, name_field="scan_url"):
        fields = ["scan_id", "scan_status", "date_time", "project__project_name"]
        if name_field:
            fields = ["scan_id", name_field, "scan_status", "date_time", "project__project_name"]
        items = []
        for item in qs.values(*fields).order_by("-date_time")[:20]:
            d = dict(item, scanner_type=scanner_label)
            val = d.pop(name_field, None) if name_field else None
            d["scan_url"] = val
            items.append(d)
        return items

    recent_web = _annotate_scanner(web_qs, "Web", "scan_url")
    recent_net = _annotate_scanner(net_qs, "Network", "ip")
    recent_static = _annotate_scanner(static_qs, "Static", None) if StaticScansDb else []
    recent_cloud = _annotate_scanner(cloud_qs, "Cloud", None) if CloudScansDb else []

    all_recent = sorted(
        chain(recent_web, recent_net, recent_static, recent_cloud),
        key=lambda x: x.get("date_time") or datetime.datetime.min,
        reverse=True,
    )[:10]

    # Scan status breakdown (handles both new enum values and legacy numeric strings)
    def _status_count(qs, status):
        status_lower = status.lower()
        q = Q(scan_status__iexact=status_lower)
        if status_lower == "completed":
            q |= Q(scan_status="100")
        elif status_lower == "running":
            q |= Q(scan_status__in=[str(i) for i in range(1, 100)])
        return qs.filter(q).count()

    scan_statuses = {
        "completed": (
            _status_count(web_qs, "completed")
            + _status_count(net_qs, "completed")
            + (_status_count(static_qs, "completed") if StaticScansDb else 0)
            + (_status_count(cloud_qs, "completed") if CloudScansDb else 0)
        ),
        "running": (
            _status_count(web_qs, "running")
            + _status_count(net_qs, "running")
            + (_status_count(static_qs, "running") if StaticScansDb else 0)
            + (_status_count(cloud_qs, "running") if CloudScansDb else 0)
        ),
        "failed": (
            _status_count(web_qs, "failed")
            + _status_count(net_qs, "failed")
            + (_status_count(static_qs, "failed") if StaticScansDb else 0)
            + (_status_count(cloud_qs, "failed") if CloudScansDb else 0)
        ),
    }

    # Recent high/critical findings
    def _recent_high(qs, scanner):
        return [
            dict(item, scanner_type=scanner)
            for item in qs.filter(severity__in=["High", "Critical"])
            .values("vuln_id", "title", "severity", "date_time", "project__project_name")
            .order_by("-date_time")[:5]
        ]

    recent_high = sorted(
        chain(
            _recent_high(web_res, "Web"),
            _recent_high(net_res, "Network"),
            (_recent_high(static_res, "Static") if StaticScanResultsDb else []),
            (_recent_high(cloud_res, "Cloud") if CloudScansResultsDb else []),
        ),
        key=lambda x: x.get("date_time") or datetime.datetime.min,
        reverse=True,
    )[:10]

    return render(
        request,
        "dashboard/index.html",
        {
            "all_project": all_project,
            "scanners": "vscanners",
            "total_count_project": total_count_project,
            "open_count_project": {"total_open__sum": 0},
            "close_count_project": close_count_project,
            "false_count_project": false_count_project,
            "net_count_project": net_count_project,
            "web_count_project": web_count_project,
            "static_count_project": static_count_project,
            "cloud_count_project": cloud_count_project,
            "critical_count_project": critical_count_project,
            "high_count_project": high_count_project,
            "medium_count_project": medium_count_project,
            "low_count_project": low_count_project,
            "critical_net_count_project": critical_net_count_project,
            "critical_web_count_project": critical_web_count_project,
            "critical_static_count_project": critical_static_count_project,
            "critical_cloud_count_project": critical_cloud_count_project,
            "high_net_count_project": high_net_count_project,
            "high_web_count_project": high_web_count_project,
            "high_static_count_project": high_static_count_project,
            "high_cloud_count_project": high_cloud_count_project,
            "medium_net_count_project": medium_net_count_project,
            "medium_web_count_project": medium_web_count_project,
            "medium_static_count_project": medium_static_count_project,
            "medium_cloud_count_project": medium_cloud_count_project,
            "low_net_count_project": low_net_count_project,
            "low_web_count_project": low_web_count_project,
            "low_static_count_project": low_static_count_project,
            "low_cloud_count_project": low_cloud_count_project,
            "all_month_data_display": all_month_data_display,
            "current_year": current_year,
            "message": Notification.objects.unread(),
            "trend_daily_data": json.dumps(trend_daily_data),
            "recent_scans": all_recent,
            "scan_statuses": scan_statuses,
            "recent_high": recent_high,
        },
    )


def trend_history(request):
    """
    Historical daily trend (UTC+8) for the current year; combines Web + Network findings.
    """
    tz = ZoneInfo("Asia/Singapore")
    year = datetime.datetime.now(tz=tz).year

    user = request.user
    org = getattr(user, "organization", None)

    # Scope to this user/org just like my_dashboard
    web_res = WebScanResultsDb.objects.filter(organization=org, created_by=user)
    net_res = NetworkScanResultsDb.objects.filter(organization=org, created_by=user)

    # Aggregate daily counts per severity (dedup by vuln_id+day+severity)
    counts = {}

    def _bump(qs):
        seen = set()
        for row in qs.values("vuln_id", "title", "severity", "date_time", "created_time", "scan_id", "project_id"):
            dt = row.get("date_time") or row.get("created_time")
            if not dt:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            dt = dt.astimezone(tz)
            if dt.year != year:
                continue
            severity = (row.get("severity") or "").lower()
            month = dt.month
            day = dt.day
            unique_key = (
                severity,
                str(row.get("vuln_id") or "").strip()
                or str(row.get("title") or "").strip()
                or str(row.get("scan_id") or "").strip(),
                str(row.get("project_id") or "").strip(),
                dt.date(),
            )
            if unique_key in seen:
                continue
            seen.add(unique_key)
            counts.setdefault(month, {}).setdefault(day, {}).setdefault(severity, 0)
            counts[month][day][severity] += 1

    _bump(web_res)
    _bump(net_res)

    # Build chart-friendly payload for all months in the current year
    months_payload = []
    for month in range(1, 13):
        days_in_month = calendar.monthrange(year, month)[1]
        days = list(range(1, days_in_month + 1))

        def _series(sev):
            data = []
            for day in days:
                data.append(counts.get(month, {}).get(day, {}).get(sev, 0))
            return data

        months_payload.append(
            {
                "month": month,
                "label": datetime.date(year, month, 1).strftime("%B %Y"),
                "days": days,
                "critical": _series("critical"),
                "high": _series("high"),
                "medium": _series("medium"),
                "low": _series("low"),
            }
        )

    return render(
        request,
        "dashboard/trend_history.html",
        {
            "current_year": year,
            "trend_data_json": json.dumps(months_payload),
        },
    )


def project_dashboard(request):
    """
    The function calling Project Dashboard page.
    :param request:
    :return:
    """

    scanners = "vscanners"

    all_project = ProjectDb.objects.filter(organization=request.user.organization)

    all_notify = Notification.objects.unread()

    return render(
        request,
        "dashboard/project.html",
        {"all_project": all_project, "scanners": scanners, "message": all_notify},
    )


def proj_data(request):
    """
    The function pulling all project data from database.
    :param request:
    :return:
    """
    all_project = ProjectDb.objects.filter(organization=request.user.organization)
    if request.GET["uu_id"]:
        uu_id = request.GET["uu_id"]
    else:
        uu_id = ""

    project_dat = ProjectDb.objects.filter(
        uu_id=uu_id, organization=request.user.organization
    )
    web_scan_dat = WebScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    static_scan = StaticScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    cloud_scan = CloudScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    network_dat = NetworkScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    inspec_dat = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    dockle_dat = DockleScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    compliance_dat = chain(inspec_dat, dockle_dat)
    all_comp_inspec = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_comp_dockle = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = PentestScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_notify = Notification.objects.unread()

    all_critical = scans_query.all_vuln(project_id=uu_id, query="critical")
    all_high = scans_query.all_vuln(project_id=uu_id, query="high")
    all_medium = scans_query.all_vuln(project_id=uu_id, query="medium")
    all_low = scans_query.all_vuln(project_id=uu_id, query="low")

    total = all_critical, all_high, all_medium, all_low

    tota_vuln = sum(total)

    return render(
        request,
        "dashboard/project.html",
        {
            "project_id": uu_id,
            "tota_vuln": tota_vuln,
            "all_vuln": scans_query.all_vuln(project_id=uu_id, query="total"),
            "total_web": scans_query.all_web(project_id=uu_id, query="total"),
            "total_static": scans_query.all_static(project_id=uu_id, query="total"),
            "total_cloud": scans_query.all_cloud(project_id=uu_id, query="total"),
            "total_network": scans_query.all_net(project_id=uu_id, query="total"),
            "all_critical": all_critical,
            "all_high": all_high,
            "all_medium": all_medium,
            "all_low": all_low,
            "all_web_critical": scans_query.all_web(project_id=uu_id, query="critical"),
            "all_web_high": scans_query.all_web(project_id=uu_id, query="high"),
            "all_web_medium": scans_query.all_web(project_id=uu_id, query="medium"),
            "all_network_medium": scans_query.all_net(project_id=uu_id, query="medium"),
            "all_network_critical": scans_query.all_net(
                project_id=uu_id, query="critical"
            ),
            "all_network_high": scans_query.all_net(project_id=uu_id, query="high"),
            "all_web_low": scans_query.all_web(project_id=uu_id, query="low"),
            "all_network_low": scans_query.all_net(project_id=uu_id, query="low"),
            "all_project": all_project,
            "project_dat": project_dat,
            "web_scan_dat": web_scan_dat,
            "all_static_critical": scans_query.all_static(
                project_id=uu_id, query="critical"
            ),
            "all_static_high": scans_query.all_static(project_id=uu_id, query="high"),
            "all_static_medium": scans_query.all_static(
                project_id=uu_id, query="medium"
            ),
            "all_static_low": scans_query.all_static(project_id=uu_id, query="low"),
            "static_scan": static_scan,
            "all_cloud_critical": scans_query.all_cloud(
                project_id=uu_id, query="critical"
            ),
            "all_cloud_high": scans_query.all_cloud(project_id=uu_id, query="high"),
            "all_cloud_medium": scans_query.all_cloud(project_id=uu_id, query="medium"),
            "all_cloud_low": scans_query.all_cloud(project_id=uu_id, query="low"),
            "cloud_scan": cloud_scan,
            "pentest": pentest,
            "network_dat": network_dat,
            "all_compliance_failed": scans_query.all_compliance(
                project_id=uu_id, query="failed"
            ),
            "all_compliance_passed": scans_query.all_compliance(
                project_id=uu_id, query="passed"
            ),
            "all_compliance_skipped": scans_query.all_compliance(
                project_id=uu_id, query="skipped"
            ),
            "total_compliance": scans_query.all_compliance(
                project_id=uu_id, query="total"
            ),
            "all_compliance": all_compliance_seg,
            "compliance_dat": compliance_dat,
            "inspec_dat": inspec_dat,
            "dockle_dat": dockle_dat,
            "all_closed_vuln": scans_query.all_vuln_count_data(uu_id, query="Closed"),
            "all_false_positive": scans_query.all_vuln_count_data(uu_id, query="false"),
            "message": all_notify,
        },
    )


def all_high_vuln(request):
    # add your scanner gloabl variable <scannername>
    web_all_high = ""
    sast_all_high = ""
    cloud_all_high = ""
    net_all_high = ""
    pentest_all_high = ""

    all_notify = Notification.objects.unread()
    project_uu_id = request.GET.get("project_id", "")
    severity = request.GET.get("severity", "")
    if project_uu_id:
        if project_uu_id == "none":
            project_id = ""
        else:
            project_id = (
                ProjectDb.objects.filter(
                    uu_id=project_uu_id, organization=request.user.organization
                )
                .values("id")
                .get()["id"]
            )
    else:
        project_id = ""
        severity = ""
    if severity == "All":
        web_all_high = WebScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            organization=request.user.organization
        )

    elif severity == "All_Closed":
        web_all_high = WebScanResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            organization=request.user.organization
        )

    # add your scanner name here <scannername>
    elif severity == "All_False_Positive":
        web_all_high = WebScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            organization=request.user.organization
        )

    elif severity == "Network":
        net_all_high = NetworkScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )

    elif severity == "Web":
        web_all_high = WebScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="web", organization=request.user.organization
        )

    # add your scanner name here <scannername>
    elif severity == "Static":
        sast_all_high = StaticScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="static", organization=request.user.organization
        )

    elif severity == "Cloud":
        cloud_all_high = CloudScansResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="cloud", organization=request.user.organization
        )

    elif severity == "Critical":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Critical",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "High":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="High",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "Medium":
        # All Medium

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Medium",
            project_id=project_id,
            organization=request.user.organization,
        )

    # All Low
    elif severity == "Low":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Low",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "Total":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )

    elif severity == "False":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )

        pentest_all_high = ""

    elif severity == "Close":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )

    else:
        return HttpResponseRedirect(
            reverse("dashboard:proj_data") + "?project_id=%s" % project_id
        )

    web_scan_type_subquery = WebScansDb.objects.filter(scan_id=OuterRef("scan_id")).values("scan_type")[:1]
    net_scan_type_subquery = NetworkScanDb.objects.filter(scan_id=OuterRef("scan_id")).values("scan_type")[:1]

    def _annotate_scan_type(queryset, subquery):
        if hasattr(queryset, "annotate"):
            return queryset.annotate(
                scan_type=Coalesce(
                    Subquery(subquery, output_field=TextField()),
                    Value("", output_field=TextField()),
                    output_field=TextField(),
                )
            )
        return queryset

    web_all_high = _annotate_scan_type(web_all_high, web_scan_type_subquery)
    net_all_high = _annotate_scan_type(net_all_high, net_scan_type_subquery)

    # add your scanner name here <scannername>
    return render(
        request,
        "dashboard/all_high_vuln.html",
        {
            "web_all_high": web_all_high,
            "sast_all_high": sast_all_high,
            "cloud_all_high": cloud_all_high,
            "net_all_high": net_all_high,
            "pentest_all_high": pentest_all_high,
            "project_id": project_id,
            "severity": severity,
            "message": all_notify,
        },
    )


def export(request):
    """
    :param request:
    :return:
    """

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        report_type = request.POST.get("type")
        severity = request.POST.get("severity")

        # Map "All" to "Total" for the query function
        if severity == "All":
            severity = "Total"

        resource = AllResource()

        all_data = scans_query.all_vuln_count(project_id=project_id, query=severity)
        
        # Ensure we have a queryset, not an integer
        if isinstance(all_data, int):
            all_data = WebScanResultsDb.objects.none()

        dataset = resource.export(all_data)

        if report_type == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = (
                'attachment; filename="%s.csv"' % project_id
            )
            return response
        if report_type == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = (
                'attachment; filename="%s.json"' % project_id
            )
            return response

    return HttpResponse("Invalid request", status=400)
