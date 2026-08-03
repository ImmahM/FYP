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

from __future__ import unicode_literals

import hashlib
import os

from django.contrib import messages
from django.core import signing
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.db.models import OuterRef, Subquery, IntegerField, Count
from django.db.models.functions import Coalesce
from jira import JIRA
from notifications.models import Notification
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from jiraticketing.models import jirasetting
from user_management.models import Organization, UserProfile
from user_management import permissions
from webscanners.models import WebScanResultsDb, WebScansDb
from webscanners.serializers import (WebScanResultsDbSerializer,
                                     WebScansDbSerializer)
from scanners.scanner_plugin.web_scanner import zap_plugin
from archerysettings.models import ZapSettingsDb


class WebScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        # Show only current user's own scans in their org (admin sees own scans here)
        user_org = getattr(request.user, "organization", None)
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        org_qs = Organization.objects.filter(pk=getattr(user_org, "id", None)) if user_org else Organization.objects.none()

        # Annotate each scan with a result_count (how many findings exist for this scan_id)
        base_results = WebScanResultsDb.objects.filter(
            scan_id=OuterRef("scan_id"), organization__in=org_qs
        )
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]
        # Scope by organization; non-admins only see their own scans
        base_qs = WebScansDb.objects.filter(organization__in=org_qs, created_by=request.user)

        all_scans = (
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

        # Mark scans that appear stopped (not reaching 100% and no updates for a while)
        from django.utils import timezone
        STALLED_AFTER_MINUTES = 15
        cutoff_seconds = STALLED_AFTER_MINUTES * 60
        scans_list = list(all_scans)

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
            serialized_data = WebScansDbSerializer(all_scans, many=True)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            ctx = {"all_scans": scans_list, "message": all_notify}
            return render(request, "webscanners/scans/list_scans.html", ctx)


class AdminWebScanExplorer(APIView):
    """Admin explorer with user-only filtering and owner column."""
    # Allow Admin, Organization Admin, or superuser
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        # Only filter by owners (users); remove organization filter UI
        selected_owner_ids = [uid for uid in request.GET.getlist("owner") if uid]
        owners_qs = UserProfile.objects.all()

        base_results = WebScanResultsDb.objects.filter(
            scan_id=OuterRef("scan_id")
        )
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        fp_count_sq = base_results.filter(false_positive__iexact="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]

        base_qs = WebScansDb.objects.all()
        if selected_owner_ids:
            base_qs = base_qs.filter(created_by_id__in=selected_owner_ids)

        all_scans = (
            base_qs
            .annotate(
                result_count=Coalesce(Subquery(res_count_sq, output_field=IntegerField()), 0),
                res_critical=Coalesce(Subquery(crit_count_sq, output_field=IntegerField()), 0),
                res_high=Coalesce(Subquery(high_count_sq, output_field=IntegerField()), 0),
                res_medium=Coalesce(Subquery(med_count_sq, output_field=IntegerField()), 0),
                res_low=Coalesce(Subquery(low_count_sq, output_field=IntegerField()), 0),
                res_info=Coalesce(Subquery(info_count_sq, output_field=IntegerField()), 0),
                res_dup=Coalesce(Subquery(dup_count_sq, output_field=IntegerField()), 0),
                res_false=Coalesce(Subquery(fp_count_sq, output_field=IntegerField()), 0),
                latest_result_time=Subquery(latest_result_dt_sq),
            )
            .order_by("-date_time")
        )
        scans_list = list(all_scans)

        all_notify = Notification.objects.unread()
        ctx = {
            "all_scans": scans_list,
            "message": all_notify,
            # Only pass owners and show_owner flag; no orgs
            "owners": owners_qs,
            "selected_owner_ids": selected_owner_ids,
            "show_owner": True,
        }
        return render(request, "webscanners/scans/list_scans.html", ctx)


class WebScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        vuln_data = ""
        jira_url = None

        jira = jirasetting.objects.filter(organization=request.user.organization)
        for d in jira:
            jira_url = d.jira_server
        if uu_id is None:
            scan_id = request.GET["scan_id"]
            name = request.GET["scan_name"]
            vuln_data = WebScanResultsDb.objects.filter(
                title=name, scan_id=scan_id, organization=request.user.organization
            )
        else:
            try:
                vuln_data = WebScanResultsDb.objects.filter(
                    scan_id=uu_id, organization=request.user.organization
                )
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )

        if request.path[:4] == "/api":
            serialized_data = WebScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return render(
                request,
                "webscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url},
            )


class WebScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        vuln_name = request.POST.get("vuln_name")
        notes = request.POST.get("note")
        WebScanResultsDb.objects.filter(
            vuln_id=vuln_id, scan_id=scan_id, organization=request.user.organization
        ).update(false_positive=false_positive, vuln_status=status, note=notes)

        if false_positive == "Yes":
            vuln_info = WebScanResultsDb.objects.filter(
                scan_id=scan_id, vuln_id=vuln_id, organization=request.user.organization
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.url
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                WebScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id,
                    organization=request.user.organization,
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                    note=notes,
                )

        all_vuln = WebScanResultsDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
            vuln_status="Open",
            organization=request.user.organization,
        )

        # Case-insensitive, consistent severity counts
        total_high = all_vuln.filter(severity__iexact="High").count()
        total_medium = all_vuln.filter(severity__iexact="Medium").count()
        total_low = all_vuln.filter(severity__iexact="Low").count()
        total_info = all_vuln.filter(severity__istartswith="Info").count()  # Info/Informational/Information
        total_dup = all_vuln.filter(vuln_duplicate="Yes").count()
        total_vul = total_high + total_medium + total_low + total_info
        # Only mark as failed if there are no results saved for this scan
        result_count = WebScanResultsDb.objects.filter(
            scan_id=scan_id,
            organization=request.user.organization,
        ).count()
        failure_msg = None if result_count > 0 else "Scan appears failed: empty results (no results saved)."
        WebScansDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        ).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
            failure_reason=failure_msg,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln_info")
            + "?scan_id=%s&scan_name=%s" % (scan_id, vuln_name)
        )


class WebScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]

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

        # Enforce access: non-admins can only access their own vulns
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        vul_qs = WebScanResultsDb.objects.filter(
            vuln_id=vuln_id, organization=request.user.organization
        )
        if not is_admin:
            vul_qs = vul_qs.filter(created_by=request.user)
        vul_dat = vul_qs.order_by("vuln_id")

        return render(
            request,
            "webscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
        )


class WebScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            # Attempt to stop any active scanner tied to this row
            try:
                row = WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).first()
                if row:
                    scanner = (row.scanner or "").strip().lower()
                    if scanner == "zap":
                        try:
                            # Inline best-effort ZAP stop similar to ZapStop
                            from webscanners.zapscanner import zap_plugin
                            random_port = "8090"
                            zap = zap_plugin.zap_connect(random_port=random_port)
                            ascan_id = (row.zap_ascan_id or "").strip()
                            if ascan_id:
                                try:
                                    zap.ascan.stop(ascan_id)
                                except Exception:
                                    pass
                            else:
                                # Fallback by host
                                from urllib.parse import urlparse as _u
                                def _host(u):
                                    try:
                                        return (_u(str(u)).netloc or "").lstrip("www.").lower()
                                    except Exception:
                                        return ""
                                thost = _host(row.scan_url)
                                try:
                                    for s in (zap.ascan.scans() or []):
                                        sid = s.get("id") or s.get("scan")
                                        surl = s.get("url") or s.get("target") or ""
                                        if sid and _host(surl) == thost:
                                            try:
                                                zap.ascan.stop(sid)
                                            except Exception:
                                                pass
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    elif scanner == "nikto":
                        try:
                            from tools.models import NiktoResultDb
                            import os, signal, time
                            nrow = NiktoResultDb.objects.filter(scan_id=scan_id, organization=request.user.organization).first()
                            if nrow and (nrow.pgid or nrow.pid):
                                try:
                                    if nrow.pgid:
                                        os.killpg(int(nrow.pgid), signal.SIGTERM)
                                    if nrow.pid:
                                        os.kill(int(nrow.pid), signal.SIGTERM)
                                    time.sleep(0.8)
                                except Exception:
                                    pass
                                try:
                                    if nrow.pgid:
                                        os.killpg(int(nrow.pgid), signal.SIGKILL)
                                    if nrow.pid:
                                        os.kill(int(nrow.pid), signal.SIGKILL)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass

            # Non-admins can delete only their own scans
            item_qs = WebScansDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False
            if not is_admin:
                item_qs = item_qs.filter(created_by=request.user)
            # Capture scanner type before delete for log/PID cleanup
            row = item_qs.first()
            item = item_qs
            item.delete()
            item_results = WebScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item_results.delete()

            # Best-effort filesystem cleanup for tool logs
            try:
                import os
                # Nikto writes per-scan logs
                if row and str(getattr(row, 'scanner', '')).strip().lower() == 'nikto':
                    nikto_log = os.path.join(os.getcwd(), 'logs', 'nikto', f'{scan_id}.log')
                    try:
                        if os.path.exists(nikto_log):
                            os.remove(nikto_log)
                    except Exception:
                        pass
            except Exception:
                pass
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


class WebScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = WebScanResultsDb.objects.filter(
                vuln_id=vuln_id, organization=request.user.organization
            )
            delete_vuln.delete()
        all_vuln = WebScanResultsDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        total_vul = all_vuln.count()
        total_critical = all_vuln.filter(severity__iexact="Critical").count()
        total_high = all_vuln.filter(severity__iexact="High").count()
        total_medium = all_vuln.filter(severity__iexact="Medium").count()
        total_low = all_vuln.filter(severity__iexact="Low").count()
        total_info = all_vuln.filter(severity__istartswith="Info").count()  # Info/Informational/Information

        # Only failed if there are no results saved at all
        result_count = WebScanResultsDb.objects.filter(
            scan_id=scan_id,
            organization=request.user.organization,
        ).count()
        failure_msg = None if result_count > 0 else "Scan appears failed: empty results (no results saved)."
        WebScansDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            failure_reason=failure_msg,
            organization=request.user.organization,
        )
        return HttpResponseRedirect(
            reverse("webscanners:list_vuln") + "?scan_id=%s" % (scan_id)
        )


class WebScanVulnList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_vuln.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        # Ensure access control: same org; non-admins limited to own scans
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        # Verify scan ownership if required
        scan_qs = WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization)
        if not is_admin:
            scan_qs = scan_qs.filter(created_by=request.user)
        if not scan_qs.exists():
            return HttpResponseRedirect(reverse("webscanners:list_scans"))
        base_vuln = WebScanResultsDb.objects.filter(scan_id=scan_id, organization=request.user.organization)
        # Build available phases dynamically (ignore null/empty)
        try:
            _phases = list(
                base_vuln.values_list('scan_phase', flat=True).distinct()
            )
            available_phases = [p for p in _phases if p and str(p).strip()]
        except Exception:
            available_phases = []
        all_vuln = base_vuln
        phase = request.GET.get('phase')
        if phase and phase in set(available_phases):
            all_vuln = all_vuln.filter(scan_phase=phase)
        return render(
            request,
            "webscanners/scans/list_vuln.html",
            {
                "all_vuln": all_vuln,
                "scan_id": scan_id,
                "phase": phase or "All",
                "available_phases": available_phases,
            },
        )


class WebScanSummaries(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        ids = request.GET.get("ids", "").split(",")
        ids = [i.strip() for i in ids if i.strip()]
        if not ids:
            return Response({}, status=status.HTTP_200_OK)
        base_results = WebScanResultsDb.objects.filter(
            scan_id=OuterRef("scan_id"), organization=request.user.organization
        )
        res_count_sq = base_results.values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        crit_count_sq = base_results.filter(severity__iexact="Critical").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        high_count_sq = base_results.filter(severity__iexact="High").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        med_count_sq = base_results.filter(severity__iexact="Medium").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        low_count_sq = base_results.filter(severity__iexact="Low").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        info_count_sq = base_results.filter(severity__istartswith="Info").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        dup_count_sq = base_results.filter(vuln_duplicate="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        fp_count_sq = base_results.filter(false_positive__iexact="Yes").values("scan_id").annotate(cnt=Count("id")).values("cnt")[:1]
        latest_result_dt_sq = base_results.order_by("-date_time").values("date_time")[:1]
        # Scope summaries to org; non-admins only see their scans
        base_qs = WebScansDb.objects.filter(organization=request.user.organization, scan_id__in=ids)
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
                res_false=Coalesce(Subquery(fp_count_sq, output_field=IntegerField()), 0),
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
                "res_false": row.res_false,
                "total_vul": (row.critical_vul or 0) + (row.high_vul or 0) + (row.medium_vul or 0) + (row.low_vul or 0) + (row.info_vul or 0),
                "critical_vul": row.critical_vul or 0,
                "high_vul": row.high_vul or 0,
                "medium_vul": row.medium_vul or 0,
                "low_vul": row.low_vul or 0,
                "info_vul": row.info_vul or 0,
                "total_dup": int(row.total_dup or 0),
                "ui_stopped": stopped,
                "failure_reason": row.failure_reason or "",
                "last_update": (last_update.isoformat() if last_update else None),
            }
        from rest_framework.response import Response as _Resp
        return _Resp(data, status=200)


class WebScanRecent(APIView):
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

        base_qs = WebScansDb.objects.filter(
            organization=request.user.organization,
            updated_time__gt=since,
        ).order_by("-updated_time")[:100]
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        if not is_admin:
            base_qs = base_qs.filter(created_by=request.user)

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
                "url": getattr(row, "scan_url", "") or "",
                "date_time": getattr(row, "date_time", None).isoformat() if getattr(row, "date_time", None) else None,
                "updated_time": getattr(row, "updated_time", None).isoformat() if getattr(row, "updated_time", None) else None,
                "scan_status": str(getattr(row, "scan_status", "0")),
                "icon": icon,
            })
        from rest_framework.response import Response as _Resp
        return _Resp({"items": items, "since": _tz.now().isoformat()}, status=200)


class ZapLog(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # Only Admin or Organization Admin (or superuser)
        role = str(getattr(request.user, 'role', ''))
        if not (getattr(request.user, 'is_superuser', False) or role in ('Admin', 'Organization Admin')):
            return HttpResponse("Forbidden", status=403)

        # Primary: local ZAP daemon stdout captured to zap.log when Archery starts ZAP
        log_path = os.path.join(os.getcwd(), "zap.log")
        raw = request.GET.get("raw") == "1"

        def _read(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    return fh.read()
            except Exception:
                return None

        primary = _read(log_path) if os.path.exists(log_path) else None

        # Optional native/container logs (prefer these over the primary)
        candidates = []
        env_path = os.getenv("ZAP_SECONDARY_LOG")
        if env_path:
            candidates.append(env_path)
        candidates.extend([
            "/shared/zapscanner.log",                  # shared volume (compose)
            os.path.join(os.getcwd(), "zapscanner.log"),
            os.path.join(os.getcwd(), "logs", "zapscanner.log"),
            "/zap/zap.out",                             # common stdout redirect path
            "/zap/wrk/zap.log",                         # ZAP work dir log if configured
        ])

        native_logs = []
        for cand in candidates:
            try:
                if cand and os.path.exists(cand):
                    data = _read(cand)
                    if data is not None:
                        native_logs.append((cand, data))
            except Exception:
                continue

        allow_fallback = request.GET.get("fallback", "0") == "1"
        content_parts = []
        if native_logs:
            # Hide the legacy app stream (zap.log) when we have a native/container log
            for path, data in native_logs:
                header = f"----- Native: {os.path.basename(path)} -----\n"
                content_parts.append(header + (data or ""))
        elif primary and allow_fallback:
            content_parts.append(f"----- Primary: zap.log -----\n" + primary)

        if not content_parts:
            tips = [
                "No ZAP log files found.",
                "If using external zapscanner, confirm shared volume and pipeline:",
                "  - ZAP_SECONDARY_LOG=/shared/zapscanner.log",
                "  - zap.sh ... 2>&1 | tee -a /shared/zapscanner.log",
                "Checked locations:",
            ] + [f"  - {p}" for p in candidates] + [
                "Per-app fallback (enable via ?fallback=1):",
                f"  - {os.path.join(os.getcwd(), 'zap.log')}",
            ]
            msg = "\n".join(tips)
            if raw:
                return HttpResponse(msg + "\n", content_type="text/plain")
            return render(
                request,
                "webscanners/zap_log.html",
                {"has_log": False, "initial": msg},
            )

        combined = "".join(content_parts)
        if raw:
            return HttpResponse(combined, content_type="text/plain")
        # Sanitize noisy, non-actionable entries (e.g., telemetry call-home errors)
        try:
            lines = combined.splitlines()
            filtered = []
            for ln in lines:
                if "ExtensionCallHome" in ln and "ERROR" in ln:
                    # Hide ZAP telemetry upload failures from the log viewer
                    continue
                filtered.append(ln)
            combined = "\n".join(filtered)
        except Exception:
            pass
        return render(
            request,
            "webscanners/zap_log.html",
            {"has_log": True, "initial": combined},
        )


class WebScannerLog(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET.get("scan_id")
        raw = request.GET.get("raw") == "1"
        log_path = os.path.join(os.getcwd(), "logs", "zap", f"{scan_id}.log")  # adjust path
        if not os.path.exists(log_path):
            if raw:
                return HttpResponse("", status=202, content_type="text/plain")
            return render(request, "webscanners/log.html", {"scan_id": scan_id, "has_log": False, "initial": ""})
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as e:
            if raw:
                return HttpResponse(f"Failed to read log: {e}", status=500, content_type="text/plain")
            return render(request, "webscanners/log.html", {"scan_id": scan_id, "has_log": True, "initial": f"Failed to read log: {e}"})
        if raw:
            return HttpResponse(content, content_type="text/plain")
        return render(request, "webscanners/log.html", {"scan_id": scan_id, "has_log": True, "initial": content})


class WebRescan(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # allow Admin, Organization Admin and User (or superuser)
        role = str(getattr(request.user, "role", "")).lower()
        allowed_roles = ("admin", "organization admin", "user")
        if not (getattr(request.user, "is_superuser", False) or role in allowed_roles):
            if request.path[:4] == "/api":
                return Response({"message": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
            return HttpResponse("Forbidden", status=403)

        scan_id = request.POST.get("scan_id")
        target_url = request.POST.get("target_url")
        scan_type = request.POST.get("scan_type")
        scanner = request.POST.get("scanner")
        user = request.user

        # Validate input
        if not scan_id or not target_url or not scan_type or not scanner:
            return Response({"message": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        # Only allow specific scan types and scanners
        allowed_scan_types = ["quick", "full"]
        allowed_scanners = ["zap", "nikto"]
        if scan_type not in allowed_scan_types or scanner not in allowed_scanners:
            return Response({"message": "Invalid scan type or scanner."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a scan with the same ID is already in progress
        existing_scan = WebScansDb.objects.filter(scan_id=scan_id, organization=user.organization)
        if existing_scan.exists():
            return Response({"message": "A scan with this ID is already in progress."}, status=status.HTTP_400_BAD_REQUEST)

        # Create the scan object
        new_scan = WebScansDb(
            scan_id=scan_id,
            scan_url=target_url,
            scan_type=scan_type,
            scanner=scanner,
            organization=user.organization,
            created_by=user,
        )
        new_scan.save()

        # Start the scan using the appropriate scanner plugin
        try:
            if scanner == "zap":
                # For ZAP, initiate a scan and save the async scan ID
                from webscanners.zapscanner import zap_plugin
                random_port = "8090"
                zap = zap_plugin.zap_connect(random_port=random_port)
                ascan_id = zap.ascan.scan(target_url)
                new_scan.zap_ascan_id = ascan_id
                new_scan.save()
            elif scanner == "nikto":
                # For Nikto, start the scan process
                from tools.models import NiktoResultDb
                import os, signal, time
                nikto_process = NiktoResultDb.objects.filter(scan_id=scan_id, organization=user.organization).first()
                if nikto_process and (nikto_process.pgid or nikto_process.pid):
                    try:
                        if nikto_process.pgid:
                            os.killpg(int(nikto_process.pgid), signal.SIGTERM)
                        if nikto_process.pid:
                            os.kill(int(nikto_process.pid), signal.SIGTERM)
                        time.sleep(0.8)
                    except Exception:
                        pass
                    try:
                        if nikto_process.pgid:
                            os.killpg(int(nikto_process.pgid), signal.SIGKILL)
                        if nikto_process.pid:
                            os.kill(int(nikto_process.pid), signal.SIGKILL)
                    except Exception:
                        pass
                # Now start a new Nikto scan
                from scanners.scanner_plugin.web_scanner import nikto_plugin
                nikto = nikto_plugin.Nikto()
                nikto.setup(scan_id, target_url)
                nikto.run()
            else:
                return Response({"message": "Unsupported scanner."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Handle any exceptions during the scan initiation
            new_scan.delete()  # Clean up the scan object on error
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Scan started successfully.", "scan_id": scan_id}, status=status.HTTP_202_ACCEPTED)
