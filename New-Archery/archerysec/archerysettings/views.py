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
import time
import uuid

from django.core import signing
from django.contrib import messages
from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from notifications.signals import notify
from PyBurprestapi import burpscanner
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

# NEW: mail + validators
from django.core.mail import EmailMessage, get_connection
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

import PyArachniapi
from archerysettings.models import (ArachniSettingsDb, BurpSettingDb, EmailDb,
                                    OpenvasSettingDb, SettingsDb,
                                    ZapSettingsDb)
from jiraticketing.models import jirasetting
from scanners.scanner_plugin.network_scanner.openvas_plugin import \
    OpenVAS_Plugin
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from user_management import permissions
# original helper still imported if used elsewhere
from utility.email_notify import email_sch_notify


class EmailSetting(APIView):
    """
    Upgraded controller for Email settings & sending.
    - Admins can SAVE SMTP config (host/port/TLS/user/password/sender).
    - Any authenticated user can SEND (uses saved SMTP config; otherwise falls back to settings.py EMAIL_*).
    - 'send_test' checks SMTP connectivity before sending.
    """
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/email_setting_form.html"
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        org = request.user.organization

        # Auto-create default email settings with Gmail if none exist
        if not EmailDb.objects.filter(organization=org).exists():
            EmailDb.objects.create(
                setting_id=uuid.uuid4(),
                subject='ArcherySec Notification',
                message='',
                recipient_list='immahkali939@gmail.com',
                smtp_host='smtp.gmail.com',
                smtp_port=587,
                smtp_use_tls=True,
                smtp_user='immahkali939@gmail.com',
                smtp_password=signing.dumps('cyfhdwpoujgrtxei'),
                sender_email='immahkali939@gmail.com',
                organization=org,
            )

        all_email = EmailDb.objects.filter(organization=org)
        data = all_email.first()
        # Don't expose the password — keep it hidden
        if data:
            data.smtp_password = ''
        inbox = Notification.objects.filter(recipient=request.user).order_by("-timestamp")[:50]
        return render(
            request,
            "setting/email_setting_form.html",
            {"all_email": all_email, "data": data, "inbox": inbox},
        )

    def _parse_list(self, val):
        if not val:
            return []
        parts = []
        for chunk in str(val).replace("\n", ",").replace(" ", ",").split(","):
            c = chunk.strip()
            if c:
                parts.append(c)
        return parts

    def _validate_many(self, addrs):
        for a in addrs:
            try:
                validate_email(a)
            except ValidationError:
                return a  # return first invalid
        return None

    def post(self, request):
        from django.db import transaction

        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        action = (request.POST.get("action") or "").strip()  # 'save' | 'send' | 'send_test'

        # basic message fields (still stored like before)
        subject = (request.POST.get("email_subject") or "").strip()
        body = (request.POST.get("email_message") or "").strip()
        to_list = self._parse_list(request.POST.get("to_email"))
        cc_list = self._parse_list(request.POST.get("cc_email"))
        bcc_list = self._parse_list(request.POST.get("bcc_email"))
        reply_to_list = self._parse_list(request.POST.get("reply_to"))

        # SMTP fields (Admins can save these)
        smtp_host = (request.POST.get("smtp_host") or "").strip()
        smtp_port = (request.POST.get("smtp_port") or "").strip()
        smtp_use_tls = bool(request.POST.get("smtp_use_tls"))
        smtp_user = (request.POST.get("smtp_user") or "").strip()
        sender_email = (request.POST.get("sender_email") or "").strip()
        smtp_password_plain = request.POST.get("smtp_password")  # may be blank to keep existing

        # current org email row (if exists)
        email_obj = EmailDb.objects.filter(organization=request.user.organization).first()

        # ---------- SAVE (Admin only) ----------
        if action == "save":
            if not is_admin:
                messages.error(request, "Only Admins can save email settings.")
                return HttpResponseRedirect(reverse("archerysettings:email_setting"))

            # optional: validate fields (host/port/user/email)
            if smtp_host and not smtp_port:
                smtp_port = "587"
            try:
                port_val = int(smtp_port) if smtp_port else 587
            except ValueError:
                messages.error(request, "SMTP Port must be a number.")
                return HttpResponseRedirect(reverse("archerysettings:email_setting"))

            if sender_email:
                bad = self._validate_many([sender_email])
                if bad:
                    messages.error(request, f"Invalid sender email: {bad}")
                    return HttpResponseRedirect(reverse("archerysettings:email_setting"))

            with transaction.atomic():
                setting_id = getattr(email_obj, "setting_id", uuid.uuid4())
                # keep existing encrypted password if field left blank
                encrypted_password = None
                if smtp_password_plain:
                    encrypted_password = signing.dumps(smtp_password_plain)
                else:
                    if email_obj and email_obj.smtp_password:
                        encrypted_password = email_obj.smtp_password

                obj, _ = EmailDb.objects.update_or_create(
                    organization=request.user.organization,
                    defaults={
                        "subject": subject,
                        "message": body,
                        "recipient_list": ",".join(to_list),
                        "setting_id": setting_id,
                        "smtp_host": smtp_host or (email_obj.smtp_host if email_obj else ""),
                        "smtp_port": port_val if port_val else (email_obj.smtp_port if email_obj else 587),
                        "smtp_use_tls": smtp_use_tls,
                        "smtp_user": smtp_user or (email_obj.smtp_user if email_obj else ""),
                        "smtp_password": encrypted_password,
                        "sender_email": sender_email or (email_obj.sender_email if email_obj else (smtp_user or None)),
                    },
                )

                # probe SMTP and update SettingsDb.setting_status
                setting_status = False
                try:
                    if obj.smtp_user and obj.smtp_password:
                        pwd = signing.loads(obj.smtp_password)
                        conn = get_connection(
                            backend='django.core.mail.backends.smtp.EmailBackend',
                            host=obj.smtp_host or '',
                            port=getattr(obj, "smtp_port", 587),
                            username=obj.smtp_user,
                            password=pwd,
                            use_tls=bool(getattr(obj, "smtp_use_tls", True)),
                            fail_silently=False,
                        )
                        conn.open()
                        conn.close()
                        setting_status = True
                except Exception:
                    setting_status = False

                SettingsDb.objects.update_or_create(
                    organization=request.user.organization,
                    setting_scanner="Email",
                    defaults={
                        "setting_id": obj.setting_id,
                        "setting_status": setting_status,
                    },
                )

            messages.success(request, f"Saved email settings. SMTP status: {'OK' if setting_status else 'FAILED'}")
            return HttpResponseRedirect(reverse("archerysettings:email_setting"))

        # Validate addresses for send/test
        if action in {"send", "send_test"}:
            if not subject:
                messages.error(request, "Subject is required.")
                return HttpResponseRedirect(reverse("archerysettings:email_setting"))
            if not to_list:
                messages.error(request, "At least one recipient is required.")
                return HttpResponseRedirect(reverse("archerysettings:email_setting"))
            bad = self._validate_many(to_list + cc_list + bcc_list + reply_to_list)
            if bad:
                messages.error(request, f"Invalid email address: {bad}")
                return HttpResponseRedirect(reverse("archerysettings:email_setting"))

            # choose config: saved SMTP if present; otherwise fallback to project EMAIL_* settings
            cfg = email_obj

            try:
                connection = None
                if cfg and cfg.smtp_user and cfg.smtp_password:
                    try:
                        pwd = signing.loads(cfg.smtp_password)
                    except Exception:
                        pwd = None
                    if pwd:
                        connection = get_connection(
                            backend='django.core.mail.backends.smtp.EmailBackend',
                            host=cfg.smtp_host or '',
                            port=getattr(cfg, "smtp_port", 587),
                            username=cfg.smtp_user,
                            password=pwd,
                            use_tls=bool(getattr(cfg, "smtp_use_tls", True)),
                            fail_silently=False,
                        )

                if connection is None:
                    connection = get_connection(fail_silently=False)  # uses settings.py EMAIL_*

                # for send_test, verify credentials early
                if action == "send_test":
                    try:
                        connection.open()
                        connection.close()
                        messages.success(request, "SMTP connection successful.")
                    except Exception as e:
                        messages.error(request, f"SMTP connection failed: {e}")
                        return HttpResponseRedirect(reverse("archerysettings:email_setting"))

                from_email = (
                    (cfg.sender_email if cfg and cfg.sender_email else None)
                    or getattr(settings, 'DEFAULT_FROM_EMAIL', None)
                    or getattr(settings, 'EMAIL_HOST_USER', None)
                )

                mail = EmailMessage(
                    subject=subject,
                    body=body,
                    from_email=from_email,
                    to=to_list,
                    cc=cc_list or None,
                    bcc=bcc_list or None,
                    reply_to=reply_to_list or None,
                    connection=connection,
                )
                if "attachment" in request.FILES:
                    up = request.FILES["attachment"]
                    mail.attach(up.name, up.read(), up.content_type or "application/octet-stream")

                mail.send(fail_silently=False)
                messages.success(request, "Email sent." if action == "send" else "SMTP test succeeded and email sent.")

                # in-app notifications to internal users (optional best-effort)
                try:
                    from user_management.models import UserProfile as _UP
                    for addr in to_list:
                        recipient = _UP.objects.filter(email=addr, organization=request.user.organization).first()
                        if recipient is not None:
                            notify.send(
                                request.user,
                                recipient=recipient,
                                verb=subject or "New Message",
                                description=(body or ""),
                            )
                except Exception:
                    pass

            except Exception as e:
                messages.error(request, f"Failed to send email: {e}")

            return HttpResponseRedirect(reverse("archerysettings:email_setting"))

        # No recognized action
        messages.warning(request, "No action selected.")
        return HttpResponseRedirect(reverse("archerysettings:email_setting"))


class NotificationsClear(APIView):
    """Clear all or selected notifications for the current user."""
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        action = request.POST.get("action")
        ids = request.POST.get("ids", "")
        qs = Notification.objects.filter(recipient=request.user)
        try:
            if action == "all":
                count = qs.count()
                qs.delete()
                messages.success(request, f"Cleared {count} notification(s)")
            elif action == "selected":
                id_list = [i.strip() for i in ids.split(",") if i.strip()]
                del_qs = qs.filter(id__in=id_list)
                count = del_qs.count()
                del_qs.delete()
                messages.success(request, f"Cleared {count} selected notification(s)")
            else:
                messages.warning(request, "No action specified")
        except Exception:
            messages.error(request, "Unable to clear notifications")
        return HttpResponseRedirect(reverse("archerysettings:email_setting"))


class DeleteSettings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def post(self, request):
        setting_id = request.POST.get("setting_id")
        org_id = request.POST.get("org")
        from user_management.models import Organization
        org = getattr(request.user, "organization", None)
        if getattr(request.user, "is_superuser", False) and org_id:
            try:
                org = Organization.objects.get(pk=org_id)
            except Exception:
                pass

        delete_dat = SettingsDb.objects.filter(
            setting_id=setting_id, organization=org
        )
        delete_dat.delete()
        redirect_url = reverse("archerysettings:settings")
        if getattr(request.user, "is_superuser", False) and org:
            redirect_url = f"{redirect_url}?org={org.id}"
        return HttpResponseRedirect(redirect_url)


class Settings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/settings_page.html"
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def _selected_org(self, request):
        from user_management.models import Organization
        org = getattr(request.user, "organization", None)
        if getattr(request.user, "is_superuser", False):
            sel = request.GET.get("org") or request.POST.get("org") or request.session.get("settings_org")
            if sel:
                try:
                    org = Organization.objects.get(pk=sel)
                except Exception:
                    pass
            if org:
                try:
                    request.session["settings_org"] = str(org.id)
                except Exception:
                    pass
        return org

    def get(self, request):
        all_notify = Notification.objects.unread()
        org = self._selected_org(request)

        all_settings_data = SettingsDb.objects.filter(
            organization=org
        )

        # Auto-create default JIRA settings entry if none exist
        jira_setting_exists = jirasetting.objects.filter(organization=org).exists()
        settings_jira_exists = SettingsDb.objects.filter(setting_scanner='Jira', organization=org).exists()
        if not jira_setting_exists:
            jirasetting.objects.create(
                setting_id=uuid.uuid4(),
                jira_server='https://my-fyp-org.atlassian.net',
                jira_username=signing.dumps('tp077928@mail.apu.edu'),
                jira_password=signing.dumps('ATATT3xFfGF0mBv3Jjdgg5WpO6uovniTe4FQCkkT99klL-5Wud8PrAuWNnNZYdx0fBV4VWmW9dzPARaIjbbxFlBsx6s0gwZuMamgGcaniwUQyqAixzUQYO7N58TBDHj4viVV2UBEszjncFfGMUgtU8QIx4LW2aUIxCiFJ4GyBXdNld42CCsUH94=DEEABC81'),
                organization=org,
            )
        if not settings_jira_exists:
            SettingsDb.objects.create(
                setting_id=uuid.uuid4(),
                setting_scanner='Jira',
                organization=org,
                setting_status=False,
            )

        # Auto-create default OpenVAS settings entry if none exist
        openvas_exists = OpenvasSettingDb.objects.filter(organization=org).exists()
        settings_openvas_exists = SettingsDb.objects.filter(setting_scanner='Openvas', organization=org).exists()
        if not openvas_exists:
            OpenvasSettingDb.objects.create(
                setting_id=uuid.uuid4(),
                host='customarcherysecopenvas',
                port='9390',
                user='admin',
                password='admin',
                enabled=True,
                organization=org,
            )
        if not settings_openvas_exists:
            SettingsDb.objects.create(
                setting_id=uuid.uuid4(),
                setting_scanner='Openvas',
                organization=org,
                setting_status=False,
            )

        # Auto-create default Email settings entry with Gmail if none exist
        email_exists = EmailDb.objects.filter(organization=org).exists()
        settings_email_exists = SettingsDb.objects.filter(setting_scanner='Email', organization=org).exists()
        if not email_exists:
            EmailDb.objects.create(
                setting_id=uuid.uuid4(),
                subject='ArcherySec Notification',
                message='',
                recipient_list='immahkali939@gmail.com',
                smtp_host='smtp.gmail.com',
                smtp_port=587,
                smtp_use_tls=True,
                smtp_user='immahkali939@gmail.com',
                smtp_password=signing.dumps('cyfhdwpoujgrtxei'),
                sender_email='immahkali939@gmail.com',
                organization=org,
            )
        if not settings_email_exists:
            SettingsDb.objects.create(
                setting_id=uuid.uuid4(),
                setting_scanner='Email',
                organization=org,
                setting_status=False,
            )

        # Refresh settings data after creating defaults
        all_settings_data = SettingsDb.objects.filter(organization=org)

        from user_management.models import Organization
        orgs = []
        if getattr(request.user, "is_superuser", False):
            orgs = list(Organization.objects.all())

        return render(
            request,
            "setting/settings_page.html",
            {
                "all_settings_data": all_settings_data,
                "all_notify": all_notify,
                "orgs": orgs,
                "selected_org": org,
            },
        )

    def post(self, request):
        all_notify = Notification.objects.unread()
        org = self._selected_org(request)

        jira_url = None
        j_username = None
        password = None

        all_settings_data = SettingsDb.objects.filter(
            organization=org
        )

        # Loading ZAP Settings (kept same)
        all_zap = ZapSettingsDb.objects.filter(organization=org)

        # Loading Arachni Settings
        arachni_hosts = ""
        arachni_ports = ""
        arachni_user = ""
        arachni_pass = ""

        all_arachni = ArachniSettingsDb.objects.filter(
            organization=org
        )
        for arachni in all_arachni:
            arachni_hosts = arachni.arachni_url
            arachni_ports = arachni.arachni_port
            arachni_user = arachni.arachni_user
            arachni_pass = arachni.arachni_pass

        burp_host = ""
        burp_port = ""
        burp_api_key = ""
        all_burp_setting = BurpSettingDb.objects.filter(
            organization=org
        )
        for data in all_burp_setting:
            burp_host = data.burp_url
            burp_port = data.burp_port
            burp_api_key = data.burp_api_key

        jira_setting = jirasetting.objects.filter(
            organization=org
        )

        for jira in jira_setting:
            jira_url = jira.jira_server
            j_username = jira.jira_username
            password = jira.jira_password
        jira_server = jira_url
        if j_username is None:
            jira_username = None
        else:
            jira_username = signing.loads(j_username)

        if password is None:
            jira_password = None
        else:
            jira_password = signing.loads(password)

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"

        setting_of = request.POST.get("setting_of")
        setting_id = request.POST.get("setting_id")

        if setting_of == "zap":
            all_zap = ZapSettingsDb.objects.filter(
                organization=org
            )
            for zap in all_zap:
                zap_enabled = zap.enabled

            if zap_enabled is False:
                zap_info = "Disabled"
                try:
                    random_port = zap_plugin.zap_local()
                except Exception:
                    return render(
                        request, "setting/settings_page.html", {"zap_info": zap_info}
                    )

                for i in range(0, 100):
                    while True:
                        try:
                            zap_connect = zap_plugin.zap_connect(random_port)
                            zap_connect.spider.scan(url=target_url)
                        except Exception:
                            print("ZAP Connection Not Found, re-try after 5 sec")
                            time.sleep(5)
                            continue
                        break
            else:
                try:
                    zap_connect = zap_plugin.zap_connect(random_port)
                    zap_connect.spider.scan(url=target_url)
                    zap_info = True
                    SettingsDb.objects.filter(
                        setting_id=setting_id, organization=request.user.organization
                    ).update(setting_status=zap_info)
                except Exception:
                    zap_info = False
                    SettingsDb.objects.filter(
                        setting_id=setting_id, organization=request.user.organization
                    ).update(setting_status=zap_info)

        if setting_of == "burp":
            host = "http://" + burp_host + ":" + burp_port + "/"
            try:
                bi = burpscanner.BurpApi(host, burp_api_key)
            except Exception:
                burp_info = False
                return burp_info

            issue_list = bi.issue_definitions()
            if issue_list.data is None:
                burp_info = False
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=burp_info)
            else:
                burp_info = True
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=burp_info)

        if setting_of == "openvas":
            sel_profile = ""
            scan_ip = ""
            project_id = ""

            openvas = OpenVAS_Plugin(scan_ip, project_id, sel_profile, request)
            try:
                openvas.connect()
                openvas_info = True
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=openvas_info)
            except Exception as e:
                print(f"OpenVAS connection test failed: {e}")
                openvas_info = False
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=openvas_info)

        if setting_of == "arachni":
            global scan_run_id, scan_status
            arachni_hosts = None
            arachni_ports = None
            arachni_user = None
            arachni_pass = None
            all_arachni = ArachniSettingsDb.objects.filter(
                organization=org
            )
            for arachni in all_arachni:
                arachni_hosts = arachni.arachni_url
                arachni_ports = arachni.arachni_port
                arachni_user = arachni.arachni_user
                arachni_pass = arachni.arachni_pass

            arachni = PyArachniapi.arachniAPI(
                arachni_hosts, arachni_ports, arachni_user, arachni_pass
            )

            check = []
            data = {"url": "https://archerysec.com", "checks": check, "audit": {}}
            d = json.dumps(data)

            scan_launch = arachni.scan_launch(d)
            time.sleep(3)

            try:
                scan_data = scan_launch.data
                for key, value in scan_data.items():
                    if key == "id":
                        scan_run_id = value
                arachni_info = True
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=arachni_info)
            except Exception:
                arachni_info = False
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=arachni_info)

        if setting_of == "jira":
            global jira_projects, jira_ser
            jira_setting = jirasetting.objects.filter(
                organization=org
            )

            for jira in jira_setting:
                jira_url = jira.jira_server
                username = jira.jira_username
                password = jira.jira_password

                if jira_url is None:
                    print("No jira url found")

            try:
                jira_server = jira_url
                jira_username = signing.loads(username)
                jira_password = signing.loads(password)
            except Exception:
                jira_info = False

            options = {"server": jira_server}
            try:
                if jira_username is not None and jira_username != "":
                    jira_ser = JIRA(
                        options, basic_auth=(jira_username, jira_password), timeout=5
                    )
                else:
                    jira_ser = JIRA(options, token_auth=jira_password, timeout=5)

                jira_projects = jira_ser.projects()
                print(len(jira_projects))
                jira_info = True
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=jira_info)
            except Exception as e:
                print(e)
                jira_info = False
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=org
                ).update(setting_status=jira_info)

        from user_management.models import Organization
        orgs = []
        if getattr(request.user, "is_superuser", False):
            orgs = list(Organization.objects.all())
        return render(
            request,
            "setting/settings_page.html",
            {
                "all_settings_data": all_settings_data,
                "all_notify": all_notify,
                "orgs": orgs,
                "selected_org": org,
            },
        )


class SettingsGuide(APIView):
    """
    In-app guide tailored per role (Admin, Organization Admin, User).
    """

    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/guide.html"
    permission_classes = (IsAuthenticated,)

    def _base_dashboard_notes(self):
        return [
            "Summary tiles show Total, False Positive, Closed, Network, and Web counts with quick filters.",
            "Trend chart tracks vulnerabilities by month; click the title to open Trend History.",
            "Ring charts break down severity across all findings, plus dedicated Web and Network rings.",
            "Project List shows per-project severity counts, creator, and delete action (respecting permissions).",
            "Upload and Add Project buttons sit above the Project List for quick ingestion and setup.",
        ]

    def _admin_context(self):
        # Admin sees full context for all roles
        role_matrix = [
            {
                "name": "Admin",
                "tag": "Owner",
                "badge": "danger",
                "summary": "Full platform control across all organizations (or the current org if multi-tenant).",
                "can": [
                    "Manage connectors, email, and API access keys",
                    "Create and delete users, set roles, and manage organizations",
                    "Launch web and network scans, and view Admin Logs / Admin Scan Explorer",
                    "Generate reports, upload XML findings, and manage all projects",
                ],
            },
            {
                "name": "Organization Admin",
                "tag": "Org Lead",
                "badge": "info",
                "summary": "Operates within their organization; manages people and tooling scoped to that org.",
                "can": [
                    "Create and manage users inside the organization",
                    "Launch scans and manage projects for the org",
                    "Configure approved connectors such as scanners, Jira, and email",
                ],
            },
            {
                "name": "User",
                "tag": "Contributor",
                "badge": "secondary",
                "summary": "Executes day-to-day testing and triage for assigned projects.",
                "can": [
                    "Launch permitted scans and view their results",
                    "Work from Dashboard and Project views to triage findings",
                    "Upload reports when allowed and collaborate through notifications",
                ],
            },
        ]
        role_playbooks = [
            {
                "title": "Admin sequence",
                "badge": "danger",
                "steps": [
                    "Create a project (Dashboard ➜ Add Project).",
                    "Set connectors (Settings ➜ Connectors) and verify ZAP/OpenVAS/Jira/Email with Test.",
                    "Create users (Settings ➜ Users) and assign roles; add organizations if needed.",
                    "Launch scans (Launch Scans ➜ Web/Network) targeting the project.",
                    "Review scan results (Scans ➜ Web/Network) and, if needed, Admin Scan Explorer / Admin Logs.",
                    "Track posture in Dashboard (tiles, trend chart, ring charts, Project List).",
                    "Generate reports (Reports ➜ Generate Report) for scans or projects.",
                    "Send emails (Settings ➜ Email) using saved SMTP; notify stakeholders.",
                ],
            },
            {
                "title": "Org Admin sequence",
                "badge": "info",
                "steps": [
                    "Create or select a project inside the organization.",
                    "Configure connectors for the org (Settings ➜ Connectors) and test them.",
                    "Create org users with allowed roles (User/Analyst/Org Admin).",
                    "Launch scans for org projects (Launch Scans ➜ Web/Network).",
                    "Review results in Scans and Project pages.",
                    "Monitor org health in Dashboard and Project List.",
                    "Generate reports for stakeholders.",
                    "Send emails using org SMTP (Settings ➜ Email) when needed.",
                ],
            },
            {
                "title": "Contributor sequence",
                "badge": "secondary",
                "steps": [
                    "Open assigned projects from Dashboard ➜ Project List.",
                    "Launch permitted scans (Launch Scans ➜ Web/Network) for those projects.",
                    "Review and triage findings in Scans and Project views.",
                    "Watch Dashboard for trends and counts relevant to your projects.",
                    "Generate reports if allowed, or share findings with the team.",
                    "Use in-app notifications; send emails if enabled.",
                ],
            },
        ]
        workflows = [
            {
                "title": "Add a user",
                "steps": [
                    "Go to Settings ➜ Users",
                    "Click Add User, provide name/email/password",
                    "Choose a role (Admins can assign any; Org Admins are limited to org-scoped roles)",
                    "Save; the user appears in the Users list and receives notifications after login",
                ],
                "hint": "Use Organization to group users; Org Admins cannot create Admins or Superusers.",
            },
            {
                "title": "Create or manage a project",
                "steps": [
                    "From Dashboard, click Add Project (top-right of Project List)",
                    "Name the project and assign it to your organization",
                    "Use the Project List to open a project and review severity counters per project",
                ],
                "hint": "You can also upload XML findings directly from the Dashboard Upload button.",
            },
            {
                "title": "Connect scanners and integrations",
                "steps": [
                    "Navigate to Settings ➜ Connectors",
                    "Use Add Connector to open ZAP, OpenVAS, JIRA, or Email configuration",
                    "After saving, use Test to validate connectivity and update the status badge",
                ],
                "hint": "Connector availability is scoped to the selected organization.",
            },
            {
                "title": "Configure email and send a test",
                "steps": [
                    "Open Settings ➜ Email",
                    "Fill SMTP host/port/user/password, sender address, and defaults",
                    "Click Save to store settings, then Send Test to verify delivery",
                    "Use Send to email recipients directly (supports CC/BCC, Reply-To, attachment)",
                ],
                "hint": "Saved SMTP credentials are encrypted; tests update the Email connector status.",
            },
            {
                "title": "Launch scans",
                "steps": [
                    "Go to Launch Scans ➜ Web Scans or Network Scans",
                    "Provide target details and select the project to associate findings",
                    "Submit to queue the scan; track progress under Scans ➜ Web/Network",
                    "Admins can review full history via Admin Scan Explorer and Admin Logs",
                ],
                "hint": "Use Projects to keep targets grouped; dashboards roll up by project.",
            },
            {
                "title": "Generate or download reports",
                "steps": [
                    "Open Reports ➜ Generate Report",
                    "Pick project/scan, choose template, and export",
                    "For existing artifacts, use the Project view or scan list download actions",
                ],
                "hint": "Report uploads from Dashboard support XML imports for consolidation.",
            },
        ]
        navigation = [
            {"label": "Dashboard", "desc": "Overall risk view, trend charts, and Project List.", "url": "dashboard:dashboard"},
            {"label": "Scans ➜ Web/Network", "desc": "Run new scans and browse historical results.", "url": "webscanners:list_scans"},
            {"label": "Scans ➜ Admin Logs", "desc": "Admin-only event log for scans and automation.", "url": "webscanners:admin_logs"},
            {"label": "Scans ➜ Admin Scan Explorer", "desc": "Full inventory of all scans across users.", "url": "webscanners:admin_scans"},
            {"label": "Launch Scans", "desc": "Shortcut to start Web or Network scans.", "url": "webscanners:index"},
            {"label": "Reports", "desc": "Generate exportable reports for scans/projects.", "url": "reports:generate_report"},
            {"label": "Settings ➜ Connectors", "desc": "Configure ZAP, OpenVAS, JIRA, and Email for the org.", "url": "archerysettings:settings"},
            {"label": "Settings ➜ Access Keys", "desc": "Create/revoke API access keys (Admin only).", "url": "archeryapi:access-key"},
            {"label": "Settings ➜ Users / Organization / Projects", "desc": "Manage people, org metadata, and project catalog.", "url": "users:list_user"},
        ]
        return {
            "role_matrix": role_matrix,
            "role_playbooks": role_playbooks,
            "workflows": workflows,
            "navigation": navigation,
        }

    def _org_admin_context(self):
        role_matrix = [
            {
                "name": "Organization Admin",
                "tag": "Org Lead",
                "badge": "info",
                "summary": "Operates within their organization; manages people and tooling scoped to that org.",
                "can": [
                    "Create and manage users inside the organization",
                    "Launch scans and manage projects for the org",
                    "Configure approved connectors such as scanners, Jira, and email",
                ],
            },
        ]
        role_playbooks = [
            {
                "title": "Org Admin sequence",
                "badge": "info",
                "steps": [
                    "Create or select a project inside the organization.",
                    "Create org users with allowed roles (User/Analyst/Org Admin).",
                    "Launch scans for org projects (Launch Scans ➜ Web/Network).",
                    "Review results in Scans and Project pages.",
                    "Monitor org health in Dashboard and Project List.",
                    "Generate reports for stakeholders.",
                    "Share updates via reports; request Admins to send emails if required.",
                ],
            },
        ]
        workflows = [
            {
                "title": "Manage org users",
                "steps": [
                    "Go to Settings ➜ Users",
                    "Add or edit users; assign roles within your org scope",
                    "Save changes and confirm the user appears in the list",
                ],
                "hint": "Org Admins cannot create platform Admins or Superusers.",
            },
            {
                "title": "Launch and track scans",
                "steps": [
                    "Use Launch Scans to start Web or Network scans for org projects",
                    "Check progress/results under Scans ➜ Web/Network",
                    "Share updates via reports or email if configured",
                ],
                "hint": "Keep projects organized for clear reporting.",
            },
        ]
        navigation = [
            {"label": "Dashboard", "desc": "Org risk view, trend charts, and Project List.", "url": "dashboard:dashboard"},
            {"label": "Scans ➜ Web/Network", "desc": "Run and review scans for your organization.", "url": "webscanners:list_scans"},
            {"label": "Launch Scans", "desc": "Start Web or Network scans for org projects.", "url": "webscanners:index"},
            {"label": "Reports", "desc": "Generate exportable reports for scans/projects.", "url": "reports:generate_report"},
            {"label": "Projects", "desc": "Manage projects in your organization.", "url": "projects:manage"},
            {"label": "Users", "desc": "Create/manage users within your organization.", "url": "users:list_user"},
            {"label": "Organization", "desc": "Org profile and details.", "url": "users:list_org"},
        ]
        return {
            "role_matrix": role_matrix,
            "role_playbooks": role_playbooks,
            "workflows": workflows,
            "navigation": navigation,
        }

    def _user_context(self):
        role_matrix = [
            {
                "name": "User",
                "tag": "Contributor",
                "badge": "secondary",
                "summary": "Executes day-to-day testing and triage for assigned projects.",
                "can": [
                    "Launch permitted scans and view their results",
                    "Work from Dashboard and Project views to triage findings",
                    "Upload reports when allowed and collaborate through notifications",
                ],
            },
        ]
        role_playbooks = [
            {
                "title": "User sequence",
                "badge": "secondary",
                "steps": [
                    "Open assigned projects from Dashboard ➜ Project List.",
                    "Launch permitted scans (Launch Scans ➜ Web/Network) for those projects.",
                    "Review and triage findings in Scans and Project views.",
                    "Watch Dashboard for trends and counts relevant to your projects.",
                    "Generate reports."
                ],
            },
        ]
        workflows = [
            {
                "title": "Launch scans on assigned projects",
                "steps": [
                    "Go to Launch Scans ➜ Web/Network",
                    "Select your project and target, then submit",
                    "Track results under Scans ➜ Web/Network",
                ],
                "hint": "Ensure you pick the correct project so findings roll up correctly.",
            },
            {
                "title": "Triage findings",
                "steps": [
                    "Open Scans or the Project view to review issues",
                    "Use status/severity to prioritize work",
                    "Coordinate with your team via notifications or reports",
                ],
                "hint": "Leverage Dashboard for trend awareness.",
            },
        ]
        navigation = [
            {"label": "Dashboard", "desc": "Your overview and Project List.", "url": "dashboard:dashboard"},
            {"label": "Scans ➜ Web/Network", "desc": "Browse results and history.", "url": "webscanners:list_scans"},
            {"label": "Launch Scans", "desc": "Start Web or Network scans for your projects.", "url": "webscanners:index"},
            {"label": "Reports", "desc": "Generate reports when permitted.", "url": "reports:generate_report"},
            {"label": "Projects", "desc": "View project catalog.", "url": "projects:manage"},
        ]
        return {
            "role_matrix": role_matrix,
            "role_playbooks": role_playbooks,
            "workflows": workflows,
            "navigation": navigation,
        }

    def get(self, request):
        role_name = str(getattr(request.user, "role", ""))
        is_super = getattr(request.user, "is_superuser", False)
        is_admin = is_super or role_name == "Admin"
        is_org_admin = role_name == "Organization Admin"

        if is_admin:
            ctx = self._admin_context()
            ctx["guide_title"] = "Admin Guide"
            ctx["guide_banner"] = "This page is visible to Admins. Use it as the in-product guide for setup, day-to-day work, and to onboard Organization Admins or Analysts."
            ctx["fast_paths"] = [
                "Add users and set roles from Settings > Users.",
                "Keep SMTP, ZAP, OpenVAS, and Jira healthy via Settings > Connectors.",
                "Launch scans from Launch Scans, then track them in Scans.",
                "Use Admin Logs and Admin Scan Explorer for full audit visibility.",
                "Create API keys in Settings > Access Keys for automation.",
            ]
            ctx["fast_paths_title"] = "Fast paths for Admins"
            ctx["lifecycle"] = [
                "Prepare: ensure the project exists; connectors (ZAP/OpenVAS/Jira/Email) are green in Settings ➜ Connectors.",
                "Launch: go to Launch Scans (Web or Network), set the target, select the project, and submit.",
                "Monitor: view progress and results under Scans > Web/Network; Admins can use Admin Scan Explorer for a global view.",
                "Notify/report: send updates with Settings ➜ Email or export from Reports.",
                "Close/triage: work findings in Project view or Dashboard; mark false positives or closed where applicable.",
            ]
            ctx["lifecycle_title"] = "Scan lifecycle at a glance"
            ctx["ops_tips"] = [
                {
                    "title": "User and org hygiene",
                    "items": [
                        "Keep Organizations aligned to business units; assign an Organization Admin per org.",
                        "Use the Users list bulk delete carefully; protected Admin/superuser rows cannot be removed by Org Admins.",
                        "Rotate API Access Keys regularly and disable unused ones.",
                    ],
                },
                {
                    "title": "Connectors and notifications",
                    "items": [
                        "After saving SMTP settings, always run Send Test to update status.",
                        "Use Admin Logs to trace scan launches and connector tests.",
                        "Encourage analysts to watch the bell icon for live notifications and clear them regularly.",
                    ],
                },
            ]
        elif is_org_admin:
            ctx = self._org_admin_context()
            ctx["guide_title"] = "Organization Admin Guide"
            ctx["guide_banner"] = "This guide is tailored to Organization Admins. It covers the tasks you can perform inside your organization."
            ctx["fast_paths"] = [
                "Add users and set roles from Settings > Users (org scope).",
                "Create and manage org projects in Projects.",
                "Launch scans from Launch Scans for org projects; track them in Scans.",
                "Generate reports for stakeholders.",
                "Monitor Dashboard for org posture and trends.",
            ]
            ctx["fast_paths_title"] = "Fast paths for Org Admins"
            ctx["lifecycle"] = [
                "Prepare: ensure the project exists and targets are assigned to the right project.",
                "Launch: use Launch Scans (Web or Network), set the target, select the project, and submit.",
                "Monitor: view progress and results under Scans > Web/Network.",
                "Notify/report: export from Reports; request Admins for email broadcasts if needed.",
                "Close/triage: work findings in Project view or Dashboard; mark false positives or closed where applicable.",
            ]
            ctx["lifecycle_title"] = "Scan lifecycle for Org Admins"
            ctx["ops_tips"] = [
                {
                    "title": "User and org hygiene",
                    "items": [
                        "Keep org projects organized by team or application.",
                        "Use the Users list carefully; protected Admin/superuser rows cannot be removed.",
                        "Coordinate with Admins for connector/email changes.",
                    ],
                },
                {
                    "title": "Notifications and reporting",
                    "items": [
                        "Use reports to share updates with stakeholders.",
                        "Encourage analysts to watch the bell icon for live notifications and clear them regularly.",
                        "Ask Admins to send email broadcasts when required.",
                    ],
                },
            ]
        else:
            ctx = self._user_context()
            ctx["guide_title"] = "User Guide"
            ctx["guide_banner"] = "This guide is tailored to Users. It focuses on the actions you can take on assigned projects."
            ctx["fast_paths"] = [
                "Open your projects from Dashboard > Project List.",
                "Launch permitted scans from Launch Scans.",
                "Review results under Scans and Project views.",
                "Generate or download reports if permitted; otherwise ask your Org Admin to share exports.",
            ]
            ctx["fast_paths_title"] = "Fast paths for Users"
            ctx["lifecycle"] = [
                "Prepare: pick the correct project before launching scans.",
                "Launch: use Launch Scans (Web or Network) and submit your target.",
                "Monitor: check Scans > Web/Network for progress and results.",
                "Report: download or request reports from your Org Admin.",
                "Triage: work findings in Project view or Dashboard; flag false positives when allowed.",
            ]
            ctx["lifecycle_title"] = "Scan lifecycle for Users"
            ctx["ops_tips"] = [
                {
                    "title": "Working smoothly",
                    "items": [
                        "Coordinate with your Org Admin for project access and scope.",
                        "Check scan results regularly to stay on top of updates.",
                        "Keep notes on scan targets and timing for easier follow-up.",
                    ],
                },
                {
                    "title": "Reporting",
                    "items": [
                        "Export reports if your role allows it; otherwise ask an Org Admin/Admin.",
                        "Provide concise updates to your Org Admin or project owner.",
                    ],
                },
            ]

        ctx["dashboard_notes"] = self._base_dashboard_notes()
        return render(request, self.template_name, ctx)
