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
        all_email = EmailDb.objects.filter(organization=request.user.organization)
        data = all_email.first()
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
            except Exception:
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
