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

from django.db import models
from django.utils import timezone

from user_management.models import Organization, UserProfile


class ZapSettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    zap_url = models.TextField(blank=False, null=False, default="127.0.0.1")
    zap_api = models.TextField(
        blank=False, null=False, default="dwed23wdwedwwefw4rwrfw"
    )
    zap_port = models.IntegerField(blank=False, null=False, default=8090)
    enabled = models.BooleanField(blank=False, null=False)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="zap_settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="zap_settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class ArachniSettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    arachni_url = models.TextField(blank=True, null=True)
    arachni_port = models.TextField(blank=True, null=True)
    arachni_user = models.TextField(blank=True, null=True)
    arachni_pass = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(auto_now=True, blank=True)
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="arachni_settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="arachni_settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class BurpSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    burp_url = models.TextField(blank=True, null=True)
    burp_port = models.TextField(blank=True, null=True)
    burp_api_key = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="burp_settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="burp_settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class OpenvasSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    host = models.TextField(blank=True, null=True)
    port = models.IntegerField(blank=False, null=False, default=9390)
    enabled = models.BooleanField(blank=False, null=False)
    user = models.TextField(blank=True, null=True)
    password = models.TextField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="openvas_settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="openvas_settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class NmapSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    # Optional override for the nmap binary; leave blank to auto-detect from PATH
    binary_path = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(blank=False, null=False, default=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nmap_setting_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nmap_setting_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class NiktoSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    # Optional override for the nikto binary; leave blank to auto-detect from PATH
    binary_path = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(blank=False, null=False, default=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nikto_setting_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nikto_setting_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class NmapVulnersSettingDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    enabled = models.BooleanField(blank=False, null=False)
    # -sV | Version detection
    version = models.BooleanField(blank=False, null=False)
    # -Pn | Treat all hosts as online -- skip host discovery
    online = models.BooleanField(blank=False, null=False)
    # -T4 | Set timing template (higher is faster)
    timing = models.IntegerField(blank=False, null=False, default=0)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nmap_vulner_settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="nmap_vulner_settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)


class EmailDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)

    # Message defaults (existing)
    subject = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    recipient_list = models.TextField(blank=True)

    # NEW: SMTP configuration saved per organization (used by the updated view)
    smtp_host = models.CharField(
        max_length=255, blank=True, null=True, help_text="SMTP server hostname, e.g. smtp.gmail.com"
    )
    smtp_port = models.PositiveIntegerField(
        blank=True, null=True, default=587, help_text="SMTP port (587 for STARTTLS, 465 for SSL)"
    )
    smtp_use_tls = models.BooleanField(
        default=True, help_text="Use STARTTLS (recommended with port 587)"
    )
    smtp_user = models.CharField(
        max_length=255, blank=True, null=True, help_text="SMTP username / login"
    )
    smtp_password = models.TextField(
        blank=True, null=True, help_text="Encrypted via django.core.signing before save"
    )
    sender_email = models.EmailField(
        blank=True, null=True, help_text="From address shown to recipients"
    )

    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="email_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="email_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)

    class Meta:
        verbose_name = "Email Setting"
        verbose_name_plural = "Email Settings"

    def __str__(self):
        org = getattr(self.organization, "name", str(self.organization_id))
        return "Email settings for org={}".format(org)


class SettingsDb(models.Model):
    setting_id = models.UUIDField(blank=True, null=True)
    setting_name = models.TextField(blank=True, null=True)
    setting_scanner = models.TextField(blank=True, null=True)
    setting_status = models.BooleanField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="settings_db_created",
    )
    updated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name="settings_db_updated",
    )
    is_active = models.BooleanField(default=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)
