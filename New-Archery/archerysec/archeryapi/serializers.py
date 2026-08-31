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

from rest_framework import serializers


class CreateUser(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)


class OrgAPIKeySerializer(serializers.Serializer):
    api_key = serializers.CharField(max_length=255)
    uu_id = serializers.CharField(max_length=255)


class GenericScanResultsDbSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField(required=True, help_text=("Provide ScanId"))
    project_id = serializers.UUIDField(read_only=True)
    date_time = serializers.DateTimeField(read_only=True)
    vuln_id = serializers.UUIDField(read_only=True)
    false_positive = serializers.CharField(read_only=True)
    severity_color = serializers.CharField(read_only=True)
    dup_hash = serializers.CharField(read_only=True)
    vuln_duplicate = serializers.CharField(read_only=True)
    false_positive_hash = serializers.CharField(read_only=True)
    vuln_status = serializers.CharField(read_only=True)
    jira_ticket = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    solution = serializers.CharField(read_only=True)
    scanner = serializers.CharField(read_only=True)
    target = serializers.CharField(read_only=True)
    cvss_score = serializers.FloatField(read_only=True, required=False)
    mitre_techniques = serializers.CharField(read_only=True, required=False)
    risk_score = serializers.FloatField(read_only=True, required=False)


class JiraLinkSerializer(serializers.Serializer):
    vuln_id = serializers.UUIDField(read_only=True)
    link_jira_ticket_id = serializers.CharField(max_length=255)
    current_jira_ticket_id = serializers.CharField(max_length=255)


class AuditLogSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    user_email = serializers.CharField(read_only=True)
    action = serializers.CharField(read_only=True)
    resource_type = serializers.CharField(read_only=True)
    resource_id = serializers.CharField(read_only=True)
    details = serializers.JSONField(read_only=True)
    ip_address = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class NotificationSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    verb = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    unread = serializers.BooleanField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)


class NotificationPreferencesSerializer(serializers.Serializer):
    notify_email = serializers.BooleanField(required=False)
    notify_in_app = serializers.BooleanField(required=False)
    notify_on_scan_start = serializers.BooleanField(required=False)
    notify_on_scan_complete = serializers.BooleanField(required=False)
    notify_on_scan_fail = serializers.BooleanField(required=False)
    notify_critical_only = serializers.BooleanField(required=False)


class ReportDownloadSerializer(serializers.Serializer):
    project_id = serializers.ListField(child=serializers.CharField(), required=False)
    scan_types = serializers.ListField(child=serializers.CharField(), required=False)
    format = serializers.ChoiceField(choices=["pdf", "html", "csv", "xml", "jinja2_pdf", "jinja2_html", "jinja2_csv", "jinja2_xml", "jinja2_json"], default="pdf")
    severity = serializers.ListField(child=serializers.CharField(), required=False)
    sections = serializers.ListField(child=serializers.CharField(), required=False)
    status = serializers.CharField(required=False)
