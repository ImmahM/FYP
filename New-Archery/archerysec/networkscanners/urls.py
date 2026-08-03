#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2017 Anand Tiwari

from django.urls import include, path

from networkscanners import views

app_name = "networkscanners"

urlpatterns = [
    path("launch_scan/", views.OpenvasLaunchScan.as_view(), name="launch_scan"),
    path("ip_scan/", views.NetworkScan.as_view(), name="ip_scan"),
    path("nv_setting/", views.OpenvasSettingEnable.as_view(), name="nv_setting"),
    path("nv_details/", views.OpenvasSettingEnableDetails.as_view(), name="nv_details"),
    path("openvas_setting/", views.OpenvasSetting.as_view(), name="openvas_setting"),
    path("openvas_details/", views.OpenvasDetails.as_view(), name="openvas_details"),
    path("net_scan_schedule/", views.NetworkScanSchedule.as_view(), name="net_scan_schedule"),
    path("del_net_scan_schedule/", views.NetworkScanScheduleDelete.as_view(), name="del_net_scan_schedule"),
    path("list_scans/", views.NetworkScanList.as_view(), name="list_scans"),
    path("recent/", views.NetworkScanRecent.as_view(), name="recent_scans"),
    path("admin_scans/", views.AdminNetworkScanExplorer.as_view(), name="admin_scans"),
    path("list_vuln_info/", views.NetworkScanVulnInfo.as_view(), name="list_vuln_info"),
    path("scan_details/", views.NetworkScanDetails.as_view(), name="scan_details"),
    path("scan_delete/", views.NetworkScanDelete.as_view(), name="scan_delete"),
    path("vuln_delete/", views.NetworkScanVulnDelete.as_view(), name="vuln_delete"),
    path("vuln_mark/", views.NetworkScanVulnMark.as_view(), name="vuln_mark"),
    path("rescan/", views.NetworkRescan.as_view(), name="rescan"),
    path("stop/", views.NetworkStop.as_view(), name="stop"),
    # Batch summaries for in-progress rows
    path("scan_summaries/", views.NetworkScanSummaries.as_view(), name="scan_summaries"),
    # Single-row refresh endpoint
    path("scan_row/", views.NetworkScanRow.as_view(), name="scan_row"),
    # Nmap launch endpoint
    path("nmap_launch/", views.NmapLaunch.as_view(), name="nmap_launch"),
    # Nmap log viewer
    path("nmap_log/", views.NmapLog.as_view(), name="nmap_log"),
    path("openvas_log/", views.OpenVASLog.as_view(), name="openvas_log"),
    path("openvas_service_log/", views.OpenVASServiceLog.as_view(), name="openvas_service_log"),
    path("nmap_latest_log/", views.NmapLatestLog.as_view(), name="nmap_latest_log"),
]
