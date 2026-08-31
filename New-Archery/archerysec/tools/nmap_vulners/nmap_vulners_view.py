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

from itertools import starmap

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from notifications.signals import notify

from tools.models import NmapResultDb, NmapScanDb, NmapVulnersPortResultDb
from tools.nmap_vulners.nmap_vulners_scan import run_nmap_vulners


def nmap_vulners_scan(request):
    """

    :return:
    """
    all_nmap = NmapScanDb.objects.filter()

    return render(
        request, "tools/nmap_scan.html", {"all_nmap": all_nmap, "is_vulners": True}
    )


def nmap_vulners(request):
    """

    :return:
    """
    user = request.user

    all_nmap = ""

    if request.method == "POST":
        ip_address = request.POST.get("ip")
        project_id = request.POST.get("project_id")

        # Preflight: require the org-level Nmap connector (parity with other Nmap launch paths)
        try:
            from archerysettings.models import SettingsDb as _SettingsDb
            has_connector = _SettingsDb.objects.filter(
                setting_scanner="Nmap",
                organization=request.user.organization,
                setting_status=True,
            ).exists()
        except Exception:
            has_connector = False
        if not has_connector:
            return HttpResponse(
                "Nmap settings are missing or disabled for your organization. Configure it under Settings → Add Connector → Nmap.",
                status=400,
            )

        try:
            run_nmap_vulners(ip_addr=ip_address, project_id=project_id)
            notify.send(user, recipient=user, verb="NMAP Scan Completed")
        except Exception as e:
            print("Error in nmap_vulners scan:", e)

        return HttpResponseRedirect("/tools/nmap_scan/")

    elif request.method == "GET":
        ip_address = request.GET.get("ip")

        all_nmap = NmapResultDb.objects.filter(ip_address=ip_address)

    return render(request, "tools/nmap_vulners_list.html", {"all_nmap": all_nmap})


def nmap_vulners_port(request):
    ip_address = request.GET.get("ip")
    port = request.GET.get("port")
    if not (ip_address and port):
        raise ValueError("Nmap Vulners Port info: both IP and port must be present.")

    port_info = NmapVulnersPortResultDb.objects.filter(ip_address=ip_address, port=port)

    cve_info = list()
    if port_info.first().vulners_extrainfo:
        info = port_info.first().vulners_extrainfo.split("\n\t")[1:]
        info_gen = starmap(lambda x: x.split("\t\t"), info)

        names = (
            "cve",
            "cvss",
            "link",
        )
        cve_info = (dict(zip(names, info)) for info in info_gen)

    return render(
        request,
        "tools/nmap_vulners_port_list.html",
        {"ip": ip_address, "port": port, "cve_info": cve_info},
    )
