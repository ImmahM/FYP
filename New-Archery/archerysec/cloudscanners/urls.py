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

from django.urls import include, path
from django.http import HttpResponseNotFound

app_name = "cloudscanners"


def disabled_view(request, *args, **kwargs):
    return HttpResponseNotFound("Cloud scanning is disabled.")


urlpatterns = [
    # Cloud scanning disabled: keep names for reverse() but return 404
    path("list_vuln/", disabled_view, name="list_vuln"),
    path("list_scans/", disabled_view, name="list_scans"),
    path("list_vuln_info/", disabled_view, name="list_vuln_info"),
    path("scan_details/", disabled_view, name="scan_details"),
    path("scan_delete/", disabled_view, name="scan_delete"),
    path("vuln_delete/", disabled_view, name="vuln_delete"),
    path("vuln_mark/", disabled_view, name="vuln_mark"),
]
