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

import codecs
import hashlib
import os
import subprocess
import uuid
from datetime import datetime
from django.utils import timezone
import threading
from urllib.parse import urlparse
import ipaddress
import signal
import time

import defusedxml.ElementTree as ET
from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render
from django.http import HttpResponse
from django.urls import reverse
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from scanners.scanner_parser.network_scanner import nmap_parser
from projects.models import ProjectDb
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from tools.models import (NiktoResultDb, NiktoVulnDb, NmapResultDb, NmapScanDb,
                          SslscanResultDb)
from webscanners.models import WebScansDb
# NOTE[gmedian]: in order to be more portable we just import everything rather than add anything in this very script
from tools.nmap_vulners.nmap_vulners_view import (nmap_vulners,
                                                  nmap_vulners_port,
                                                  nmap_vulners_scan)
from user_management import permissions

sslscan_output = None
nikto_output = ""
scan_result = ""
all_nmap = ""

_WEB_URL_ERROR = "Web scans only support URLs (e.g., https://example.com)."


def _parse_url_targets(raw_value):
    raw = str(raw_value or "").replace("\n", ",")
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    targets = []
    invalid = []
    seen = set()
    for tok in tokens:
        try:
            parsed = urlparse(tok)
            if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                if tok not in seen:
                    targets.append(tok)
                    seen.add(tok)
                continue
        except Exception:
            pass
        invalid.append(tok)
    return targets, invalid


def _url_error_message(invalid_targets):
    if invalid_targets:
        uniq = list(dict.fromkeys(invalid_targets))
        preview = ", ".join(uniq[:3])
        if len(uniq) > 3:
            preview += f" (+{len(uniq) - 3} more)"
        return f"{_WEB_URL_ERROR} Invalid input: {preview}"
    return _WEB_URL_ERROR


class SslScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/sslscan_list.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        all_sslscan = SslscanResultDb.objects.filter(
            organization=request.user.organization
        )

        return render(request, "tools/sslscan_list.html", {"all_sslscan": all_sslscan})


class SslScanLaunch(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/sslscan_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        sslscan_output = ""
        user = request.user
        scan_url = request.POST.get("scan_url")
        project_id = request.POST.get("project_id")

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = uuid.uuid4()
            scans_url = value_split.__getitem__(i)

            try:
                sslscan_output = subprocess.check_output(
                    ["sslscan", "--no-colour", scans_url]
                )
                notify.send(recipient=user, verb="SSLScan Completed")

            except Exception as e:
                print(e)

            dump_scans = SslscanResultDb(
                scan_url=scans_url,
                scan_id=scan_id,
                project_id=project_id,
                sslscan_output=sslscan_output,
                organization=request.user.organization,
            )

            dump_scans.save()
            return HttpResponseRedirect(reverse("tools:sslscan"))


class SslScanResult(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/sslscan_result.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        scan_result = SslscanResultDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )
        return render(
            request, "tools/sslscan_result.html", {"scan_result": scan_result}
        )


class SslScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/sslscan_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = SslscanResultDb.objects.filter(
                scan_id=vuln_id, organization=request.user.organization
            )
            del_scan.delete()

        return HttpResponseRedirect(reverse("tools:sslscan"))


class NiktoScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_scan_list.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        all_nikto = NiktoResultDb.objects.filter(organization=request.user.organization)

        return render(request, "tools/nikto_scan_list.html", {"all_nikto": all_nikto})


def _run_nikto_scan(*, scans_url, scan_id, project_id, profile_tuning, request, user, org, nikto_res_path, force_cgi=False, plugins_all=False, maxtime_min=None, pause_sec=None, evasion=None, user_agent=None, config_path=None, extra_flags=None, timeout_s=15):
    """Background task to run Nikto, write HTML and log, parse, and update status."""
    # Prepare log path
    from django.conf import settings as _settings
    log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        # Best effort: if this fails, we'll attempt to open the file later and fail fast
        pass
    log_path = os.path.join(log_dir, f"{scan_id}.log")
    # Touch the log early so the UI stops showing "Waiting for output" immediately
    try:
        with open(log_path, "a", encoding="utf-8", errors="ignore") as _lf_touch:
            _lf_touch.write(f"[archerysec] Nikto scan initialized for {scans_url} (scan_id={scan_id})\n")
            _lf_touch.write(f"[archerysec] Logs: {log_dir} | Results: {os.path.dirname(nikto_res_path)}\n")
            try:
                _lf_touch.flush()
            except Exception:
                pass
    except Exception as _e:
        # If even touching the log fails, record failure_reason and bail
        try:
            from django.utils import timezone as _tz
            NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                nikto_status="Scan Failed"
            )
            WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                failure_reason=f"Cannot write Nikto log: {_e}",
                updated_time=_tz.now(),
            )
        except Exception:
            pass
        return

    # Ensure a log file exists immediately so the UI does not sit in
    # "Waiting for output" limbo. Also makes it easier to surface early
    # failures (e.g., binary missing) since we can append to this file.
    try:
        if not os.path.exists(log_path):
            with open(log_path, "w", encoding="utf-8", errors="ignore") as lf:
                lf.write("- Nikto log initialized\n")
    except Exception:
        # If we cannot create the log file at all, there is likely a
        # filesystem/permissions issue. Continue anyway so that DB status
        # still updates, but the UI will keep showing 'Waiting for output'.
        pass

    def _exec(cmd):
        with open(log_path, "a", encoding="utf-8", errors="ignore") as lf:
            lf.write("$ "+" ".join(cmd)+"\n")
            # start_new_session creates a new process group; easier to kill later
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except Exception as e:
                try:
                    lf.write(f"[archerysec] Failed to start nikto: {e}\n")
                except Exception:
                    pass
                try:
                    from django.utils import timezone as _tz
                    NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                        nikto_status="Scan Failed"
                    )
                    WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                        failure_reason=f"nikto failed to start: {str(e)[:180]}",
                        updated_time=_tz.now(),
                    )
                except Exception:
                    pass
                return 127
            try:
                # Save PID/PGID for stop/kill support
                pgid = os.getpgid(proc.pid)
                from django.utils import timezone as _tz
                NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                    pid=proc.pid,
                    pgid=pgid,
                    nikto_status="Running",
                    created_time=getattr(_tz, "now", timezone.now)(),
                )
            except Exception:
                pass
            start_elapsed_guard = time.time()
            proc.wait()
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as rf:
                    content = rf.read().lower()
                elapsed = time.time() - start_elapsed_guard
                mark = False
                try:
                    if (maxtime_min is not None) and ('maximum execution time' in content):
                        cap_s = int(maxtime_min) * 60
                        if elapsed >= 0.9 * cap_s:
                            mark = True
                except Exception:
                    mark = False
                if mark:
                    from django.utils import timezone as _tz
                    try:
                        NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                            nikto_status='Completed (time-capped)'
                        )
                    except Exception:
                        pass
                    try:
                        WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                            failure_reason='Completed (time-capped)',
                            updated_time=_tz.now()
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        return proc.returncode

    # Fail fast if nikto is not installed or not on PATH
    try:
        import shutil
        _which_nikto = shutil.which("nikto") or shutil.which("nikto.pl")
        if not _which_nikto:
            msg = "Nikto binary not found on server PATH. Install nikto or add it to PATH."
            try:
                with open(log_path, "a", encoding="utf-8", errors="ignore") as lf:
                    lf.write(msg + "\n")
                    lf.write(f"PATH={os.environ.get('PATH','')}\n")
            except Exception:
                pass
            try:
                from django.utils import timezone as _tz
                NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                    nikto_status="Scan Failed"
                )
                WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                    failure_reason=msg,
                    updated_time=_tz.now(),
                )
            except Exception:
                pass
            return
        else:
            try:
                with open(log_path, "a", encoding="utf-8", errors="ignore") as lf:
                    lf.write(f"[archerysec] Using nikto at: {_which_nikto}\n")
            except Exception:
                pass
    except Exception:
        pass

    # Normalize target and decide flags
    parsed = urlparse(scans_url)
    target_host = parsed.hostname or scans_url

    def _is_ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

    # Build primary and fallback commands
    # Base Nikto command with execution guards
    cmd = [
        "nikto",
        "-o", nikto_res_path,
        "-Format", "htm",
        # optional -maxtime added below
        "-timeout", str(int(timeout_s)),
        "-ask", "no",
    ]
    # Advanced flags
    if user_agent:
        cmd += ["-useragent", str(user_agent)]
    if evasion:
        cmd += ["-evasion", str(evasion)]
    try:
            if pause_sec:
                ps = int(pause_sec)
                jitter = max(1, int(round(ps * (1 + (random.random()*0.4 - 0.2)))))
                cmd += ["-Pause", str(jitter)]
    except Exception:
        pass
    if config_path:
        cmd += ["-config", config_path]
    # Advanced flags from presets/inputs
    if user_agent:
        cmd += ["-useragent", str(user_agent)]
    if evasion:
        cmd += ["-evasion", str(evasion)]
    try:
        if pause_sec:
            ps = int(pause_sec)
            if ps > 0:
                cmd += ["-Pause", str(ps)]
    except Exception:
        pass
    if config_path:
        cmd += ["-config", config_path]
    # Only use -nolookup if the target is an IP address
    if _is_ip(target_host):
        cmd += ["-nolookup"]
    # Max time in minutes
    try:
        if maxtime_min is not None:
            mt = int(maxtime_min)
            if mt > 0:
                cmd += ["-maxtime", f"{mt}m"]
    except Exception:
        pass
    # Plugins and CGI options
    if plugins_all:
        cmd += ["-Plugins", "all"]
    if force_cgi:
        cmd += ["-C", "all"]
    # Respect profile tuning
    if profile_tuning:
        cmd += ["-Tuning", profile_tuning]
    if extra_flags:
        try:
            cmd += list(extra_flags)
        except Exception:
            pass
    # HTTPS hint if scheme provided
    if parsed.scheme == "https":
        cmd += ["-ssl"]
    cmd += ["-host", target_host]

    rc = _exec(cmd)
    if rc != 0:
        # fallback to nikto.pl
        cmd2 = [
            "nikto.pl",
            "-o", nikto_res_path,
            "-Format", "htm",
            # optional -maxtime added below
            "-timeout", str(int(timeout_s)),
            "-ask", "no",
        ]
        if user_agent:
            cmd2 += ["-useragent", str(user_agent)]
        if evasion:
            cmd2 += ["-evasion", str(evasion)]
        try:
            if pause_sec:
                ps = int(pause_sec)
                jitter = max(1, int(round(ps * (1 + (random.random()*0.4 - 0.2)))))
                cmd2 += ["-Pause", str(jitter)]
        except Exception:
            pass
        if config_path:
            cmd2 += ["-config", config_path]
        if user_agent:
            cmd2 += ["-useragent", str(user_agent)]
        if evasion:
            cmd2 += ["-evasion", str(evasion)]
        try:
            if pause_sec:
                ps = int(pause_sec)
                if ps > 0:
                    cmd2 += ["-Pause", str(ps)]
        except Exception:
            pass
        if config_path:
            cmd2 += ["-config", config_path]
        try:
            if maxtime_min is not None:
                mt = int(maxtime_min)
                if mt > 0:
                    cmd2 += ["-maxtime", f"{mt}m"]
        except Exception:
            pass
        if plugins_all:
            cmd2 += ["-Plugins", "all"]
        if _is_ip(target_host):
            cmd2 += ["-nolookup"]
        if force_cgi:
            cmd2 += ["-C", "all"]
        if profile_tuning:
            cmd2 += ["-Tuning", profile_tuning]
        if parsed.scheme == "https":
            cmd2 += ["-ssl"]
        if extra_flags:
            try:
                cmd2 += list(extra_flags)
            except Exception:
                pass
        cmd2 += ["-host", target_host]
        rc = _exec(cmd2)

    # Attempt to parse if HTML exists
    try:
        if os.path.exists(nikto_res_path):
            with codecs.open(nikto_res_path, "r") as f:
                data = f.read()
            nikto_html_parser(data, project_id, scan_id, request)
            notify.send(user, recipient=user, verb="Nikto Scan Completed")
            NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                nikto_status="Scan Completed"
            )
        else:
            NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                nikto_status="Scan Failed"
            )
            try:
                from django.utils import timezone as _tz
                WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                    failure_reason="Nikto did not produce a results file (check Nikto log)",
                    updated_time=_tz.now(),
                )
            except Exception:
                pass
    except Exception as e:
        try:
            NiktoResultDb.objects.filter(scan_id=scan_id, organization=org).update(
                nikto_status="Scan Failed"
            )
            from django.utils import timezone as _tz
            WebScansDb.objects.filter(scan_id=scan_id, organization=org).update(
                failure_reason=f"Nikto failed: {str(e)[:180]}",
                updated_time=_tz.now(),
            )
        except Exception:
            pass


class NiktoScanLaunch(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_scan_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        user = request.user
        timeout_s = 15
        # Accept either 'scan_url' (tools form) or 'url' (web scanner form)
        scan_url = request.POST.get("scan_url") or request.POST.get("url")
        # Convert project uu_id to numeric id if needed
        project_uu_id = request.POST.get("project_id")
        try:
            if project_uu_id and not str(project_uu_id).isdigit():
                project_id = (
                    ProjectDb.objects.filter(uu_id=project_uu_id, organization=request.user.organization)
                    .values("id")
                    .get()["id"]
                )
            else:
                project_id = project_uu_id
        except Exception:
            project_id = None
        # Optional: profile/tuning controls
        # New multi-switch inputs (custom tuning removed per request)
        def _to_bool(v):
            return str(v).lower() in ("1","true","on","yes")
        comp = _to_bool(request.POST.get("nikto_comprehensive"))  # repurposed: File Retrieval preset
        base = _to_bool(request.POST.get("nikto_baseline"))       # repurposed: Stealth Info preset
        inj = _to_bool(request.POST.get("nikto_injection"))       # repurposed: Targeted Injection preset
        broad = _to_bool(request.POST.get("nikto_broad"))         # new: Broad excluding DoS
        force_cgi_toggle = _to_bool(request.POST.get("nikto_force_cgi"))
        # Optional max time in minutes
        maxtime_raw = request.POST.get("nikto_maxtime_min")
        try:
            maxtime_min = int(str(maxtime_raw).strip()) if str(maxtime_raw).strip() else None
            if maxtime_min is not None and maxtime_min < 1:
                maxtime_min = None
        except Exception:
            maxtime_min = None
        # Map to your requested four profiles
        profile_tuning = None
        plugins_all = False
        pause_sec = None
        evasion = None
        force_cgi = False
        # Comprehensive File Retrieval & Server-Side Scan
        if comp:
            profile_tuning = "57"
            evasion = "248"
            pause_sec = 10
        # Targeted Injection & XSS Vulnerability Scan
        elif inj:
            profile_tuning = "49a"
            evasion = "17"
            pause_sec = 7
        # Stealthy Information Gathering & Software Identification
        elif base:
            profile_tuning = "3b"
            pause_sec = 5
        # Broad Scan with Dangerous Test Exclusions
        elif broad:
            profile_tuning = "x6"
            pause_sec = 6

        # Preset-driven options
        preset = (request.POST.get("nikto_preset") or "").strip()
        user_agent = (request.POST.get("nikto_useragent") or "").strip()
        pause_sec = None
        evasion = None
        if preset:
            if preset == "stealth_info":
                pause_sec = 5
                profile_tuning = "3b"
                plugins_all = False
                if not user_agent:
                    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
            elif preset == "targeted_injection":
                pause_sec = 7
                profile_tuning = "49a"
                evasion = "17"
                plugins_all = False
            elif preset == "file_retrieval":
                pause_sec = 10
                profile_tuning = "57"
                evasion = "248"
                plugins_all = False
            elif preset == "broad_no_dos":
                pause_sec = 6
                profile_tuning = "x6"
                plugins_all = False

        # Optional error limit (FAILURES) support: numeric or disable via 0
        disable_failures = str(request.POST.get("nikto_disable_failures")).lower() in ("1","true","on","yes")
        failures_value = None
        try:
            _raw = request.POST.get("nikto_failures")
            if _raw is not None:
                _s = str(_raw).strip()
                if _s != "":
                    failures_value = int(_s)
                    if failures_value < 0:
                        failures_value = None
        except Exception:
            failures_value = None

        targets, invalid_targets = _parse_url_targets(scan_url)
        if (not targets) or invalid_targets:
            msg = _url_error_message(invalid_targets)
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
            return HttpResponse(msg, status=400)

        for scans_url in targets:
            date_time = datetime.now()
            scan_id = uuid.uuid4()

            from django.conf import settings as _settings
            nikto_res_dir = getattr(_settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result"))
            try:
                os.makedirs(nikto_res_dir, exist_ok=True)
            except Exception:
                pass
            nikto_res_path = os.path.join(nikto_res_dir, f"{scan_id}.html")

            # Pre-touch the Nikto log as soon as the scan is queued so the UI sees it immediately
            try:
                nikto_log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
                os.makedirs(nikto_log_dir, exist_ok=True)
                _pre_log = os.path.join(nikto_log_dir, f"{scan_id}.log")
                with open(_pre_log, "a", encoding="utf-8", errors="ignore") as lf0:
                    lf0.write(f"[archerysec] Queued Nikto scan for {scans_url} (scan_id={scan_id})\n")
            except Exception:
                pass

            # Build per-scan nikto.conf if requested
            config_path = None
            try:
                if disable_failures or (failures_value is not None):
                    from django.conf import settings as _settings
                    conf_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
                    os.makedirs(conf_dir, exist_ok=True)
                    config_path = os.path.join(conf_dir, f"{scan_id}.conf")
                    with open(config_path, "w", encoding="utf-8", errors="ignore") as cf:
                        val = 0 if disable_failures and failures_value is None else int(failures_value)
                        cf.write(f"FAILURES={val}\n")
            except Exception:
                config_path = None

            dump_scans = NiktoResultDb(
                scan_url=scans_url,
                scan_id=scan_id,
                project_id=project_id,
                date_time=date_time,
                nikto_status="Scan Started",
                organization=request.user.organization,
            )

            dump_scans.save()
            HttpResponseRedirect(reverse("tools:nikto"))

            # Create a WebScansDb row immediately so it appears in the Web Scans list
            try:
                # Build a friendly scan type label
                if comp:
                    scan_type_label = "Nikto Comprehensive"
                else:
                    parts = []
                    if base:
                        parts.append("Baseline")
                    if inj:
                        parts.append("Injection")
                    scan_type_label = "Nikto " + (" + ".join(parts) if parts else "Default")

                WebScansDb.objects.update_or_create(
                    scan_id=scan_id,
                    organization=request.user.organization,
                    defaults=dict(
                        project_id=project_id,
                        scan_url=scans_url,
                        date_time=timezone.now(),
                        rescan_id=None,
                        rescan="No",
                        scan_status="0",
                        scanner="Nikto",
                        scan_type=scan_type_label,
                        failure_reason=None,
                        created_by=request.user,
                        updated_by=request.user,
                    ),
                )
            except Exception:
                pass

            # Kick off background thread so the POST returns immediately
            thread = threading.Thread(
                target=_run_nikto_scan,
                kwargs=dict(
                    scans_url=scans_url,
                    scan_id=scan_id,
                    project_id=project_id,
                            profile_tuning=profile_tuning,
                            request=request,
                            user=user,
                            org=request.user.organization,
                            nikto_res_path=nikto_res_path,
                            force_cgi=force_cgi,
                            plugins_all=plugins_all,
                            maxtime_min=maxtime_min,
                            pause_sec=pause_sec,
                            evasion=evasion,
                            user_agent=user_agent,
                            config_path=config_path,
                            extra_flags=None,
                            timeout_s=timeout_s,
                ),
            )
            thread.daemon = True
            thread.start()

        return HttpResponseRedirect(reverse("tools:nikto"))


class NiktoScanResult(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_scan_result.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        scan_result = NiktoResultDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        return render(
            request, "tools/nikto_scan_result.html", {"scan_result": scan_result}
        )


class NiktoResultVuln(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_vuln_list.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        scan_result = NiktoVulnDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        vuln_data = NiktoVulnDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
        )

        vuln_data_close = NiktoVulnDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
            vuln_status="Closed",
            organization=request.user.organization,
        )

        false_data = NiktoVulnDb.objects.filter(
            scan_id=scan_id,
            false_positive="Yes",
            organization=request.user.organization,
        )

        # Attach severity from WebScanResultsDb to each row so UI can badge it
        try:
            from webscanners.models import WebScanResultsDb
            ws_rows = WebScanResultsDb.objects.filter(
                scan_id=scan_id, scanner="Nikto", organization=request.user.organization
            ).values("dup_hash", "severity", "severity_color")
            sev_map = {r["dup_hash"]: (r["severity"], r["severity_color"]) for r in ws_rows}
            def _enrich(qs):
                for v in qs:
                    sev, col = sev_map.get(getattr(v, "dup_hash", None), ("Info", "info"))
                    setattr(v, "severity", sev)
                    setattr(v, "severity_color", col)
            _enrich(vuln_data)
            _enrich(vuln_data_close)
            _enrich(false_data)
        except Exception:
            pass

        # Build severity summaries for open, closed, and false-positive
        def _count_sev(qs):
            buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            try:
                for v in qs:
                    label = getattr(v, "severity", "Info") or "Info"
                    buckets[label] = buckets.get(label, 0) + 1
            except Exception:
                pass
            return buckets
        sev_counts = _count_sev(vuln_data)
        sev_counts_closed = _count_sev(vuln_data_close)
        sev_counts_false = _count_sev(false_data)

        return render(
            request,
            "tools/nikto_vuln_list.html",
            {
                "scan_result": scan_result,
                "vuln_data": vuln_data,
                "vuln_data_close": vuln_data_close,
                "false_data": false_data,
                "sev_counts": sev_counts,
                "sev_counts_closed": sev_counts_closed,
                "sev_counts_false": sev_counts_false,
            },
        )

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        NiktoVulnDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id).update(
            false_positive=false_positive,
            vuln_status=status,
            organization=request.user.organization,
        )

        if false_positive == "Yes":
            vuln_info = NiktoVulnDb.objects.filter(
                scan_id=scan_id, vuln_id=vuln_id, organization=request.user.organization
            )
            for vi in vuln_info:
                discription = vi.discription
                hostname = vi.hostname
                dup_data = discription + hostname
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                NiktoVulnDb.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id,
                    organization=request.user.organization,
                ).update(
                    false_positive=false_positive,
                    vuln_status=status,
                    false_positive_hash=false_positive_hash,
                )

        # Persist changes to WebScanResultsDb as well
        try:
            from webscanners.models import WebScanResultsDb
            updated = WebScanResultsDb.objects.filter(
                scan_id=scan_id,
                vuln_id=vuln_id,
                scanner="Nikto",
                organization=request.user.organization,
            ).update(false_positive=false_positive, vuln_status=status)
            if not updated:
                vi = NiktoVulnDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id).first()
                if vi and getattr(vi, "dup_hash", None):
                    WebScanResultsDb.objects.filter(
                        scan_id=scan_id,
                        dup_hash=vi.dup_hash,
                        scanner="Nikto",
                        organization=request.user.organization,
                    ).update(false_positive=false_positive, vuln_status=status)
        except Exception:
            pass


class NiktoVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_vuln_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("del_vuln")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            _vuln_id = value_split.__getitem__(i)
            # Capture dup_hash before delete so we can remove mirrored WebScans results
            try:
                vi = NiktoVulnDb.objects.filter(vuln_id=_vuln_id, scan_id=scan_id).first()
                dup_hash = getattr(vi, "dup_hash", None)
            except Exception:
                dup_hash = None
            NiktoVulnDb.objects.filter(vuln_id=_vuln_id).delete()
            # Best-effort delete from WebScanResultsDb (by vuln_id, fallback dup_hash)
            try:
                from webscanners.models import WebScanResultsDb
                deleted = WebScanResultsDb.objects.filter(
                    scan_id=scan_id,
                    vuln_id=_vuln_id,
                    scanner="Nikto",
                ).delete()
                if (not deleted or deleted[0] == 0) and dup_hash:
                    WebScanResultsDb.objects.filter(
                        scan_id=scan_id,
                        dup_hash=dup_hash,
                        scanner="Nikto",
                    ).delete()
            except Exception:
                pass

        return HttpResponseRedirect("/tools/nikto_result_vul/?scan_id=%s" % scan_id)


class NiktoScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nikto_scan_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()

        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)
            # Best-effort kill before deletion
            try:
                row = NiktoResultDb.objects.filter(
                    scan_id=_scan_id,
                    organization=request.user.organization,
                ).first()
                if row and (row.pgid or row.pid):
                    try:
                        if row.pgid:
                            os.killpg(int(row.pgid), signal.SIGTERM)
                            time.sleep(1.0)
                        if row.pid:
                            os.kill(int(row.pid), signal.SIGTERM)
                            time.sleep(0.5)
                    except Exception:
                        pass
                    # Escalate to SIGKILL if still alive
                    try:
                        if row.pgid:
                            os.killpg(int(row.pgid), signal.SIGKILL)
                        if row.pid:
                            os.kill(int(row.pid), signal.SIGKILL)
                    except Exception:
                        pass
            except Exception:
                pass
            NiktoResultDb.objects.filter(
                scan_id=_scan_id, organization=request.user.organization
            ).delete()
            del_scan = NiktoVulnDb.objects.filter(
                scan_id=_scan_id, organization=request.user.organization
            )
            del_scan.delete()
            # Remove mirrored WebScans DB results for this Nikto scan
            try:
                from webscanners.models import WebScanResultsDb
                WebScanResultsDb.objects.filter(
                    scan_id=_scan_id,
                    scanner="Nikto",
                    organization=request.user.organization,
                ).delete()
            except Exception:
                pass

        # For AJAX callers we just return 200 OK; the list page can be visited separately
        return HttpResponse(status=200)


class NiktoStop(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=400)

        scan_ids = [s.strip() for s in str(scan_id).split(",") if s.strip()]
        for sid in scan_ids:
            try:
                row = NiktoResultDb.objects.filter(
                    scan_id=sid, organization=request.user.organization
                ).first()
                if not row:
                    continue
                # Attempt graceful then forceful stop
                try:
                    if row.pgid:
                        os.killpg(int(row.pgid), signal.SIGTERM)
                    if row.pid:
                        os.kill(int(row.pid), signal.SIGTERM)
                    time.sleep(0.8)
                except Exception:
                    pass
                try:
                    if row.pgid:
                        os.killpg(int(row.pgid), signal.SIGKILL)
                    if row.pid:
                        os.kill(int(row.pid), signal.SIGKILL)
                except Exception:
                    pass
                # Mark stopped in DB and in WebScansDb if present
                from django.utils import timezone as _tz
                NiktoResultDb.objects.filter(id=row.id).update(
                    nikto_status="Stopped",
                )
                try:
                    WebScansDb.objects.filter(
                        scan_id=sid, organization=request.user.organization
                    ).update(failure_reason="Stopped by user", updated_time=_tz.now())
                except Exception:
                    pass
            except Exception:
                pass

        if request.path[:4] == "/api":
            return Response({"message": "Nikto stop requested"}, status=200)
        return HttpResponseRedirect(reverse("tools:nikto"))


class NiktoLog(APIView):
    # Allow all authenticated users (Admin, Organization Admin, Normal User)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET.get("scan_id")
        if not scan_id:
            return HttpResponseRedirect(reverse("tools:nikto"))

        # Ensure the user has access to this scan
        # Admins and superusers can view across organizations; others scoped to their org
        try:
            role_name = str(getattr(request.user, "role", ""))
            is_admin = (role_name == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        if is_admin:
            exists = NiktoResultDb.objects.filter(scan_id=scan_id).exists()
        else:
            exists = NiktoResultDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            ).exists()
        if not exists:
            return HttpResponse("Log not found or access denied", status=404)

        import os
        from django.conf import settings as _settings
        log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
        log_path = os.path.join(log_dir, f"{scan_id}.log")

        # When `raw=1` is passed, always emit plain text (for the JS fetcher)
        raw = request.GET.get("raw") == "1"
        # Tail control to avoid heavy payloads (default 200KB). Use ?full=1 for full log.
        full = request.GET.get("full") == "1"
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200

        if not os.path.exists(log_path):
            if raw:
                # Return a short plain-text message instead of an empty body so browsers don't show a blank page
                msg = f"Log not ready yet. Please retry in a few seconds. (scan_id={scan_id})\n"
                return HttpResponse(msg, status=202, content_type="text/plain")  # 202 = accepted, not ready
            # Render lightweight viewer that auto-refreshes until log appears
            # Provide a small hint if settings fell back to temp dirs
            from django.conf import settings as _settings
            _fb = ""
            try:
                if getattr(_settings, "NIKTO_DIR_FALLBACK_USED", False):
                    _fb = f"Using temp dirs: logs={_settings.NIKTO_LOG_DIR}, results={_settings.NIKTO_RESULT_DIR}"
            except Exception:
                _fb = ""
            return render(
                request,
                "tools/nikto_log.html",
                {"scan_id": scan_id, "has_log": False, "initial": "", "fallback_note": _fb},
            )

        # Log exists – either send raw text or HTML viewer with (tailed) content
        try:
            if full:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            else:
                size = os.path.getsize(log_path)
                start = max(0, size - (max_kb * 1024))
                with open(log_path, "rb") as fhb:
                    fhb.seek(start)
                    chunk = fhb.read()
                content = chunk.decode("utf-8", errors="ignore")
        except Exception as e:
            # On read error: raw callers get 500 text; HTML callers get viewer with error
            if raw:
                return HttpResponse(
                    f"Failed to read log: {e}", status=500, content_type="text/plain"
                )
            from django.conf import settings as _settings
            _fb = ""
            try:
                if getattr(_settings, "NIKTO_DIR_FALLBACK_USED", False):
                    _fb = f"Using temp dirs: logs={_settings.NIKTO_LOG_DIR}, results={_settings.NIKTO_RESULT_DIR}"
            except Exception:
                _fb = ""
            return render(
                request,
                "tools/nikto_log.html",
                {"scan_id": scan_id, "has_log": False, "initial": str(e), "fallback_note": _fb},
                status=500,
            )

        if raw:
            resp = HttpResponse(content, content_type="text/plain")
            try:
                resp["Content-Disposition"] = f"attachment; filename=\"{scan_id}.log\""
            except Exception:
                pass
            return resp
        from django.conf import settings as _settings
        _fb = ""
        try:
            if getattr(_settings, "NIKTO_DIR_FALLBACK_USED", False):
                _fb = f"Using temp dirs: logs={_settings.NIKTO_LOG_DIR}, results={_settings.NIKTO_RESULT_DIR}"
        except Exception:
            _fb = ""
        return render(
            request, "tools/nikto_log.html", {"scan_id": scan_id, "has_log": True, "initial": content, "fallback_note": _fb}
        )


class NiktoLatestLog(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        raw = request.GET.get("raw") == "1"
        full = request.GET.get("full") == "1"
        try:
            max_kb = int(request.GET.get("max_kb", "200"))
        except Exception:
            max_kb = 200
        from django.conf import settings as _settings
        log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
        if not os.path.isdir(log_dir):
            return HttpResponse("", content_type="text/plain") if raw else HttpResponse("No Nikto logs found", status=200)
        candidates = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.log')]
        if not candidates:
            return HttpResponse("", content_type="text/plain") if raw else HttpResponse("No Nikto logs found", status=200)
        latest = max(candidates, key=lambda p: os.path.getmtime(p))
        try:
            if full:
                with open(latest, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
            else:
                size = os.path.getsize(latest)
                start = max(0, size - (max_kb * 1024))
                with open(latest, 'rb') as fh:
                    fh.seek(start)
                    chunk = fh.read()
                content = chunk.decode('utf-8', errors='ignore')
        except Exception as e:
            content = f"Failed to read log: {e}"
        # For raw consumers, prefix fallback hint if temp dirs are used
        if raw:
            try:
                from django.conf import settings as _settings
                if getattr(_settings, "NIKTO_DIR_FALLBACK_USED", False):
                    content = (
                        f"Using temp dirs: logs={_settings.NIKTO_LOG_DIR}, results={_settings.NIKTO_RESULT_DIR}\n\n"
                        + (content or "")
                    )
            except Exception:
                pass
            resp = HttpResponse(content, content_type="text/plain")
            try:
                resp["Content-Disposition"] = "attachment; filename=\"latest_nikto.log\""
            except Exception:
                pass
            return resp
        return HttpResponse(content, status=200)


class NiktoDebug(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAdminOrITUser)

    def get(self, request):
        try:
            from django.conf import settings as _settings
            import shutil
            scan_id = request.GET.get("scan_id")
            log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
            res_dir = getattr(_settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result"))
            fallback = bool(getattr(_settings, "NIKTO_DIR_FALLBACK_USED", False))
            which = shutil.which("nikto") or shutil.which("nikto.pl") or ""
            log_path = os.path.join(log_dir, f"{scan_id}.log") if scan_id else None
            res_path = os.path.join(res_dir, f"{scan_id}.html") if scan_id else None
            data = {
                "log_dir": log_dir,
                "result_dir": res_dir,
                "fallback_used": fallback,
                "nikto_on_path": bool(which),
                "nikto_path": which,
                "log_exists": (os.path.exists(log_path) if log_path else None),
                "result_exists": (os.path.exists(res_path) if res_path else None),
                "log_path": log_path,
                "result_path": res_path,
                "log_dir_files": sorted([f for f in os.listdir(log_dir) if f.endswith('.log')])[-10:] if os.path.isdir(log_dir) else [],
            }
        except Exception as e:
            data = {"error": str(e)}
        return Response(data)

class NiktoRescan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        old_scan_id = request.POST.get("scan_id")
        if not old_scan_id:
            return HttpResponse("scan_id required", status=400)
        try:
            prev = NiktoResultDb.objects.filter(
                scan_id=old_scan_id, organization=request.user.organization
            ).get()
        except Exception:
            return HttpResponse("Previous scan not found", status=404)

        scans_url = prev.scan_url
        project_id = getattr(prev, "project_id", None)
        new_scan_id = uuid.uuid4()
        from django.conf import settings as _settings
        nikto_res_dir = getattr(_settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result"))
        try:
            os.makedirs(nikto_res_dir, exist_ok=True)
        except Exception:
            pass
        nikto_res_path = os.path.join(nikto_res_dir, f"{new_scan_id}.html")

        # Try to recover previous tuning from the old log's first line
        profile_tuning = None
        try:
            from django.conf import settings as _settings
            _log_dir = getattr(_settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto"))
            old_log = os.path.join(_log_dir, f"{old_scan_id}.log")
            if os.path.exists(old_log):
                with open(old_log, "r", encoding="utf-8", errors="ignore") as fh:
                    first = fh.readline()
                idx = first.find("-Tuning ")
                if idx != -1:
                    rest = first[idx + len("-Tuning "):]
                    # token ends at next space
                    token = rest.split()[0]
                    if token:
                        profile_tuning = token.strip()
        except Exception:
            pass

        dump_scans = NiktoResultDb(
            scan_url=scans_url,
            scan_id=new_scan_id,
            project_id=project_id,
            date_time=timezone.now(),
            nikto_status="Scan Started",
            organization=request.user.organization,
        )
        dump_scans.save()

        # Update WebScansDb row for visibility
        try:
            # Preserve previous scan_type label if available so the UI shows the same type
            prev_ws = WebScansDb.objects.filter(scan_id=old_scan_id, organization=request.user.organization).first()
            scan_type_label = getattr(prev_ws, 'scan_type', None) or "Nikto"
            WebScansDb.objects.update_or_create(
                scan_id=new_scan_id,
                organization=request.user.organization,
                defaults=dict(
                    project_id=project_id,
                    scan_url=scans_url,
                    date_time=timezone.now(),
                    rescan_id=str(old_scan_id),
                    rescan="Yes",
                    scan_status="0",
                    scanner="Nikto",
                    scan_type=scan_type_label,
                    failure_reason=None,
                    created_by=request.user,
                    updated_by=request.user,
                ),
            )
        except Exception:
            pass

        # Launch background thread with recovered tuning
        thread = threading.Thread(
            target=_run_nikto_scan,
            kwargs=dict(
                scans_url=scans_url,
                scan_id=new_scan_id,
                project_id=project_id,
                profile_tuning=profile_tuning,
                request=request,
                user=request.user,
                org=request.user.organization,
                nikto_res_path=nikto_res_path,
                force_cgi=False,
                plugins_all=False,
                timeout_s=15,
            ),
        )
        thread.daemon = True
        thread.start()

        return HttpResponse(status=200)


class NmapScan(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nmap_scan.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        all_nmap = NmapScanDb.objects.filter(organization=request.user.organization)

        return render(request, "tools/nmap_scan.html", {"all_nmap": all_nmap})


class Nmap(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nmap_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        ip_address = request.GET.get("ip")
        if not ip_address:
            messages.warning(request, "Missing required parameter: ip.")
            return HttpResponseRedirect(reverse("tools:nmap_scan"))

        all_nmap = NmapResultDb.objects.filter(
            ip_address=ip_address, organization=request.user.organization
        )

        return render(request, "tools/nmap_list.html", {"all_nmap": all_nmap})

    def post(self, request):
        ip_address = request.POST.get("ip")
        project_id = request.POST.get("project_id")
        scan_id = uuid.uuid4()

        try:
            print("Start Nmap scan")
            subprocess.check_output(
                [
                    "nmap",
                    "-v",
                    "-sV",
                    "-Pn",
                    "-p",
                    "1-65535",
                    ip_address,
                    "-oX",
                    "output.xml",
                ]
            )

            print("Completed nmap scan")

        except Exception as e:
            print("Eerror in nmap scan:", e)

        try:
            tree = ET.parse("output.xml")
            root_xml = tree.getroot()

            nmap_parser.xml_parser(
                root=root_xml, scan_id=scan_id, project_id=project_id
            )

        except Exception as e:
            print("Error in xml parser:", e)

        return HttpResponseRedirect("/tools/nmap_scan/")


class NmapResult(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nmap_result.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        scan_id = request.GET["scan_id"]
        scan_result = NmapResultDb.objects.filter(
            scan_id=scan_id, organization=request.user.organization
        )

        return render(request, "tools/nmap_result.html", {"scan_result": scan_result})


class NmapScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "tools/nmap_result.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        ip_address = request.POST.get("ip_address")

        scan_item = str(ip_address)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()

        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = NmapResultDb.objects.filter(
                ip_address=vuln_id, organization=request.user.organization
            )
            del_scan.delete()
            del_scan = NmapScanDb.objects.filter(
                scan_ip=vuln_id, organization=request.user.organization
            )
            del_scan.delete()

        return HttpResponseRedirect(reverse("tools:nmap_scan"))
