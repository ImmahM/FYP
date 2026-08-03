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

import ast
import hashlib
import json
import os
import re
from urllib.parse import urlparse
import time
import uuid

from django.db.models import Q
from zapv2 import ZAPv2

from archerysettings.models import ZapSettingsDb

try:
    from scanners.scanner_parser.web_scanner import zap_xml_parser
except Exception as e:
    print(e)
import subprocess
from datetime import datetime
from django.utils import timezone

import defusedxml.ElementTree as ET

from webscanners.models import (WebScanResultsDb, WebScansDb, cookie_db,
                                excluded_db, zap_spider_db)

# ZAP Database import

# Global Variables
setting_file = os.getcwd() + "/apidata.json"
# zap_setting = load_settings.ArcherySettings(setting_file)
zap_api_key = "dwed23wdwedwwefw4rwrfw"
zap_hosts = "0.0.0.0"
zap_ports = "8090"

risk = ""
name = ""
attack = ""
confidence = ""
wascid = ""
description = ""
reference = ""
sourceid = ""
solution = ""
param = ""
method = ""
url = ""
pluginId = ""
other = ""
alert = ""
messageId = ""
evidence = ""
cweid = ""
risk = ""
vul_col = ""
all_vuln = ""

import socket

# Getting a random free tcp port in python using sockets


def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("", 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port


def zap_local():
    random_port = str(get_free_tcp_port())
    zap_path = "/home/archerysec/app/zap/"
    executable = "zap.sh"
    executable_path = os.path.join(zap_path, executable)

    zap_command = [
        executable_path,
        "-daemon",
        "-config",
        "api.disablekey=false",
        "-config",
        "api.key=" + zap_api_key,
        "-port",
        random_port,
        "-host",
        zap_hosts,
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
    ]

    log_path = os.getcwd() + "/" + "zap.log"

    with open(log_path, "w+") as log_file:
        subprocess.Popen(
            zap_command, cwd=zap_path, stdout=log_file, stderr=subprocess.STDOUT
        )

    return random_port


def zap_connect(random_port):
    """Return a ZAPv2 client pointed to either external ZAP (if enabled)
    or a local instance that this container started.
    - External: use the first enabled ZapSettingsDb row (host/port/api key).
    - Local: connect to 127.0.0.1:<random_port> with the configured api key.
    """
    conf = ZapSettingsDb.objects.filter(enabled=True).first()
    if conf:
        key = conf.zap_api or "none"
        host = conf.zap_url or "zapscanner"
        port = conf.zap_port or 8090
    else:
        # Local instance defaults
        key = zap_api_key  # must match zap_local() '-config api.key'
        host = "127.0.0.1"
        port = random_port
    return ZAPv2(
        apikey=key,
        proxies={
            "http": f"http://{host}:{port}",
            # ZAP API listens on HTTP; duplicate for https to satisfy client
            "https": f"http://{host}:{port}",
        },
    )


def zap_replacer(target_url, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.replacer.remove_rule(description=target_url, apikey=zap_api_key)
    except Exception as e:
        print("ZAP Replacer error")

    return


def zap_spider_thread(count, random_port):
    zap = zap_connect(random_port=random_port)

    zap.spider.set_option_thread_count(count, apikey=zap_api_key)

    return


def zap_scan_thread(count, random_port):
    zap = zap_connect(random_port=random_port)

    zap.ascan.set_option_thread_per_host(count, apikey=zap_api_key)

    return


def zap_spider_setOptionMaxDepth(count, random_port):
    zap = zap_connect(random_port=random_port)

    zap.spider.set_option_max_depth(count, apikey=zap_api_key)

    return


def zap_spider_setOptionMaxChildren(count, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_max_children(count, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionParseRobotsTxt(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_parse_robots_txt(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionParseSitemapXml(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_parse_sitemap_xml(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionPostForm(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_post_form(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionProcessForm(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_process_form(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionSendRefererHeader(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_send_referer_header(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionAcceptCookies(enabled, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_accept_cookies(enabled, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionHandleParameters(mode, random_port):
    """
    mode: 0 ignore parameters, 1 ignore value, 2 use all (matches ZAP API docs)
    """
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_handle_parameters(mode, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_setOptionSkipURLString(skip_token, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.set_option_skip_url_string(skip_token, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_spider_addInScopeRegex(regex, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.spider.add_in_scope_regex(regex=regex, apikey=zap_api_key)
    except Exception:
        pass
    return


def zap_scan_setOptionHostPerScan(count, random_port):
    zap = zap_connect(random_port=random_port)

    zap.ascan.set_option_host_per_scan(count, apikey=zap_api_key)

    return


def zap_scan_setOptionDelayInMs(delay_ms, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.ascan.set_option_delay_in_ms(delay_ms, apikey=zap_api_key)
    except Exception:
        pass
    return


class ZAPScanner:
    """
    ZAP Scanner Plugin. Interacting with ZAP Scanner API.
    """

    # Global variable's
    spider_alert = []
    target_url = []
    driver = []
    new_uri = []
    excluded_url = []
    vul_col = []
    note = []
    rtt = []
    tags = []
    timestamp = []
    responseHeader = []
    requestBody = []
    responseBody = []
    requestHeader = []
    cookieParams = []
    res_type = []
    res_id = []
    alert = []
    project_id = None
    scan_ip = None
    burp_status = 0
    serialNumber = []
    types = []
    name = []
    host = []
    path = []
    location = []
    severity = []
    confidence = []
    issueBackground = []
    remediationBackground = []
    references = []
    vulnerabilityClassifications = []
    issueDetail = []
    requestresponse = []
    vuln_id = []
    methods = []
    dec_res = []
    dec_req = []
    decd_req = []
    scanner = []
    all_scan_url = []
    all_url_vuln = []
    false_positive = ""

    """ Connect with ZAP scanner global variable """

    def _normalize_url(self, u: str) -> str:
        if not u:
            return u
        # Remove zero width and format characters that can slip via paste
        u = re.sub(r"[\u200B-\u200D\uFEFF\u2060]", "", str(u))
        u = u.strip()
        try:
            p = urlparse(u)
            scheme = (p.scheme or "https").lower()
            netloc = p.netloc.lower()
            # Normalize common www. prefix in matching later
            if netloc.startswith("www."):
                netloc = netloc[4:]
            path = p.path or ""
            base = f"{scheme}://{netloc}{path}"
            # remove trailing slash for stable contains checks
            return base[:-1] if base.endswith('/') else base
        except Exception:
            return u

    def __init__(self, target_url, project_id, rescan_id, rescan, random_port, request):
        """

        :param target_url: Target URL parameter.
        :param project_id: Project ID parameter.
        """
        self.raw_target_url = target_url
        self.target_url = self._normalize_url(target_url)
        self.project_id = project_id
        self.rescan_id = rescan_id
        self.rescan = rescan
        self.zap = zap_connect(random_port=random_port)
        self.request = request

        # Try installing useful add-ons once per scanner instance (best-effort)
        try:
            _ = self.zap.autoupdate
            # Install only needed add-ons (best-effort)
            for addon in ["ajaxSpider", "bruteforce"]:
                try:
                    self.zap.autoupdate.install_addon(addonId=addon)
                except Exception:
                    pass
        except Exception:
            pass

        # Optional: disable browser-dependent scanners (e.g., DOM XSS) when
        # the environment cannot run Selenium/Firefox. Enable by exporting
        # ARCHERYSEC_ZAP_DISABLE_DOMXSS=1 in the environment.
        try:
            if os.environ.get("ARCHERYSEC_ZAP_DISABLE_DOMXSS", "0") in ("1", "true", "True"):
                try:
                    # DOM XSS active scan rule id commonly 40026; ignore if unknown
                    self.zap.ascan.disable_scanners(ids="40026", apikey=zap_api_key)
                except Exception:
                    pass
        except Exception:
            pass

    def _map_risk(self, value: str):
        v = (value or "").strip()
        if v.lower() == "critical":
            return ("Critical", "critical")
        if v.lower() == "high":
            return ("High", "danger")
        if v.lower() == "medium":
            return ("Medium", "warning")
        if v.lower() in ("low", "informational", "info", "information"):
            # Keep Info separate for counting; UI color class uses 'info'
            label = "Informational" if v.lower() in ("informational", "info", "information") else "Low"
            color = "info" if label == "Informational" else "info"
            return (label, color)
        return ("Informational", "info")

    def _persist_alerts(self, alerts, un_scanid, project_id):
        """Idempotently save alerts during polling, update counts."""
        if not alerts:
            return
        request = self.request
        target_url = self.raw_target_url
        for data in alerts:
            try:
                name = data.get("name")
                risk_label, vul_col = self._map_risk(data.get("risk"))
                reference = data.get("reference")
                evidence = data.get("evidence")
                title = name
                duplicate_key = (name or "") + (risk_label or "") + (self.target_url or "")
                duplicate_hash = hashlib.sha256(duplicate_key.encode("utf-8")).hexdigest()
                # de-dup per scan_id
                if WebScanResultsDb.objects.filter(dup_hash=duplicate_hash, scan_id=un_scanid, organization=request.user.organization).exists():
                    continue
                dump_data = WebScanResultsDb(
                    vuln_id=uuid.uuid4(),
                    severity_color=vul_col,
                    scan_id=un_scanid,
                    project_id=project_id,
                    severity=risk_label,
                    reference=reference,
                    url=target_url,
                    title=title,
                    solution=data.get("solution"),
                    instance=evidence,
                    description=data.get("description"),
                    false_positive="No",
                    jira_ticket="NA",
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate="No",
                    scanner="Zap",
                    organization=request.user.organization,
                )
                dump_data.save()
            except Exception:
                continue

        # Update summary counts case-insensitively
        zap_all_vul = WebScanResultsDb.objects.filter(
            scan_id=un_scanid,
            false_positive="No",
            scanner="Zap",
            organization=request.user.organization,
        )
        duplicate_count = WebScanResultsDb.objects.filter(
            scan_id=un_scanid,
            vuln_duplicate="Yes",
            organization=request.user.organization,
        )
        total_critical = zap_all_vul.filter(severity__iexact="Critical").count()
        total_high = zap_all_vul.filter(severity__iexact="High").count()
        total_medium = zap_all_vul.filter(severity__iexact="Medium").count()
        total_low = zap_all_vul.filter(severity__iexact="Low").count()
        total_info = zap_all_vul.filter(severity__istartswith="Info").count()
        total_duplicate = duplicate_count.filter(vuln_duplicate="Yes").count()
        total_vul = total_high + total_medium + total_low + total_info
        WebScansDb.objects.filter(
            scan_id=un_scanid, organization=self.request.user.organization
        ).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_duplicate,
            updated_time=timezone.now(),
        )

    def exclude_url(self):
        """
        Exclude URL from scan. Data are fetching from Archery database.
        :return:
        """
        excluded_regexes = []
        try:
            all_excluded = excluded_db.objects.filter(
                Q(exclude_url__icontains=self.target_url)
            )
            for data in all_excluded:
                val = (data.exclude_url or "").strip()
                if not val:
                    continue
                excluded_regexes.append(val)
        except Exception as e:
            print(e)

        # Only call the API when we actually have a regex; ZAP returns
        # MISSING_PARAMETER (regex) if we pass an empty value.
        for rx in excluded_regexes:
            try:
                self.zap.spider.exclude_from_scan(regex=rx)
            except Exception:
                # Best-effort; continue with the rest
                pass

        return ",".join(excluded_regexes)

    def cookies(self):
        """
        Cookies value extracting from Archery database and replacing
         into ZAP scanner.
        :return:
        """
        all_cookies = ""
        try:
            all_cookie = cookie_db.objects.filter(Q(url__icontains=self.target_url))
            for da in all_cookie:
                all_cookies = da.cookie

        except Exception as e:
            print(e)
        print("All cookies", all_cookies)
        print("Target URL---", self.target_url)

        try:
            self.zap.replacer.add_rule(
                apikey=zap_api_key,
                description=self.target_url,
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                replacement=all_cookies,
                matchstring="Cookie",
                initiators="",
            )
        except Exception as e:
            print(e)

    def zap_spider(self):
        """
        Scan trigger in ZAP Scanner and return Scan ID
        :return:
        """
        spider_id = ""

        try:
            print("targets:-----", self.target_url)
            try:
                spider_id = self.zap.spider.scan(self.target_url)
            except Exception as e:
                print("Spider Error")
            time.sleep(5)

            save_all = zap_spider_db(
                spider_url=self.target_url, spider_scanid=spider_id
            )
            save_all.save()
        except Exception as e:
            print(e)

        return spider_id

    def zap_spider_thread(self, thread_value):
        """
        The function use for the increasing Spider thread in ZAP scanner.
        :return:
        """
        thread = ""
        try:
            thread = self.zap.spider.set_option_thread_count(
                apikey=zap_api_key, integer=thread_value
            )

        except Exception as e:
            print("Spider Thread error")

        return thread

    def spider_status(self, spider_id, max_secs=3600):
        """
        The function return the spider status.
        :param spider_id:
        :return:
        """

        try:
            start_ts = time.time()
            while int(self.zap.spider.status(spider_id)) < 100:
                if (time.time() - start_ts) > max_secs:
                    try:
                        # Best-effort stop if supported
                        getattr(self.zap.spider, 'stop', lambda *a, **k: None)(spider_id)
                    except Exception:
                        pass
                    break
                global spider_status
                spider_status = self.zap.spider.status(spider_id)

                time.sleep(5)
        except Exception as e:
            print(e)

        spider_status = "100"
        return spider_status

    def spider_result(self, spider_id):
        """
        The function return spider result.
        :param spider_id:
        :return:
        """
        data_out = ""
        try:
            spider_res_out = self.zap.spider.results(spider_id)
            data_out = "\n".join(map(str, spider_res_out))
        except Exception as e:
            print(e)

        return data_out

    def ajax_spider(self, max_wait=300):
        """
        Triggers AJAX Spider for SPA discovery and waits for completion or timeout.
        """
        try:
            # Start AJAX spider against target
            try:
                self.zap.ajaxSpider.scan(self.target_url)
            except Exception:
                # Older servers may require a direct URL param
                try:
                    self.zap.ajaxSpider.scan(url=self.target_url)
                except Exception:
                    return False

            waited = 0
            status = self.zap.ajaxSpider.status()
            while str(status).lower() in ("running", "initialised") and waited < max_wait:
                time.sleep(5)
                waited += 5
                try:
                    status = self.zap.ajaxSpider.status()
                except Exception:
                    break
            # Best-effort stop if still running
            try:
                self.zap.ajaxSpider.stop()
            except Exception:
                pass
            return True
        except Exception:
            return False

    def pscan_wait(self, timeout=300):
        """Waits until ZAP's passive scanner has processed all records or timeout."""
        try:
            waited = 0
            while True:
                try:
                    remaining = int(self.zap.pscan.records_to_scan())
                except Exception:
                    break
                if remaining <= 0 or waited >= timeout:
                    break
                time.sleep(5)
                waited += 5
            return True
        except Exception:
            return False

    # OpenAPI/GraphQL import helpers removed per request

    def forced_browse(self):
        """Run directory brute-force if the add-on exists. Non-fatal if missing."""
        try:
            try:
                self.zap.bruteforce.scan(self.target_url)
            except Exception:
                # Some versions may use explicit 'url' arg
                try:
                    self.zap.bruteforce.scan(url=self.target_url)
                except Exception:
                    return False

            # Poll briefly and then stop (to avoid long runs by default)
            tries = 0
            while tries < 20:
                time.sleep(2)
                tries += 1
            try:
                # No stop method in all versions; ignore if not available
                getattr(self.zap.bruteforce, 'stop', lambda *a, **k: None)()
            except Exception:
                pass
            return True
        except Exception:
            return False

    def zap_scan(self):
        """
        The function Trigger scan in ZAP scanner
        :return:
        """
        scan_id = ""

        try:
            # Ensure the target is known to ZAP before starting an active scan.
            # This avoids URL_NOT_FOUND errors when Sites tree is empty and
            # the caller skipped spidering.
            try:
                # accessUrl warms the sites tree without aggressive crawling
                self.zap.core.access_url(self.target_url, followredirects=True)
            except Exception:
                # Older client versions use camelCase
                try:
                    self.zap.core.accessUrl(self.target_url, followRedirects=True)
                except Exception:
                    pass
            # Small delay to give ZAP time to register the site
            time.sleep(2)
            scan_id = self.zap.ascan.scan(self.target_url)
        except Exception as e:
            print("ZAP SCAN ERROR")

        return scan_id

    def zap_scan_status(self, scan_id, un_scanid, max_secs=3600, progress_cb=None):
        """
        The function return the ZAP Scan Status.
        :param scan_id:
        :return:
        """

        last_status = 0
        error_msg = None
        start_ts = time.time()
        try:
            # Poll until ZAP reports 100
            while True:
                # Bail out early if user requested stop in UI
                try:
                    from webscanners.models import WebScansDb as _WS
                    row = _WS.objects.filter(scan_id=un_scanid).only('failure_reason').first()
                    if row and getattr(row, 'failure_reason', '') == 'Stopped by user':
                        try:
                            try:
                                self.zap.ascan.stop(scan_id)
                            except Exception:
                                self.zap.ascan.pause(scan_id)
                        except Exception:
                            pass
                        error_msg = "Stopped by user"
                        break
                except Exception:
                    pass
                try:
                    status_raw = self.zap.ascan.status(scan_id)
                except Exception as _e_stat:
                    error_msg = f"ZAP status polling error: {str(_e_stat)}"
                    break
                status_str = str(status_raw).strip().lower()
                if status_str in ("", "does_not_exist", "no_scan", "unknown"):
                    error_msg = "ZAP active scan id does not exist (it may have been cleared or ZAP was restarted)"
                    break
                try:
                    status_val = int(float(status_raw))
                except Exception:
                    # Unexpected non-numeric; treat as 0 and continue a bit
                    status_val = last_status
                if status_val >= 100:
                    break
                # Enforce maximum runtime
                if (time.time() - start_ts) > max_secs:
                    try:
                        # Try to stop the active scan gracefully
                        self.zap.ascan.stop(scan_id)
                    except Exception:
                        try:
                            self.zap.ascan.pause(scan_id)
                        except Exception:
                            pass
                    error_msg = "ZAP timed out after 1 hour"
                    break
                scan_status = status_val
                last_status = status_val if status_val is not None else last_status
                print("ZAP Scan Status:", status_val)
                try:
                    if callable(progress_cb):
                        progress_cb(int(status_val))
                except Exception:
                    pass
                # Pull alerts incrementally and persist
                try:
                    alerts = self.zap.core.alerts(baseurl=self.target_url)
                except Exception:
                    try:
                        alerts = self.zap.core.alerts()
                    except Exception:
                        alerts = []
                if alerts:
                    # Keep only same host
                    host = urlparse(self.target_url).netloc.lstrip('www.')
                    alerts = [a for a in alerts if urlparse(str(a.get('url') or '')).netloc.lstrip('www.') == host]
                    self._persist_alerts(alerts, un_scanid, self.project_id)

                time.sleep(10)
                WebScansDb.objects.filter(scan_id=un_scanid).update(
                    scan_status=status_val,
                    updated_time=timezone.now(),
                )
        except Exception as e:
            error_msg = f"ZAP status polling error: {e}"
            print(error_msg)

        # Finalize status — fetch once more to avoid getting stuck below 100
        try:
            final_str = self.zap.ascan.status(scan_id)
            fstr = str(final_str).strip().lower()
            if fstr in ("", "does_not_exist", "no_scan", "unknown"):
                final_num = last_status
            else:
                final_num = int(float(str(final_str)))
        except Exception:
            final_num = last_status

        if error_msg is None and final_num < 100:
            # ZAP logs may say completed while last polled status was <100; mark as complete
            final_num = 100

        updates = {"scan_status": final_num, "updated_time": timezone.now()}
        if error_msg:
            updates["failure_reason"] = error_msg
        WebScansDb.objects.filter(scan_id=un_scanid).update(**updates)
        # Clear the saved ascan id once the scan is finished
        try:
            WebScansDb.objects.filter(scan_id=un_scanid).update(zap_ascan_id=None)
        except Exception:
            pass
        return final_num

    def zap_scan_result(self, target_url):
        """
        The function return ZAP Scan Results.
        :return:
        """
        global all_vuln
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            try:
                all_vuln = self.zap.core.xmlreport()
                print(target_url)

            except Exception as e:
                print("zap scan result error")
        else:
            # Fetch alerts for base URL; if empty (due to encoding/path/zero-width issues),
            # fallback to all alerts and filter while saving.
            try:
                all_vuln = self.zap.core.alerts(baseurl=self.target_url)
            except Exception:
                all_vuln = []
            if not all_vuln:
                try:
                    all_vuln = self.zap.core.alerts()
                except Exception:
                    all_vuln = []

        return all_vuln

    def zap_result_save(self, all_vuln, project_id, un_scanid, target_url, request, scan_phase=None):
        """
        The function save all data in Archery Database
        :param all_vuln:
        :param project_id:
        :param un_scanid:
        :return:
        """
        date_time = timezone.now()
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            root_xml = ET.fromstring(all_vuln)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)
            try:
                zap_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=un_scanid,
                    root=root_xml_en,
                    request=request,
                )
                # Tag imported findings with the provided phase (passive/active snapshot)
                if scan_phase:
                    try:
                        WebScanResultsDb.objects.filter(
                            scan_id=un_scanid,
                            scanner="Zap",
                            scan_phase__isnull=True,
                        ).update(scan_phase=scan_phase)
                    except Exception:
                        pass
                self.zap.core.delete_all_alerts()
            except Exception as e:
                print(e)
        else:
            global name, attack, wascid, description, reference, reference, sourceid, solution, param, method, url, messageId, alert, pluginId, other, evidence, cweid, risk, vul_col, false_positive
            for data in all_vuln:
                for key, value in data.items():
                    if key == "name":
                        name = value

                    if key == "attack":
                        attack = value

                    if key == "wascid":
                        wascid = value

                    if key == "description":
                        description = value

                    if key == "reference":
                        reference = value

                    if key == "sourceid":
                        sourceid = value

                    if key == "solution":
                        solution = value

                    if key == "param":
                        param = value

                    if key == "method":
                        method = value

                    if key == "url":
                        url = value

                    if key == "pluginId":
                        pluginId = value

                    if key == "other":
                        other = value

                    if key == "alert":
                        alert = value

                    if key == "attack":
                        attack = value

                    if key == "messageId":
                        messageId = value

                    if key == "evidence":
                        evidence = value

                    if key == "cweid":
                        cweid = value

                    if key == "wascid":
                        wascid = value

                    if key == "confidence":
                        try:
                            confidence = value
                        except Exception:
                            confidence = ""

                    if key == "risk":
                        risk = value

                    if key == "messageId":
                        messageId = value
                # Skip unrelated alerts when we fetched without baseurl filter
                try:
                    data_url = data.get("url") if isinstance(data, dict) else None
                    du = self._normalize_url(data_url)
                    tu = self.target_url
                    dp = urlparse(du)
                    tp = urlparse(tu)
                    dhost = dp.netloc.lstrip('www.')
                    thost = tp.netloc.lstrip('www.')
                    if dhost and thost and dhost != thost:
                        continue
                except Exception:
                    pass

                if risk == "Critical":
                    vul_col = "critical"
                    risk = "Critical"
                elif risk == "High":
                    vul_col = "danger"
                    risk = "High"
                elif risk == "Medium":
                    vul_col = "warning"
                    risk = "Medium"
                elif risk == "info":
                    vul_col = "info"
                    risk = "Informational"
                else:
                    vul_col = "info"
                    risk = "Low"

                # Include phase in hash so the same alert can be stored per phase (Passive/Active/etc.)
                phase_tag = scan_phase or ""
                dup_data = name + risk + target_url + phase_tag
                duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

                # Skip creating a second row for the same scan/hash combination.
                # When `_persist_alerts` is enabled we may have already stored
                # this finding during progress polling; in that case just enrich
                # the existing row instead of inserting a duplicate record.
                existing = WebScanResultsDb.objects.filter(
                    dup_hash=duplicate_hash,
                    scan_id=un_scanid,
                    organization=request.user.organization,
                ).first()
                if existing:
                    updates = {}
                    if scan_phase and scan_phase != getattr(existing, "scan_phase", None):
                        updates["scan_phase"] = scan_phase
                    try:
                        cur_instance = str(getattr(existing, "instance", "") or "")
                        if evidence and str(evidence) not in cur_instance:
                            updates["instance"] = evidence
                    except Exception:
                        pass
                    if updates:
                        WebScanResultsDb.objects.filter(pk=existing.pk).update(**updates)
                    continue

                # Build a richer description with CWE/WASC and confidence if present
                desc_extra = []
                if cweid not in ("", None):
                    desc_extra.append(f"CWE-{cweid} https://cwe.mitre.org/data/definitions/{cweid}.html")
                if wascid not in ("", None):
                    desc_extra.append(f"WASC-{wascid}")
                if confidence not in ("", None):
                    desc_extra.append(f"Confidence: {confidence}")
                description_full = description
                if desc_extra:
                    description_full = (description or "") + "\n" + " | ".join(desc_extra)
                # Use instance to hold evidence if present
                instance_val = evidence or ""

                match_dup = (
                    WebScanResultsDb.objects.filter(
                        dup_hash=duplicate_hash, organization=request.user.organization
                    )
                    .values("dup_hash")
                    .distinct()
                )
                lenth_match = len(match_dup)

                vuln_id = uuid.uuid4()
                if lenth_match == 0:
                    duplicate_vuln = "No"
                    dump_data = WebScanResultsDb(
                        vuln_id=vuln_id,
                        severity_color=vul_col,
                        scan_id=un_scanid,
                        project_id=project_id,
                        severity=risk,
                        reference=reference,
                        url=target_url,
                        title=name,
                        solution=solution,
                        instance=instance_val,
                        description=description_full,
                        false_positive="No",
                        jira_ticket="NA",
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        scanner="Zap",
                        scan_phase=scan_phase,
                        organization=request.user.organization,
                        created_by=getattr(request, 'user', None),
                        updated_by=getattr(request, 'user', None),
                    )
                    dump_data.save()
                else:
                    duplicate_vuln = "Yes"

                    dump_data = WebScanResultsDb(
                        vuln_id=vuln_id,
                        severity_color=vul_col,
                        scan_id=un_scanid,
                        project_id=project_id,
                        severity=risk,
                        reference=reference,
                        url=target_url,
                        title=name,
                        solution=solution,
                        instance="na",
                        description=description,
                        false_positive="Duplicate",
                        jira_ticket="NA",
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        scanner="Zap",
                        scan_phase=scan_phase,
                        organization=request.user.organization,
                        created_by=getattr(request, 'user', None),
                        updated_by=getattr(request, 'user', None),
                    )
                    dump_data.save()

                false_p = WebScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash,
                    organization=request.user.organization,
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                vul_dat = WebScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scanner="Zap",
                    organization=request.user.organization,
                )
                full_data = []
                for data in vul_dat:
                    key = "Evidence"
                    value = data.instance
                    dd = re.sub(r"<[^>]*>", " ", value)
                    instance = key + ": " + dd
                    full_data.append(instance)
                removed_list_data = ",".join(full_data)
                WebScanResultsDb.objects.filter(
                    vuln_id=vuln_id, organization=request.user.organization
                ).update(instance=full_data)

            zap_all_vul = WebScanResultsDb.objects.filter(
                scan_id=un_scanid,
                false_positive="No",
                scanner="Zap",
                organization=request.user.organization,
            )

            duplicate_count = WebScanResultsDb.objects.filter(
                scan_id=un_scanid,
                vuln_duplicate="Yes",
                organization=request.user.organization,
            )

            total_critical = len(zap_all_vul.filter(severity="Critical"))
            total_high = len(zap_all_vul.filter(severity="High"))
            total_medium = len(zap_all_vul.filter(severity="Medium"))
            total_low = len(zap_all_vul.filter(severity="Low"))
            total_info = len(zap_all_vul.filter(severity="Informational"))
            total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))
            total_vul = total_high + total_medium + total_low + total_info

            WebScansDb.objects.filter(
                scan_id=un_scanid, organization=request.user.organization
            ).update(
                total_vul=total_vul,
                date_time=date_time,
                critical_vul=total_critical,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                info_vul=total_info,
                total_dup=total_duplicate,
                scan_url=target_url,
                organization=request.user.organization,
            )
            if total_vul == total_duplicate:
                WebScansDb.objects.filter(scan_id=un_scanid).update(
                    total_vul=total_vul,
                    date_time=date_time,
                    project_id=project_id,
                    critical_vul=total_critical,
                    high_vul=total_high,
                    medium_vul=total_medium,
                    low_vul=total_low,
                    total_dup=total_duplicate,
                    organization=request.user.organization,
                )

    def zap_shutdown(self):
        """

        :return:
        """
        self.zap.core.shutdown(apikey=zap_api_key)
