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

import json
import os
import threading
import time
import uuid
from datetime import datetime
from django.utils import timezone
from urllib.parse import urlparse

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.signals import notify
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from selenium import webdriver
import pytz

from archerysettings.models import EmailDb, SettingsDb, ZapSettingsDb
from user_management.models import Organization
from projects.models import ProjectDb
from scanners.audit import log_action
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from user_management import permissions
from webscanners.models import WebScansDb, WebScanResultsDb, cookie_db, excluded_db
from webscanners.zapscanner.serializers import (ZapScansSerializer,
                                                ZapSettingsSerializer)

scans_status = None
to_mail = ""
scan_id = None
scan_name = None

LOCAL_TZ = pytz.timezone(getattr(settings, "DEF_TIME_ZONE", "Asia/Kuala_Lumpur"))

# Per-scan ZAP logging helpers
def _zap_scan_log_path(scan_id):
    try:
        base = os.path.join(os.getcwd(), "logs", "zap")
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, f"{scan_id}.log")
    except Exception:
        return os.path.join(os.getcwd(), f"{scan_id}.log")


def _zap_log(scan_id, msg):
    try:
        now_utc = timezone.now()
        local_now = now_utc.astimezone(LOCAL_TZ)
        offset = local_now.strftime("%z")  # e.g., +0800
        offset_fmt = f"UTC{offset[:3]}:{offset[3:]}"
        ts = local_now.strftime("%Y-%m-%d %H:%M:%S")
        path = _zap_scan_log_path(scan_id)
        with open(path, "a", encoding="utf-8", errors="ignore") as fh:
            fh.write(f"[{ts} {offset_fmt}] {msg}\n")
    except Exception:
        pass


def _save_spider_urls(scan_id, project_id, urls, request, phase_label="Spider"):
    """
    Persist spider-discovered URLs so the UI can show coverage under Phase=Spider.
    Stored with severity='Informational' to avoid inflating vuln counts.
    """
    try:
        urls = [u.strip() for u in (urls or []) if u and str(u).strip()]
        if not urls:
            return
        existing = set(
            WebScanResultsDb.objects.filter(
                scan_id=scan_id, scan_phase=phase_label, organization=request.user.organization
            ).values_list("url", flat=True)
        )
        for u in urls:
            if u in existing:
                continue
            dup_hash = hashlib.sha256(f"{phase_label.lower()}|{u}".encode("utf-8")).hexdigest()
            WebScanResultsDb.objects.update_or_create(
                scan_id=scan_id,
                organization=request.user.organization,
                url=u,
                scan_phase=phase_label,
                defaults=dict(
                    vuln_id=uuid.uuid4(),
                    project_id=project_id,
                    severity="Informational",
                    severity_color="info",
                    title=u,
                    description=f"Discovered during {phase_label} phase.",
                    solution="",
                    vuln_status="Open",
                    dup_hash=dup_hash,
                    vuln_duplicate="No",
                    scanner="Zap",
                    created_by=getattr(request, "user", None),
                    updated_by=getattr(request, "user", None),
                ),
            )
    except Exception:
        pass


_WEB_URL_ERROR = "Web scans only support URLs (e.g., https://example.com)."


def _parse_target_urls(raw_value):
    """
    Normalize and validate incoming targets so ZAP behaves like the desktop UI:
    - Strip URL fragments (#...) which ZAP ignores anyway
    - Ensure a trailing slash for bare origins
    - Deduplicate by normalized value
    """
    raw = str(raw_value or "").replace("\n", ",")
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    targets = []
    invalid = []
    seen = set()
    for tok in tokens:
        try:
            parsed = urlparse(tok)
            if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                path = parsed.path or "/"
                norm = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
                if parsed.query:
                    norm = f"{norm}?{parsed.query}"
                if norm not in seen:
                    targets.append(norm)
                    seen.add(norm)
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


def _apply_ajax_options(zap_client, opts):
    """
    Apply AJAX spider options using zapv2 client.
    """
    try:
        if opts.get("max_depth") is not None:
            zap_client.ajaxSpider.set_option_max_crawl_depth(opts["max_depth"])
        if opts.get("max_states") is not None:
            zap_client.ajaxSpider.set_option_max_crawl_states(opts["max_states"])
        if opts.get("max_duration") is not None:
            zap_client.ajaxSpider.set_option_max_duration(opts["max_duration"])
        if opts.get("num_browsers") is not None:
            zap_client.ajaxSpider.set_option_number_of_browsers(opts["num_browsers"])
        if opts.get("logout_avoid") is not None:
            zap_client.ajaxSpider.set_option_logout_avoidance(opts["logout_avoid"])
        if opts.get("click_once") is not None:
            zap_client.ajaxSpider.set_option_click_elems_once(opts["click_once"])
        if opts.get("click_default") is not None:
            zap_client.ajaxSpider.set_option_click_default_elems(opts["click_default"])
        if opts.get("random_inputs") is not None:
            zap_client.ajaxSpider.set_option_random_inputs(opts["random_inputs"])
        if opts.get("event_wait") is not None:
            zap_client.ajaxSpider.set_option_event_wait(opts["event_wait"])
        if opts.get("reload_wait") is not None:
            zap_client.ajaxSpider.set_option_reload_wait(opts["reload_wait"])
        # Allowed resources
        for rx in opts.get("allowed_resources") or []:
            try:
                zap_client.ajaxSpider.add_allowed_resource(regex=rx, enabled=True)
            except Exception:
                pass
        # Excluded elements: use description=text fallback
        for desc in opts.get("excluded_elems") or []:
            try:
                zap_client.ajaxSpider.add_excluded_element(contextname="", description=desc, element=desc)
            except Exception:
                try:
                    zap_client.ajaxSpider.add_excluded_element(contextName="", description=desc, element=desc)
                except Exception:
                    pass
    except Exception:
        pass


def _apply_pscan_options(zap_client, opts):
    """
    Apply passive scan tuning.
    """
    try:
        if opts.get("scope_only") is not None:
            try:
                zap_client.pscan.set_scan_only_in_scope(opts["scope_only"])
            except Exception:
                try:
                    zap_client.pscan.setScanOnlyInScope(onlyInScope=opts["scope_only"])
                except Exception:
                    pass
        if opts.get("max_alerts") is not None:
            try:
                zap_client.pscan.set_max_alerts_per_rule(opts["max_alerts"])
            except Exception:
                try:
                    zap_client.pscan.setMaxAlertsPerRule(maxalerts=opts["max_alerts"])
                except Exception:
                    pass
        if opts.get("enable_ids"):
            ids_csv = ",".join(opts["enable_ids"])
            try:
                zap_client.pscan.enable_scanners(ids=ids_csv)
            except Exception:
                try:
                    zap_client.pscan.enableScanners(ids=ids_csv)
                except Exception:
                    pass
        if opts.get("disable_ids"):
            ids_csv = ",".join(opts["disable_ids"])
            try:
                zap_client.pscan.disable_scanners(ids=ids_csv)
            except Exception:
                try:
                    zap_client.pscan.disableScanners(ids=ids_csv)
                except Exception:
                    pass
        if opts.get("clear_queue"):
            try:
                zap_client.pscan.clear_queue()
            except Exception:
                try:
                    zap_client.pscan.clearQueue()
                except Exception:
                    pass
    except Exception:
        pass


def _apply_active_options(zap_client, opts):
    """
    Apply active scan tuning.
    """
    try:
        if opts.get("threads_per_host") is not None:
            try:
                zap_client.ascan.set_option_thread_per_host(opts["threads_per_host"])
            except Exception:
                try:
                    zap_client.ascan.setOptionThreadPerHost(opts["threads_per_host"])
                except Exception:
                    pass
        if opts.get("hosts_per_scan") is not None:
            try:
                zap_client.ascan.set_option_host_per_scan(opts["hosts_per_scan"])
            except Exception:
                try:
                    zap_client.ascan.setOptionHostPerScan(opts["hosts_per_scan"])
                except Exception:
                    pass
        if opts.get("delay_ms") is not None:
            try:
                zap_client.ascan.set_option_delay_in_ms(opts["delay_ms"])
            except Exception:
                try:
                    zap_client.ascan.setOptionDelayInMs(opts["delay_ms"])
                except Exception:
                    pass
        if opts.get("max_scan_mins") is not None:
            try:
                zap_client.ascan.set_option_max_scan_duration_in_mins(opts["max_scan_mins"])
            except Exception:
                try:
                    zap_client.ascan.setOptionMaxScanDurationInMins(opts["max_scan_mins"])
                except Exception:
                    pass
        if opts.get("max_rule_mins") is not None:
            try:
                zap_client.ascan.set_option_max_rule_duration_in_mins(opts["max_rule_mins"])
            except Exception:
                try:
                    zap_client.ascan.setOptionMaxRuleDurationInMins(opts["max_rule_mins"])
                except Exception:
                    pass
        if opts.get("enable_ids"):
            ids_csv = ",".join(opts["enable_ids"])
            try:
                zap_client.ascan.enable_scanners(ids=ids_csv)
            except Exception:
                try:
                    zap_client.ascan.enableScanners(ids=ids_csv)
                except Exception:
                    pass
        if opts.get("disable_ids"):
            ids_csv = ",".join(opts["disable_ids"])
            try:
                zap_client.ascan.disable_scanners(ids=ids_csv)
            except Exception:
                try:
                    zap_client.ascan.disableScanners(ids=ids_csv)
                except Exception:
                    pass
    except Exception:
        pass


def _apply_bruteforce_options(zap_client, opts):
    """
    Apply forced browse/bruteforce options.
    """
    try:
        if opts.get("threads") is not None:
            try:
                zap_client.bruteforce.set_option_number_of_threads(opts["threads"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionNumberOfThreads(opts["threads"])
                except Exception:
                    pass
        if opts.get("recursive") is not None:
            try:
                zap_client.bruteforce.set_option_recursive(opts["recursive"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionRecursive(opts["recursive"])
                except Exception:
                    pass
        if opts.get("in_scope_only") is not None:
            try:
                zap_client.bruteforce.set_option_scan_only_in_scope(opts["in_scope_only"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionScanOnlyInScope(opts["in_scope_only"])
                except Exception:
                    pass
        if opts.get("max_dirs") is not None:
            try:
                zap_client.bruteforce.set_option_max_dirs(opts["max_dirs"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionMaxDirs(opts["max_dirs"])
                except Exception:
                    pass
        if opts.get("max_files") is not None:
            try:
                zap_client.bruteforce.set_option_max_files(opts["max_files"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionMaxFiles(opts["max_files"])
                except Exception:
                    pass
        if opts.get("extensions"):
            try:
                zap_client.bruteforce.set_option_file_extensions(opts["extensions"])
            except Exception:
                try:
                    zap_client.bruteforce.setOptionFileExtensions(opts["extensions"])
                except Exception:
                    pass
        if opts.get("wordlist"):
            # Some versions allow directories/wordlists to be added; best-effort
            try:
                zap_client.bruteforce.add_directory(opts["wordlist"])
            except Exception:
                try:
                    zap_client.bruteforce.addDirectory(opts["wordlist"])
                except Exception:
                    pass
    except Exception:
        pass


def _resolve_wordlist_path(value):
    """
    Map friendly wordlist keys to likely filesystem locations and fall back to user input.

    Recognized keys (case-insensitive):
      - dirbuster-small
      - dirbuster-medium
      - dirbuster-large
      - seclists-common
      - seclists-big
    """
    key = str(value or "").strip().lower()
    if not key:
        return value
    mappings = {
        "dirbuster-small": [
            "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
            "/zap/wrk/dirbuster/directory-list-2.3-small.txt",
            os.path.join(os.getcwd(), "wordlists", "dirbuster", "directory-list-2.3-small.txt"),
        ],
        "dirbuster-medium": [
            "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
            "/zap/wrk/dirbuster/directory-list-2.3-medium.txt",
            os.path.join(os.getcwd(), "wordlists", "dirbuster", "directory-list-2.3-medium.txt"),
        ],
        "dirbuster-large": [
            "/usr/share/dirbuster/wordlists/directory-list-2.3-big.txt",
            "/zap/wrk/dirbuster/directory-list-2.3-big.txt",
            os.path.join(os.getcwd(), "wordlists", "dirbuster", "directory-list-2.3-big.txt"),
        ],
        "seclists-common": [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            os.path.join(os.getcwd(), "wordlists", "seclists", "common.txt"),
        ],
        "seclists-big": [
            "/usr/share/seclists/Discovery/Web-Content/big.txt",
            os.path.join(os.getcwd(), "wordlists", "seclists", "big.txt"),
        ],
    }
    candidates = mappings.get(key)
    if not candidates:
        return value
    for cand in candidates:
        try:
            if cand and os.path.exists(cand):
                return cand
        except Exception:
            continue
    return candidates[0]


def email_notify(user, subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")


def email_sch_notify(subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        print(e)


def _build_zap_scan_type(do_spider, do_ajax_spider, do_pscan_wait, do_active, do_forced_browse):
    """Return a concise human label for the ZAP scan configuration."""
    parts = []
    # Order for readability
    if do_active:
        parts.append("Active")
    passive_needed = False
    if do_pscan_wait:
        passive_needed = True
    elif not do_active and (do_spider or do_ajax_spider):
        # When no active scan runs we still consider it a passive scan
        passive_needed = True
    if passive_needed:
        parts.append("Passive")
    if do_spider:
        parts.append("Spider")
    if do_ajax_spider:
        parts.append("AJAX Spider")
    if do_forced_browse:
        parts.append("Forced Browse")
    if not parts:
        parts = ["Default"]
    return "ZAP " + " + ".join(parts)


def launch_zap_scan(
    target_url,
    project_id,
    rescan_id,
    rescan,
    scan_id,
    user,
    request,
    do_spider=True,
    do_ajax_spider=False,
    do_pscan_wait=False,
    do_active=True,
    do_forced_browse=False,
    spider_options=None,
    ajax_options=None,
    pscan_options=None,
    active_options=None,
    fb_options=None,
):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    zap_enabled = False
    random_port = "8091"

    # Use org-level ZAP settings if enabled; otherwise start a local instance
    zap_settings = ZapSettingsDb.objects.filter(organization=request.user.organization).first()
    if zap_settings and getattr(zap_settings, "enabled", False):
        zap_enabled = True
        # Respect configured port
        random_port = str(getattr(zap_settings, "zap_port", "8090") or "8090")
        # Quick connectivity probe; if it fails, fall back to local instance
        try:
            _client = zap_plugin.zap_connect(random_port)
            # cheap API call; raises if unreachable
            _ = _client.core.version
        except Exception:
            zap_enabled = False

    # Ensure a DB row exists before attempting to start/connect to ZAP so the UI reflects activity
    date_time = timezone.now()
    scan_type_label = _build_zap_scan_type(
        do_spider, do_ajax_spider, do_pscan_wait, do_active, do_forced_browse
    )
    try:
        WebScansDb.objects.update_or_create(
            scan_id=scan_id,
            organization=request.user.organization,
            defaults=dict(
                project_id=project_id,
                scan_url=target_url,
                date_time=date_time,
                rescan_id=rescan_id,
                rescan=rescan,
                scan_status="0",
                scanner="Zap",
                scan_type=scan_type_label,
                failure_reason=None,
                created_by=request.user,
                updated_by=request.user,
            ),
        )
        notify.send(user, recipient=user, verb="Web scan target %s added" % target_url)
        _zap_log(scan_id, f"Scan created for {target_url} | spider={do_spider} ajax={do_ajax_spider} passive_wait={do_pscan_wait} active={do_active} forced_browse={do_forced_browse}")
    except Exception as e:
        print(e)

    if zap_enabled is False:
        print("started local instence")
        try:
            random_port = zap_plugin.zap_local()
        except Exception as e:
            # Surface the issue in the row so the list page shows a failure reason
            try:
                WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                    failure_reason="Local ZAP not found: %s" % str(e)[:200]
                )
            except Exception:
                pass
            return

        # Try to establish a connection to the local instance (bounded retries)
        for _ in range(30):
            try:
                zc = zap_plugin.zap_connect(random_port)
                # light call that triggers API availability
                _ = zc.core.version
                _zap_log(scan_id, f"Connected to local ZAP on port {random_port}")
                break
            except Exception:
                print("ZAP local not ready, retrying...")
                time.sleep(2)

    _zap_log(scan_id, "Configuring ZAP threading/options")
    # Apply spider tuning (fall back to previous defaults if not provided)
    _spider_opts = spider_options or {}
    spider_threads = _spider_opts.get("thread_count", 20)
    spider_depth = _spider_opts.get("max_depth", 5)
    zap_plugin.zap_spider_thread(count=spider_threads, random_port=random_port)
    zap_plugin.zap_spider_setOptionMaxDepth(count=spider_depth, random_port=random_port)
    if _spider_opts.get("max_children") is not None:
        zap_plugin.zap_spider_setOptionMaxChildren(count=_spider_opts.get("max_children"), random_port=random_port)
    if _spider_opts.get("parse_robots") is not None:
        zap_plugin.zap_spider_setOptionParseRobotsTxt(enabled=_spider_opts.get("parse_robots"), random_port=random_port)
    if _spider_opts.get("parse_sitemap") is not None:
        zap_plugin.zap_spider_setOptionParseSitemapXml(enabled=_spider_opts.get("parse_sitemap"), random_port=random_port)
    if _spider_opts.get("process_forms") is not None:
        zap_plugin.zap_spider_setOptionProcessForm(enabled=_spider_opts.get("process_forms"), random_port=random_port)
    if _spider_opts.get("submit_forms") is not None:
        zap_plugin.zap_spider_setOptionPostForm(enabled=_spider_opts.get("submit_forms"), random_port=random_port)
    if _spider_opts.get("send_referer") is not None:
        zap_plugin.zap_spider_setOptionSendRefererHeader(enabled=_spider_opts.get("send_referer"), random_port=random_port)
    if _spider_opts.get("accept_cookies") is not None:
        zap_plugin.zap_spider_setOptionAcceptCookies(enabled=_spider_opts.get("accept_cookies"), random_port=random_port)
    if _spider_opts.get("handle_parameters") is not None:
        zap_plugin.zap_spider_setOptionHandleParameters(mode=_spider_opts.get("handle_parameters"), random_port=random_port)
    if _spider_opts.get("skip_url_token"):
        zap_plugin.zap_spider_setOptionSkipURLString(skip_token=_spider_opts.get("skip_url_token"), random_port=random_port)
    include_regexes = _spider_opts.get("include_regexes") or []
    for rx in include_regexes:
        zap_plugin.zap_spider_addInScopeRegex(regex=rx, random_port=random_port)

    zap_plugin.zap_scan_thread(count=30, random_port=random_port)
    zap_plugin.zap_scan_setOptionHostPerScan(count=3, random_port=random_port)
    # Active tuning overrides if provided
    _active_opts = active_options or {}
    if _active_opts.get("threads_per_host") is not None:
        zap_plugin.zap_scan_thread(count=_active_opts.get("threads_per_host"), random_port=random_port)
    if _active_opts.get("hosts_per_scan") is not None:
        zap_plugin.zap_scan_setOptionHostPerScan(count=_active_opts.get("hosts_per_scan"), random_port=random_port)
    if _active_opts.get("delay_ms") is not None:
        zap_plugin.zap_scan_setOptionDelayInMs(delay_ms=_active_opts.get("delay_ms"), random_port=random_port)

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
        request=request,
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    # (Row already created above)

    notify.send(user, recipient=user, verb="Web scan started")
    _zap_log(scan_id, "ZAP scan started")

    # Track wall-clock start; cap runtime by user-provided max (active scan mins) or a generous default (3h)
    start_ts = time.time()
    try:
        user_cap_secs = None
        try:
            if active_options and active_options.get("max_scan_mins"):
                user_cap_secs = int(active_options.get("max_scan_mins")) * 60
        except Exception:
            user_cap_secs = None
        DEFAULT_CAP_SECS = 10800  # 3 hours
        cap_secs = user_cap_secs if user_cap_secs else DEFAULT_CAP_SECS
    except Exception:
        cap_secs = 3600

    def remaining_secs():
        try:
            return max(0, cap_secs - int(time.time() - start_ts))
        except Exception:
            return cap_secs

    # Discovery: classic spider
    if do_spider:
        _zap_log(scan_id, "Spider: starting")
        zap.zap_spider_thread(thread_value=spider_threads)
        spider_id = zap.zap_spider()
        zap.spider_status(spider_id=spider_id, max_secs=remaining_secs())
        try:
            sr = zap.spider_result(spider_id=spider_id) or ""
            urls = [u for u in sr.splitlines() if u.strip()]
            _zap_log(scan_id, f"Spider: discovered {len(urls)} URL(s)")
            for u in urls:
                _zap_log(scan_id, f"  - {u}")
            _save_spider_urls(scan_id, project_id, urls, request, phase_label="Spider")
        except Exception:
            pass
        notify.send(user, recipient=user, verb="Web spider phase completed")
        _zap_log(scan_id, "Spider: completed; waiting for passive scanner")
        # Give passive scanner a moment to process spider-discovered traffic
        try:
            before = None
            try:
                before = int(zap.zap.pscan.records_to_scan())
            except Exception:
                pass
            zap.pscan_wait(timeout=min(30, remaining_secs()))
            after = None
            try:
                after = int(zap.zap.pscan.records_to_scan())
            except Exception:
                pass
            if before is not None or after is not None:
                _zap_log(scan_id, f"Passive scanner backlog: {before} -> {after}")
        except Exception:
            pass
        # Snapshot passive alerts only if requested
        if do_pscan_wait:
            try:
                sv = zap.zap_scan_result(target_url=target_url)
                zap.zap_result_save(
                    all_vuln=sv,
                    project_id=project_id,
                    un_scanid=scan_id,
                    target_url=target_url,
                    request=request,
                    scan_phase="Spider",
                )
                try:
                    from webscanners.models import WebScanResultsDb as _W
                    qs = _W.objects.filter(scan_id=scan_id, organization=request.user.organization)
                    total = qs.count()
                    crit = qs.filter(severity__iexact='Critical').count()
                    high = qs.filter(severity__iexact='High').count()
                    med = qs.filter(severity__iexact='Medium').count()
                    low = qs.filter(severity__iexact='Low').count()
                    info = qs.filter(severity__istartswith='Info').count()
                    _zap_log(scan_id, "Spider snapshot: Alerts total=%s | Critical=%s, High=%s, Medium=%s, Low=%s, Info=%s" % (total, crit, high, med, low, info))
                    try:
                        for rowx in qs.only('severity','title','url')[:25]:
                            _zap_log(scan_id, "  - %s | %s | %s" % (getattr(rowx,'severity',''), getattr(rowx,'title',''), getattr(rowx,'url','')))
                    except Exception:
                        pass
                except Exception:
                    pass
            except Exception:
                pass
        else:
            _zap_log(scan_id, "Spider: passive snapshot skipped (passive wait disabled)")

    # Discovery: AJAX spider (SPAs)
    if do_ajax_spider and remaining_secs() > 0:
        try:
            _zap_log(scan_id, "AJAX spider: starting")
            try:
                _apply_ajax_options(zap.zap, ajax_options or {})
            except Exception:
                pass
            ok = zap.ajax_spider(max_wait=remaining_secs())
            if ok:
                try:
                    ajax_urls = []
                    try:
                        ajax_urls = zap.zap.ajaxSpider.results() or []
                    except Exception:
                        ajax_urls = []
                    if ajax_urls:
                        _zap_log(scan_id, f"AJAX spider: discovered {len(ajax_urls)} URL(s)")
                        _save_spider_urls(scan_id, project_id, ajax_urls, request, phase_label="AJAX")
                except Exception:
                    pass
                notify.send(user, recipient=user, verb="Web AJAX spider phase completed")
                _zap_log(scan_id, "AJAX spider: completed; waiting for passive scanner")
                # Allow passive scanner to catch up before taking a snapshot (only if requested)
                if do_pscan_wait:
                    try:
                        zap.pscan_wait(timeout=min(45, remaining_secs()))
                    except Exception:
                        pass
                    # Snapshot any passive alerts found after AJAX spider
                    try:
                        aj = zap.zap_scan_result(target_url=target_url)
                        zap.zap_result_save(
                            all_vuln=aj,
                            project_id=project_id,
                            un_scanid=scan_id,
                            target_url=target_url,
                            request=request,
                            scan_phase="AJAX",
                        )
                        try:
                            from webscanners.models import WebScanResultsDb as _W
                            qs = _W.objects.filter(scan_id=scan_id, organization=request.user.organization)
                            total = qs.count()
                            crit = qs.filter(severity__iexact='Critical').count()
                            high = qs.filter(severity__iexact='High').count()
                            med = qs.filter(severity__iexact='Medium').count()
                            low = qs.filter(severity__iexact='Low').count()
                            info = qs.filter(severity__istartswith='Info').count()
                            _zap_log(scan_id, "AJAX snapshot: Alerts total=%s | Critical=%s, High=%s, Medium=%s, Low=%s, Info=%s" % (total, crit, high, med, low, info))
                            try:
                                for rowx in qs.only('severity','title','url')[:25]:
                                    _zap_log(scan_id, "  - %s | %s | %s" % (getattr(rowx,'severity',''), getattr(rowx,'title',''), getattr(rowx,'url','')))
                            except Exception:
                                pass
                        except Exception:
                            pass
                    except Exception:
                        pass
                else:
                    _zap_log(scan_id, "AJAX spider: passive snapshot skipped (passive wait disabled)")
        except Exception:
            pass

    # Optional forced browse for more paths
    if do_forced_browse and remaining_secs() > 0:
        try:
            _zap_log(scan_id, "Forced browse: starting")
            try:
                _apply_bruteforce_options(zap.zap, fb_options or {})
            except Exception:
                pass
            zap.forced_browse()
            try:
                fb = []
                try:
                    fb = zap.zap.bruteforce.results() or []
                except Exception:
                    fb = []
                if fb:
                    _zap_log(scan_id, f"Forced browse: discovered {len(fb)} path(s)")
                    _save_spider_urls(scan_id, project_id, fb, request, phase_label="Forced Browse")
            except Exception:
                pass
            _zap_log(scan_id, "Forced browse: completed")
        except Exception:
            pass

    # Let passive scanner catch up if requested
    if do_pscan_wait and remaining_secs() > 0:
        try:
            try:
                _apply_pscan_options(zap.zap, pscan_options or {})
            except Exception:
                pass
            _zap_log(scan_id, "Passive scanner wait: starting")
            zap.pscan_wait(timeout=remaining_secs())
            _zap_log(scan_id, "Passive scanner wait: completed")
        except Exception:
            pass
        # Save passive results snapshot
        try:
            pv = zap.zap_scan_result(target_url=target_url)
            zap.zap_result_save(
                all_vuln=pv,
                project_id=project_id,
                un_scanid=scan_id,
                target_url=target_url,
                request=request,
                scan_phase="Passive",
            )
            try:
                from webscanners.models import WebScanResultsDb as _W
                qs = _W.objects.filter(scan_id=scan_id, organization=request.user.organization)
                total = qs.count()
                crit = qs.filter(severity__iexact='Critical').count()
                high = qs.filter(severity__iexact='High').count()
                med = qs.filter(severity__iexact='Medium').count()
                low = qs.filter(severity__iexact='Low').count()
                info = qs.filter(severity__istartswith='Info').count()
                _zap_log(scan_id, "Passive snapshot: Alerts total=%s | Critical=%s, High=%s, Medium=%s, Low=%s, Info=%s" % (total, crit, high, med, low, info))
                try:
                    for rowx in qs.only('severity','title','url')[:25]:
                        _zap_log(scan_id, "  - %s | %s | %s" % (getattr(rowx,'severity',''), getattr(rowx,'title',''), getattr(rowx,'url','')))
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

    # Active scan (optional)
    zap_scan_id = None
    if do_active and remaining_secs() > 0:
        _zap_log(scan_id, "Active scan: starting")
        try:
            _apply_active_options(zap.zap, active_options or {})
        except Exception:
            pass
        zap_scan_id = zap.zap_scan()
        try:
            WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                zap_ascan_id=str(zap_scan_id)
            )
        except Exception:
            pass
        def _cb(p):
            try:
                _zap_log(scan_id, f"Active scan: {p}%")
            except Exception:
                pass
        # Guard: only poll if we received a valid numeric ascan id
        try:
            _id = str(zap_scan_id).strip()
        except Exception:
            _id = ""
        if not _id or not _id.isdigit():
            try:
                WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                    failure_reason="ZAP active scan did not start (no scan id returned)",
                    updated_time=timezone.now(),
                )
            except Exception:
                pass
            _zap_log(scan_id, f"Active scan: failed to start; id={zap_scan_id!r}")
        else:
            zap.zap_scan_status(scan_id=_id, un_scanid=scan_id, max_secs=remaining_secs(), progress_cb=_cb)
        # Save active results snapshot
        try:
            av = zap.zap_scan_result(target_url=target_url)
            zap.zap_result_save(
                all_vuln=av,
                project_id=project_id,
                un_scanid=scan_id,
                target_url=target_url,
                request=request,
                scan_phase="Active",
            )
            _zap_log(scan_id, "Active scan: results snapshot saved")
            try:
                from webscanners.models import WebScanResultsDb as _W
                qs = _W.objects.filter(scan_id=scan_id, organization=request.user.organization)
                total = qs.count()
                crit = qs.filter(severity__iexact='Critical').count()
                high = qs.filter(severity__iexact='High').count()
                med = qs.filter(severity__iexact='Medium').count()
                low = qs.filter(severity__iexact='Low').count()
                info = qs.filter(severity__istartswith='Info').count()
                _zap_log(scan_id, f"Alerts: total={total} | Critical={crit}, High={high}, Medium={med}, Low={low}, Info={info}")
                # Log ALL alerts grouped by severity (Critical → Info)
                order = [
                    ("Critical", qs.filter(severity__iexact='Critical')),
                    ("High", qs.filter(severity__iexact='High')),
                    ("Medium", qs.filter(severity__iexact='Medium')),
                    ("Low", qs.filter(severity__iexact='Low')),
                    ("Informational", qs.filter(severity__istartswith='Info')),
                ]
                for label, q in order:
                    count = q.count()
                    _zap_log(scan_id, f"{label} findings: {count}")
                    for row in q.only('title','url','severity').iterator(chunk_size=500):
                        _zap_log(scan_id, f"  • {getattr(row,'severity','')} | {getattr(row,'title','')} | {getattr(row,'url','')}")
            except Exception:
                pass
        except Exception:
            pass
    else:
        # No active scan – only save passive alerts if requested
        if do_pscan_wait:
            try:
                av = zap.zap_scan_result(target_url=target_url)
                zap.zap_result_save(
                    all_vuln=av,
                    project_id=project_id,
                    un_scanid=scan_id,
                    target_url=target_url,
                    request=request,
                    scan_phase="Passive",
                )
                try:
                    from webscanners.models import WebScanResultsDb as _W
                    qs = _W.objects.filter(scan_id=scan_id, organization=request.user.organization)
                    total = qs.count()
                    crit = qs.filter(severity__iexact='Critical').count()
                    high = qs.filter(severity__iexact='High').count()
                    med = qs.filter(severity__iexact='Medium').count()
                    low = qs.filter(severity__iexact='Low').count()
                    info = qs.filter(severity__istartswith='Info').count()
                    _zap_log(scan_id, "Passive-only run: Alerts total=%s | Critical=%s, High=%s, Medium=%s, Low=%s, Info=%s" % (total, crit, high, med, low, info))
                    try:
                        for rowx in qs.only('severity','title','url')[:25]:
                            _zap_log(scan_id, "  - %s | %s | %s" % (getattr(rowx,'severity',''), getattr(rowx,'title',''), getattr(rowx,'url','')))
                    except Exception:
                        pass
                except Exception:
                    pass
            except Exception:
                pass
        else:
            _zap_log(scan_id, "Active scan disabled; passive snapshot skipped per user selection")
        # Mark the task as completed for non-active runs so the list page stops showing "In Progress"
        try:
            WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                scan_status='100',
                failure_reason=None,
                updated_time=timezone.now(),
            )
            _zap_log(scan_id, "Spider-only run completed (passive results not saved)")
        except Exception:
            pass
    all_zap_scan = WebScansDb.objects.filter(
        scanner="zap", organization=request.user.organization
    )

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    if zap_enabled is False:
        zap.zap_shutdown()

    notify.send(user, recipient=user, verb="ZAP Scan URL %s Completed" % target_url)

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )
    email_sch_notify(subject=subject, message=message)


def launch_schudle_zap_scan(
    target_url, project_id, rescan_id, rescan, scan_id, request
):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    random_port = "8090"

    # Connection Test
    zap_connect = zap_plugin.zap_connect(random_port)

    try:
        zap_connect.spider.scan(url=target_url)

    except Exception:
        subject = "ZAP Connection Not Found"
        message = "ZAP Scanner failed due to setting not found "

        email_sch_notify(subject=subject, message=message)
        print("ZAP Connection Not Found")
        return HttpResponseRedirect(reverse("webscanners:index"))

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
        request=request,
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = timezone.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
            scan_type=_build_zap_scan_type(True, False, False, True, False),
            organization=request.user.organization,
            created_by=request.user,
            updated_by=request.user,
        )

        save_all_scan.save()
    except Exception as e:
        print(e)
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    # Guard: if scan did not start, don't poll with an empty/invalid id
    try:
        zap_scan_id_str = str(zap_scan_id).strip()
    except Exception:
        zap_scan_id_str = ""
    if not zap_scan_id_str or not zap_scan_id_str.isdigit():
        try:
            WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
                failure_reason="ZAP active scan did not start (no scan id returned)",
                updated_time=timezone.now(),
            )
        except Exception:
            pass
        _zap_log(scan_id, f"Active scan: failed to start; id={zap_scan_id!r}")
    else:
        _zap_log(scan_id, f"Active scan: started with id={zap_scan_id_str}")
        zap.zap_scan_status(scan_id=zap_scan_id_str, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
        request=request,
    )
    all_zap_scan = WebScansDb.objects.filter(
        scanner="zap", organization=request.user.organization
    )

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


class ZapScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scans_status = ""
        scan_id = ""
        project_uu_id = None
        target_url = None
        user = request.user

        # Preflight: ensure org-level ZAP connector exists and is enabled (parity with OpenVAS)
        try:
            from archerysettings.models import SettingsDb as _SettingsDb
            has_connector = _SettingsDb.objects.filter(
                setting_scanner="Zap",
                organization=request.user.organization,
                setting_status=True,
            ).exists()
        except Exception:
            has_connector = False
        if not has_connector:
            msg = "ZAP settings are missing or disabled for your organization. Configure it under Settings → Add Connector → OWASP ZAP."
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=400)
            try:
                from django.contrib import messages as _msgs
                _msgs.warning(request, msg)
            except Exception:
                pass
            return HttpResponse(msg, status=400)

        # Defaults for ZAP scan type toggles
        def _to_bool(val, default=False):
            if val is None:
                return default
            v = str(val).strip().lower()
            return v in ("1", "true", "on", "yes")
        def _to_int(val, default=None, min_val=None, max_val=None):
            try:
                i = int(str(val).strip())
                if min_val is not None:
                    i = max(min_val, i)
                if max_val is not None:
                    i = min(max_val, i)
                return i
            except Exception:
                return default
        def _split_regex(raw):
            items = []
            seen = set()
            for line in str(raw or "").replace("\r", "\n").split("\n"):
                r = line.strip()
                if not r or r in seen:
                    continue
                seen.add(r)
                items.append(r)
            return items
        def _split_lines(raw):
            items = []
            seen = set()
            for line in str(raw or "").replace("\r", "\n").split("\n"):
                r = line.strip()
                if not r or r in seen:
                    continue
                seen.add(r)
                items.append(r)
            return items
        def _split_ids(raw):
            out = []
            for token in str(raw or "").replace("\n", ",").split(","):
                t = token.strip()
                if t:
                    out.append(t)
            return out
        def _to_str(val):
            return (str(val or "")).strip()

        # Defaults: run nothing unless the user/API explicitly enables it
        do_spider = False
        do_ajax_spider = False
        do_pscan_wait = False
        do_active = False
        do_forced_browse = False

        if request.path[:4] == "/api":
            _url = None
            _project_id = None

            serializer = ZapScansSerializer(data=request.data)
            if serializer.is_valid():
                target_url = request.data.get(
                    "url",
                )

                project_uu_id = request.data.get(
                    "project_id",
                )
            # Optional ZAP scan type toggles via API
            # Guard: require a project UUID before querying (avoids empty-string UUID errors)
            if not project_uu_id:
                return Response({"error": "project_id is required"}, status=400)
            do_spider = _to_bool(request.data.get("zap_spider"), False)
            do_ajax_spider = _to_bool(request.data.get("zap_ajax_spider"), False)
            do_pscan_wait = _to_bool(request.data.get("zap_pscan_wait"), False)
            do_active = _to_bool(request.data.get("zap_active_scan"), False)
            do_forced_browse = _to_bool(request.data.get("zap_forced_browse"), False)
            spider_opts = {
                "thread_count": _to_int(request.data.get("zap_spider_threads"), 24, 1, 75),
                "max_depth": _to_int(request.data.get("zap_spider_max_depth"), 12, 0, 50),
                "max_children": _to_int(request.data.get("zap_spider_max_children"), 200, 0, 2000),
                "parse_robots": _to_bool(request.data.get("zap_spider_parse_robots"), None),
                "parse_sitemap": _to_bool(request.data.get("zap_spider_parse_sitemap"), None),
                "process_forms": _to_bool(request.data.get("zap_spider_process_forms"), None),
                "submit_forms": _to_bool(request.data.get("zap_spider_submit_forms"), None),
                "send_referer": _to_bool(request.data.get("zap_spider_send_referer"), None),
                "accept_cookies": _to_bool(request.data.get("zap_spider_accept_cookies"), None),
                "handle_parameters": _to_int(request.data.get("zap_spider_handle_parameters"), None, 0, 2),
                "skip_url_token": (request.data.get("zap_spider_skip_token") or "").strip(),
                "include_regexes": _split_regex(request.data.get("zap_spider_include_regex")),
            }
            ajax_opts = {
                "max_depth": _to_int(request.data.get("ajax_max_depth"), 8, 0, 50),
                "max_states": _to_int(request.data.get("ajax_max_states"), 300, 0, 2000),
                "max_duration": _to_int(request.data.get("ajax_max_duration"), 120, 0, 360),
                "num_browsers": _to_int(request.data.get("ajax_num_browsers"), 2, 1, 6),
                "in_scope_only": _to_bool(request.data.get("ajax_in_scope_only"), None),
                "subtree_only": _to_bool(request.data.get("ajax_subtree_only"), None),
                "logout_avoid": _to_bool(request.data.get("ajax_logout_avoid"), None),
                "click_once": _to_bool(request.data.get("ajax_click_once"), None),
                "click_default": _to_bool(request.data.get("ajax_click_default"), None),
                "random_inputs": _to_bool(request.data.get("ajax_random_inputs"), None),
                "event_wait": _to_int(request.data.get("ajax_event_wait"), None, 0, 5000),
                "reload_wait": _to_int(request.data.get("ajax_reload_wait"), None, 0, 5000),
                "allowed_resources": _split_regex(request.data.get("ajax_allowed_regex")),
                "excluded_elems": _split_lines(request.data.get("ajax_excluded_elems")),
            }
            pscan_opts = {
                "scope_only": _to_bool(request.data.get("pscan_scope_only"), None),
                "clear_queue": _to_bool(request.data.get("pscan_clear_queue"), None),
                "max_alerts": _to_int(request.data.get("pscan_max_alerts"), None, 0, 20000),
                "enable_ids": _split_ids(request.data.get("pscan_enable_ids")),
                "disable_ids": _split_ids(request.data.get("pscan_disable_ids")),
            }
            active_opts = {
                "threads_per_host": _to_int(request.data.get("active_threads_per_host"), 4, 1, 50),
                "hosts_per_scan": _to_int(request.data.get("active_hosts_per_scan"), 2, 1, 10),
                "delay_ms": _to_int(request.data.get("active_delay_ms"), 0, 0, 5000),
                "max_scan_mins": _to_int(request.data.get("active_max_scan_mins"), 120, 0, 480),
                "max_rule_mins": _to_int(request.data.get("active_max_rule_mins"), 15, 0, 120),
                "recurse": _to_bool(request.data.get("active_recurse"), None),
                "in_scope_only": _to_bool(request.data.get("active_in_scope_only"), None),
                "enable_ids": _split_ids(request.data.get("active_enable_ids")),
                "disable_ids": _split_ids(request.data.get("active_disable_ids")),
            }
            fb_opts = {
                "threads": _to_int(request.data.get("fb_threads"), 10, 1, 50),
                "extensions": _to_str(request.data.get("fb_extensions")),
                "recursive": _to_bool(request.data.get("fb_recursive"), True),
                "in_scope_only": _to_bool(request.data.get("fb_in_scope_only"), True),
                "max_dirs": _to_int(request.data.get("fb_max_dirs"), 10000, 0, 200000),
                "max_files": _to_int(request.data.get("fb_max_files"), 20000, 0, 200000),
                "wordlist": _resolve_wordlist_path(_to_str(request.data.get("fb_wordlist"))),
            }
        else:
            target_url = request.POST.get("url")
            project_uu_id = request.POST.get("project_id")
            # Optional ZAP scan type toggles via UI
            # Guard: require a project UUID before querying (avoids empty-string UUID errors)
            if not project_uu_id:
                msg = "project_id is required"
                if request.path[:4] == "/api":
                    return Response({"error": msg}, status=400)
                return HttpResponse(msg, status=400)
            do_spider = _to_bool(request.POST.get("zap_spider"), False)
            do_ajax_spider = _to_bool(request.POST.get("zap_ajax_spider"), False)
            do_pscan_wait = _to_bool(request.POST.get("zap_pscan_wait"), False)
            do_active = _to_bool(request.POST.get("zap_active_scan"), False)
            do_forced_browse = _to_bool(request.POST.get("zap_forced_browse"), False)
            spider_opts = {
                "thread_count": _to_int(request.POST.get("zap_spider_threads"), 24, 1, 75),
                "max_depth": _to_int(request.POST.get("zap_spider_max_depth"), 12, 0, 50),
                "max_children": _to_int(request.POST.get("zap_spider_max_children"), 200, 0, 2000),
                "parse_robots": _to_bool(request.POST.get("zap_spider_parse_robots"), None),
                "parse_sitemap": _to_bool(request.POST.get("zap_spider_parse_sitemap"), None),
                "process_forms": _to_bool(request.POST.get("zap_spider_process_forms"), None),
                "submit_forms": _to_bool(request.POST.get("zap_spider_submit_forms"), None),
                "send_referer": _to_bool(request.POST.get("zap_spider_send_referer"), None),
                "accept_cookies": _to_bool(request.POST.get("zap_spider_accept_cookies"), None),
                "handle_parameters": _to_int(request.POST.get("zap_spider_handle_parameters"), None, 0, 2),
                "skip_url_token": (request.POST.get("zap_spider_skip_token") or "").strip(),
                "include_regexes": _split_regex(request.POST.get("zap_spider_include_regex")),
            }
            ajax_opts = {
                "max_depth": _to_int(request.POST.get("ajax_max_depth"), 8, 0, 50),
                "max_states": _to_int(request.POST.get("ajax_max_states"), 300, 0, 2000),
                "max_duration": _to_int(request.POST.get("ajax_max_duration"), 120, 0, 360),
                "num_browsers": _to_int(request.POST.get("ajax_num_browsers"), 2, 1, 6),
                "in_scope_only": _to_bool(request.POST.get("ajax_in_scope_only"), None),
                "subtree_only": _to_bool(request.POST.get("ajax_subtree_only"), None),
                "logout_avoid": _to_bool(request.POST.get("ajax_logout_avoid"), None),
                "click_once": _to_bool(request.POST.get("ajax_click_once"), None),
                "click_default": _to_bool(request.POST.get("ajax_click_default"), None),
                "random_inputs": _to_bool(request.POST.get("ajax_random_inputs"), None),
                "event_wait": _to_int(request.POST.get("ajax_event_wait"), None, 0, 5000),
                "reload_wait": _to_int(request.POST.get("ajax_reload_wait"), None, 0, 5000),
                "allowed_resources": _split_regex(request.POST.get("ajax_allowed_regex")),
                "excluded_elems": _split_lines(request.POST.get("ajax_excluded_elems")),
            }
            pscan_opts = {
                "scope_only": _to_bool(request.POST.get("pscan_scope_only"), None),
                "clear_queue": _to_bool(request.POST.get("pscan_clear_queue"), None),
                "max_alerts": _to_int(request.POST.get("pscan_max_alerts"), None, 0, 20000),
                "enable_ids": _split_ids(request.POST.get("pscan_enable_ids")),
                "disable_ids": _split_ids(request.POST.get("pscan_disable_ids")),
            }
            active_opts = {
                "threads_per_host": _to_int(request.POST.get("active_threads_per_host"), 4, 1, 50),
                "hosts_per_scan": _to_int(request.POST.get("active_hosts_per_scan"), 2, 1, 10),
                "delay_ms": _to_int(request.POST.get("active_delay_ms"), 0, 0, 5000),
                "max_scan_mins": _to_int(request.POST.get("active_max_scan_mins"), 120, 0, 480),
                "max_rule_mins": _to_int(request.POST.get("active_max_rule_mins"), 15, 0, 120),
                "recurse": _to_bool(request.POST.get("active_recurse"), None),
                "in_scope_only": _to_bool(request.POST.get("active_in_scope_only"), None),
                "enable_ids": _split_ids(request.POST.get("active_enable_ids")),
                "disable_ids": _split_ids(request.POST.get("active_disable_ids")),
            }
            fb_opts = {
                "threads": _to_int(request.POST.get("fb_threads"), 10, 1, 50),
                "extensions": _to_str(request.POST.get("fb_extensions")),
                "recursive": _to_bool(request.POST.get("fb_recursive"), True),
                "in_scope_only": _to_bool(request.POST.get("fb_in_scope_only"), True),
                "max_dirs": _to_int(request.POST.get("fb_max_dirs"), 10000, 0, 200000),
                "max_files": _to_int(request.POST.get("fb_max_files"), 20000, 0, 200000),
                "wordlist": _resolve_wordlist_path(_to_str(request.POST.get("fb_wordlist"))),
            }
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id, organization=request.user.organization
            )
            .values("id")
            .get()["id"]
        )
        rescan_id = None
        rescan = "No"
        targets, invalid_targets = _parse_target_urls(target_url)
        if (not targets) or invalid_targets:
            msg = _url_error_message(invalid_targets)
            if request.path[:4] == "/api":
                return Response({"error": msg}, status=400)
            return HttpResponse(msg, status=400)
        scan_ids = []
        for target in targets:
            scan_id = uuid.uuid4()
            scan_ids.append(str(scan_id))
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(
                    target,
                    project_id,
                    rescan_id,
                    rescan,
                    scan_id,
                    user,
                    request,
                    do_spider,
                    do_ajax_spider,
                    do_pscan_wait,
                    do_active,
                    do_forced_browse,
                ),
                kwargs={"spider_options": spider_opts, "ajax_options": ajax_opts, "pscan_options": pscan_opts, "active_options": active_opts, "fb_options": fb_opts},
            )
            thread.daemon = True
            thread.start()
            time.sleep(10)
        log_action(request, "scan_start", "zap_scan", ",".join(str(s) for s in scan_ids), {"targets": targets})
        if scans_status == "100":
            scans_status = "0"
        else:
            if request.path[:4] == "/api":
                return Response({"scan_ids": scan_ids})
            return JsonResponse({"scan_ids": scan_ids, "targets": targets}, status=200)

        if request.path[:4] == "/api":
            return Response({"scan_ids": scan_ids})
        else:
            return JsonResponse({"scan_ids": scan_ids, "targets": targets}, status=200)


class ZapSetting(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        zap_api_key = ""
        zap_hosts = None
        zap_ports = None
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_api_key = zap.zap_api
            zap_hosts = zap.zap_url
            zap_ports = zap.zap_port
            zap_enabled = zap.enabled

        if zap_enabled:
            zap_enabled = "True"
        else:
            zap_enabled = "False"

        if request.path[:4] == "/api":
            return Response(
                {
                    "zap_api_key": zap_api_key,
                    "zap_hosts": zap_hosts,
                    "zap_ports": zap_ports,
                    "zap_enabled": zap_enabled,
                }
            )
        else:
            return render(
                request,
                "webscanners/zapscanner/zap_settings_form.html",
                {
                    "zap_apikey": zap_api_key,
                    "zap_host": zap_hosts,
                    "zap_port": zap_ports,
                    "zap_enabled": zap_enabled,
                },
            )


class ZapSettingUpdate(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(request, "webscanners/zapscanner/zap_settings_form.html")

    def post(self, request):
        zaphost = "NA"
        port = "NA"
        apikey = "NA"

        # Determine target organization (supports superuser org switching)
        org = getattr(request.user, "organization", None)
        org_id_param = request.GET.get("org") or request.POST.get("org")
        if getattr(request.user, "is_superuser", False) and org_id_param:
            try:
                org = Organization.objects.get(pk=org_id_param)
            except Exception:
                pass

        ZapSettingsDb.objects.filter(organization=org).delete()
        SettingsDb.objects.filter(setting_scanner="Zap", organization=org).delete()

        if request.POST.get("zap_enabled") == "on":
            zap_enabled = True
        else:
            zap_enabled = False

        if request.path[:4] == "/api":
            serializer = ZapSettingsSerializer(data=request.data)
            if serializer.is_valid():
                apikey = request.data.get(
                    "zap_api_key",
                )
                zaphost = request.data.get(
                    "zap_host",
                )
                port = request.data.get(
                    "zap_port",
                )
                zap_enabled = request.data.get(
                    "zap_enabled",
                )
        else:
            apikey = request.POST.get(
                "apikey",
            )
            zaphost = request.POST.get(
                "zappath",
            )
            port = request.POST.get(
                "port",
            )

        setting_id = uuid.uuid4()

        save_zap_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Zap",
            organization=org,
        )
        save_zap_data.save()

        save_data = ZapSettingsDb(
            setting_id=setting_id,
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey,
            enabled=zap_enabled,
            organization=org,
        )
        save_data.save()

        if request.path[:4] == "/api":
            if zap_enabled is False:
                return Response({"message": "OWASP ZAP scanner updated!!!"})

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"
        zap_info = ""

        all_zap = ZapSettingsDb.objects.filter(organization=org)
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            if request.path[:4] == "/api":
                return Response({"message": "OWASP ZAP Scanner Disabled"})
            zap_info = "Disabled"
            try:
                random_port = zap_plugin.zap_local()
            except:
                return render(
                    request, "setting/settings_page.html", {"zap_info": zap_info}
                )

            for i in range(0, 100):
                while True:
                    try:
                        # Connection Test
                        zap_connect = zap_plugin.zap_connect(random_port)
                        zap_connect.spider.scan(url=target_url)
                    except Exception as e:
                        print("ZAP Connection Not Found, re-try after 5 sec")
                        time.sleep(5)
                        continue
                    break
        else:
            try:
                zap_connect = zap_plugin.zap_connect(
                    random_port,
                )
                zap_connect.spider.scan(url=target_url)
                zap_info = True
                SettingsDb.objects.filter(setting_id=setting_id, organization=org).update(
                    setting_status=zap_info
                )
                if request.path[:4] == "/api":
                    return Response({"message": "OWASP ZAP scanner updated!!!"})
            except:
                zap_info = False
                SettingsDb.objects.filter(setting_id=setting_id, organization=org).update(
                    setting_status=zap_info
                )
                if request.path[:4] == "/api":
                    return Response({"message": "Not updated, Something Wrong !!!"})

        redirect_url = reverse("archerysettings:settings")
        if getattr(request.user, "is_superuser", False) and getattr(org, "id", None):
            redirect_url = f"{redirect_url}?org={org.id}"
        return HttpResponseRedirect(redirect_url)


class ZapRescan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        import uuid as _uuid
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=400)
        try:
            ws = WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).get()
        except Exception:
            return Response({"message": "Scan not found"}, status=404)

        # Only Admin/superuser or the owner may rescan
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        except Exception:
            is_admin = False
        if not is_admin and getattr(ws, "created_by_id", None) != getattr(request.user, "id", None):
            return Response({"message": "Forbidden"}, status=403)

        # Re-use the same scan_id so the row reloads itself
        new_scan_id = ws.scan_id
        target_url = ws.scan_url
        project_id = ws.project_id
        user = request.user
        rescan_id = str(ws.scan_id)
        rescan = "Yes"

        # Try to preserve the original ZAP step selection based on the saved scan_type label
        do_spider = True
        do_ajax_spider = False
        do_pscan_wait = False
        do_active = True
        do_forced_browse = False
        try:
            st = (getattr(ws, 'scan_type', '') or '').lower()
            # Accept labels like "ZAP Active + Spider", "Active", "Passive", etc.
            if st:
                do_active = ('active' in st)
                do_spider = ('spider' in st) and (not 'ajax' in st) or ('active + spider' in st) or ('spider (crawl)' in st)
                do_ajax_spider = ('ajax' in st)
                do_pscan_wait = ('passive' in st) or ('pscan' in st)
                do_forced_browse = ('forced' in st) or ('dirbuster' in st)
        except Exception:
            pass

        # Purge previous results and reset aggregates for a clean rescan
        try:
            from webscanners.models import WebScanResultsDb
            WebScanResultsDb.objects.filter(
                scan_id=new_scan_id, organization=request.user.organization
            ).delete()
            from django.utils import timezone as _tz
            WebScansDb.objects.filter(
                scan_id=new_scan_id, organization=request.user.organization
            ).update(
                total_vul=0,
                critical_vul=0,
                high_vul=0,
                medium_vul=0,
                low_vul=0,
                info_vul=0,
                total_dup=0,
                scan_status="0",
                failure_reason=None,
                updated_time=_tz.now(),
            )
        except Exception:
            pass

        thread = threading.Thread(
            target=launch_zap_scan,
            args=(target_url, project_id, rescan_id, rescan, new_scan_id, user, request),
            kwargs=dict(
                do_spider=do_spider,
                do_ajax_spider=do_ajax_spider,
                do_pscan_wait=do_pscan_wait,
                do_active=do_active,
                do_forced_browse=do_forced_browse,
                spider_options=None,
            ),
        )
        thread.daemon = True
        # Clear any stale ascan id prior to relaunch
        try:
            from django.utils import timezone as _tz
            WebScansDb.objects.filter(scan_id=new_scan_id, organization=request.user.organization).update(
                zap_ascan_id=None, scan_status="0", failure_reason=None, updated_time=_tz.now()
            )
        except Exception:
            pass
        thread.start()

        if request.path[:4] == "/api":
            return Response({"scan_id": str(new_scan_id)}, status=200)
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


class ZapStop(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scan_id = request.POST.get("scan_id") or request.data.get("scan_id")
        if not scan_id:
            return Response({"message": "scan_id required"}, status=400)

        # Prefer stopping the exact ZAP ascan id saved for this row; fallback to host match
        try:
            # Owner check first
            ws = WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).first()
            try:
                is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
            except Exception:
                is_admin = False
            if ws and (not is_admin) and getattr(ws, "created_by_id", None) != getattr(request.user, "id", None):
                return Response({"message": "Forbidden"}, status=403)

            # Prefer configured port; fall back to default daemon port
            random_port = "8090"
            zap = zap_plugin.zap_connect(random_port=random_port)
            # Lookup the target from DB
            try:
                target_url = ws.scan_url or ""
                ascan_id = (ws.zap_ascan_id or "").strip()
            except Exception:
                target_url = ""
                ascan_id = ""

            # Normalize hosts for comparison
            from urllib.parse import urlparse
            def _host(u):
                try:
                    h = urlparse(str(u)).netloc or ""
                    return h.lstrip("www.").lower()
                except Exception:
                    return ""
            thost = _host(target_url)

            stopped_any = False
            # If we know the exact ZAP ascan id, stop only that one
            if ascan_id:
                try:
                    zap.ascan.stop(ascan_id)
                    stopped_any = True
                except Exception:
                    # If stop by id fails, continue with fallback
                    pass
            if not stopped_any:
                # Fallback: Stop active scans matching the same host
                try:
                    scans = []
                    try:
                        scans = zap.ascan.scans()
                    except Exception:
                        scans = []
                    for s in scans or []:
                        sid = s.get("id") or s.get("scan") or s.get("scanid") or s.get("scanId")
                        surl = s.get("url") or s.get("target") or ""
                        if sid and thost and _host(surl) == thost:
                            try:
                                zap.ascan.stop(sid)
                                stopped_any = True
                            except Exception:
                                pass
                except Exception:
                    pass
            # Also try to stop matching spider scans
            try:
                sscans = []
                try:
                    sscans = zap.spider.scans()
                except Exception:
                    sscans = []
                for s in sscans or []:
                    sid = s.get("scan") or s.get("id")
                    surl = s.get("url") or s.get("target") or ""
                    if sid and thost and _host(surl) == thost:
                        try:
                            zap.spider.stop(sid)
                            stopped_any = True
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            # Swallow connection issues; we'll still mark the DB as stopped
            pass

        from django.utils import timezone as _tz
        # Try to capture last known progress to reflect immediately in UI
        last_pct = None
        try:
            scans = []
            try:
                scans = zap.ascan.scans()
            except Exception:
                scans = []
            for s in scans or []:
                sid = s.get("id") or s.get("scan") or s.get("scanid") or s.get("scanId")
                if sid and sid == (ws.zap_ascan_id or "").strip():
                    # Some ZAP versions expose 'progress' or 'status'
                    pct = s.get("progress") or s.get("status") or s.get("percentage")
                    try:
                        last_pct = int(float(str(pct)))
                    except Exception:
                        last_pct = None
                    break
        except Exception:
            last_pct = None

        updates = {
            "failure_reason": "Stopped by user",
            "zap_ascan_id": None,
            "updated_time": _tz.now(),
        }
        if last_pct is not None:
            updates["scan_status"] = str(last_pct)
        WebScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(**updates)

        if request.path[:4] == "/api":
            return Response({"message": "ZAP scan stop requested"}, status=200)
        return HttpResponseRedirect(reverse("webscanners:list_scans"))


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
