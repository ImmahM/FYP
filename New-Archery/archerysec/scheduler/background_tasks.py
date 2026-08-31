import os
import threading
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytz
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

LOCAL_TZ = pytz.timezone(getattr(settings, "DEF_TIME_ZONE", "Asia/Kuala_Lumpur"))
FREQUENCY_MAP = {
    "DAILY": timedelta(days=1),
    "WEEKLY": timedelta(weeks=1),
    "EVERY_2_WEEKS": timedelta(weeks=2),
    "EVERY_4_WEEKS": timedelta(weeks=4),
    "HOURLY": timedelta(hours=1),
}

_LOCK = threading.Lock()
_TIMERS = {"web": {}, "net": {}}
_BOOTSTRAPPED = False


def _log(msg):
    try:
        from logging import getLogger

        logger = getLogger("scheduler")
        logger.info(msg)
    except Exception:
        print(f"[Scheduler] {msg}")


def _notify_user(user, message):
    if not user:
        return
    try:
        from notifications.signals import notify

        notify.send(user, recipient=user, verb=message)
    except Exception:
        _log(f"Notification suppressed: {message}")
    try:
        from scanners.notification import send_notification
        send_notification(user, verb=message[:255], description=message)
    except Exception:
        pass


def _parse_dt(value):
    if not value:
        return None
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S %p", "%d/%m/%Y %H:%M:%S"):
        try:
            naive = datetime.strptime(value.strip(), fmt)
            return LOCAL_TZ.localize(naive).astimezone(timezone.utc)
        except Exception:
            continue
    return None


def _ensure_schedule_fields(schedule):
    updated = False
    if not schedule.schedule_time_utc and schedule.schedule_time:
        parsed = _parse_dt(schedule.schedule_time)
        if parsed:
            schedule.schedule_time_utc = parsed
            updated = True
    if updated:
        schedule.save(update_fields=["schedule_time_utc"])


def _request_for(user):
    return SimpleNamespace(user=user, META={}, GET={}, POST={}, session={})


def _schedule_next(schedule, kind):
    freq = FREQUENCY_MAP.get((schedule.periodic_task or "").upper())
    if not freq:
        schedule.is_active = False
        schedule.save(update_fields=["is_active", "last_run_at"])
        return
    next_run = (schedule.schedule_time_utc or timezone.now()) + freq
    schedule.schedule_time_utc = next_run
    local_display = next_run.astimezone(LOCAL_TZ).strftime("%d/%m/%Y %I:%M:%S %p")
    schedule.schedule_time = local_display
    schedule.save(update_fields=["schedule_time", "schedule_time_utc", "last_run_at"])
    if kind == "web":
        register_web_schedule(schedule)
    else:
        register_network_schedule(schedule)


def _execute_web(schedule_id):
    from webscanners.models import task_schedule_db
    from webscanners.zapscanner.views import launch_zap_scan

    schedule = (
        task_schedule_db.objects.select_related("created_by", "organization")
        .filter(id=schedule_id, is_active=True)
        .first()
    )
    if not schedule:
        return
    _ensure_schedule_fields(schedule)
    user = schedule.created_by or get_user_model().objects.filter(is_superuser=True).first()
    if not user:
        _log(f"No user available to run scheduled web scan {schedule_id}")
        return
    schedule.last_run_at = timezone.now()
    schedule.save(update_fields=["last_run_at"])
    _notify_user(
        user,
        f"Scheduled web scan for {schedule.target} (scanner: {schedule.scanner}) started.",
    )
    try:
        from utility.email_notify import email_scan_started

        email_scan_started(
            subject="Archery Tool Scan Status - Scheduled Web Scan Started",
            target_url=schedule.target,
            scanner=schedule.scanner or "web",
            scheduled_for=schedule.schedule_time or schedule.schedule_time_utc,
        )
    except Exception as exc:
        _log(f"Scheduled web scan started email failed: {exc}")
    try:
        if schedule.scanner == "zap_scan":
            config = schedule.scan_config or {}

            def _cfg_bool(key, default):
                val = config.get(key)
                if val is None:
                    return default
                if isinstance(val, bool):
                    return val
                try:
                    return str(val).strip().lower() in ("1", "true", "on", "yes")
                except Exception:
                    return default

            launch_zap_scan(
                target_url=schedule.target,
                project_id=schedule.project_id,
                rescan_id=uuid.uuid4(),
                rescan="",
                scan_id=uuid.uuid4(),
                user=user,
                request=_request_for(user),
                do_spider=_cfg_bool("zap_spider", True),
                do_ajax_spider=_cfg_bool("zap_ajax_spider", False),
                do_pscan_wait=_cfg_bool("zap_pscan_wait", False),
                do_active=_cfg_bool("zap_active_scan", True),
                do_forced_browse=_cfg_bool("zap_forced_browse", False),
            )
        elif schedule.scanner == "nikto_scan":
            _run_scheduled_nikto(schedule, user)
        else:
            _log(f"Scanner {schedule.scanner} not supported for scheduling.")
    except Exception as exc:
        _log(f"Scheduled web scan {schedule_id} failed: {exc}")
        _notify_user(
            user,
            f"Scheduled web scan for {schedule.target} failed to start: {exc}",
        )
    finally:
        _notify_user(
            user,
            f"Scheduled web scan for {schedule.target} completed.",
        )
        _schedule_next(schedule, "web")


def _run_scheduled_nikto(schedule, user):
    from tools.models import NiktoResultDb
    from tools.views import _run_nikto_scan
    from webscanners.models import WebScansDb

    config = schedule.scan_config or {}

    def _cfg_bool(key, default=False):
        val = config.get(key)
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        try:
            return str(val).strip().lower() in ("1", "true", "on", "yes")
        except Exception:
            return default

    scan_id = uuid.uuid4()
    target = schedule.target
    org = schedule.organization
    now = timezone.now()
    # Preflight: only run the scheduled Nikto scan if the org Nikto connector is green
    try:
        from archerysettings.models import SettingsDb as _SettingsDb
        has_connector = _SettingsDb.objects.filter(
            setting_scanner="Nikto",
            organization=org,
            setting_status=True,
        ).exists()
    except Exception:
        has_connector = False
    if not has_connector:
        _log(f"Scheduled Nikto scan skipped: Nikto connector missing/disabled for org {getattr(org, 'id', None)}")
        _notify_user(
            user,
            f"Scheduled Nikto scan for {target} skipped: Nikto connector is not enabled. Configure it under Settings → Connectors.",
        )
        return
    try:
        nikto_res_dir = getattr(
            settings, "NIKTO_RESULT_DIR", os.path.join(os.getcwd(), "nikto_result")
        )
        os.makedirs(nikto_res_dir, exist_ok=True)
    except Exception:
        nikto_res_dir = os.path.join(os.getcwd(), "nikto_result")
        try:
            os.makedirs(nikto_res_dir, exist_ok=True)
        except Exception:
            pass
    nikto_res_path = os.path.join(nikto_res_dir, f"{scan_id}.html")
    try:
        nikto_log_dir = getattr(
            settings, "NIKTO_LOG_DIR", os.path.join(os.getcwd(), "logs", "nikto")
        )
        os.makedirs(nikto_log_dir, exist_ok=True)
        log_path = os.path.join(nikto_log_dir, f"{scan_id}.log")
        with open(log_path, "a", encoding="utf-8", errors="ignore") as log_fh:
            log_fh.write(
                f"[scheduler] Queued Nikto scan for {target} (schedule_id={schedule.id})\n"
            )
    except Exception:
        pass

    NiktoResultDb.objects.create(
        scan_url=target,
        scan_id=scan_id,
        project_id=schedule.project_id,
        date_time=now,
        nikto_status="Scan Started",
        organization=org,
    )
    WebScansDb.objects.update_or_create(
        scan_id=scan_id,
        organization=org,
        defaults=dict(
            project_id=schedule.project_id,
            scan_url=target,
            date_time=now,
            rescan_id=None,
            rescan="No",
            scan_status="0",
            scanner="Nikto",
            scan_type=schedule.scan_type or "Nikto Scan",
            failure_reason=None,
            created_by=user,
            updated_by=user,
        ),
    )
    _run_nikto_scan(
        scans_url=target,
        scan_id=scan_id,
        project_id=schedule.project_id,
        profile_tuning=config.get("profile_tuning"),
        request=_request_for(user),
        user=user,
        org=org,
        nikto_res_path=nikto_res_path,
        force_cgi=_cfg_bool("force_cgi", False),
        plugins_all=_cfg_bool("plugins_all", False),
        maxtime_min=config.get("maxtime_min"),
        pause_sec=config.get("pause_sec"),
        evasion=config.get("evasion"),
        user_agent=config.get("user_agent"),
        config_path=config.get("config_path"),
        extra_flags=config.get("extra_flags"),
        timeout_s=config.get("timeout_s", 15),
    )


def _run_scheduled_nmap(schedule, user):
    from networkscanners.models import NetworkScanDb
    from networkscanners.views import _run_nmap

    config = schedule.scan_config or {}

    def _cfg_bool(val, default=False):
        if isinstance(val, bool):
            return val
        if val is None:
            return default
        try:
            return str(val).strip().lower() in ("1", "true", "on", "yes")
        except Exception:
            return default

    profile = str(config.get("nmap_profile") or "quick").lower()
    if profile not in ("quick", "full"):
        profile = "quick"
    os_guess = _cfg_bool(config.get("nmap_os_guess"), False)

    project_id_value = schedule.project_id
    try:
        if project_id_value is not None and project_id_value != "":
            project_id_value = int(str(project_id_value))
    except Exception:
        project_id_value = None

    scan_id = uuid.uuid4()
    target = str(schedule.target or "").strip()
    org = schedule.organization

    # Preflight: only run the scheduled Nmap scan if the org Nmap connector is green
    try:
        from archerysettings.models import SettingsDb as _SettingsDb
        has_connector = _SettingsDb.objects.filter(
            setting_scanner="Nmap",
            organization=org,
            setting_status=True,
        ).exists()
    except Exception:
        has_connector = False
    if not has_connector:
        _log(f"Scheduled Nmap scan skipped: Nmap connector missing/disabled for org {getattr(org, 'id', None)}")
        _notify_user(
            user,
            f"Scheduled Nmap scan for {target} skipped: Nmap connector is not enabled. Configure it under Settings → Connectors.",
        )
        return

    now = timezone.now()

    NetworkScanDb.objects.create(
        scan_id=str(scan_id),
        project_id=project_id_value,
        ip=target,
        date_time=now,
        scan_status="0",
        scanner="Nmap",
        scan_type="Nmap - " + ("Full" if profile == "full" else "Quick") + (" + OS" if os_guess else ""),
        organization=org,
        created_by=user,
        updated_by=user,
    )

    runner = threading.Thread(
        target=_run_nmap,
        args=(scan_id, target, project_id_value, profile, os_guess, _request_for(user)),
    )
    runner.daemon = True
    runner.start()


def _execute_network(schedule_id):
    from networkscanners.models import TaskScheduleDb
    from networkscanners.views import openvas_scanner

    schedule = (
        TaskScheduleDb.objects.filter(id=schedule_id, is_active=True).first()
    )
    if not schedule:
        return
    _ensure_schedule_fields(schedule)
    from user_management.models import UserProfile

    user = UserProfile.objects.filter(id=schedule.created_by_id).first()
    if not user:
        user = get_user_model().objects.filter(is_superuser=True).first()
    if not user:
        _log(f"No user available to run scheduled network scan {schedule_id}")
        return
    schedule.last_run_at = timezone.now()
    schedule.save(update_fields=["last_run_at"])
    _notify_user(
        user,
        f"Scheduled network scan for {schedule.target} (scanner: {schedule.scanner}) started.",
    )
    try:
        from utility.email_notify import email_scan_started

        email_scan_started(
            subject="Archery Tool Scan Status - Scheduled Network Scan Started",
            target_url=schedule.target,
            scanner=schedule.scanner or "network",
            scheduled_for=schedule.schedule_time or schedule.schedule_time_utc,
        )
    except Exception as exc:
        _log(f"Scheduled network scan started email failed: {exc}")
    try:
        scanner_name = str(schedule.scanner or "")
        if scanner_name == "open_vas":
            config = schedule.scan_config or {}

            def _cfg_profile():
                try:
                    profile = config.get("openvas_profile")
                except Exception:
                    profile = None
                if not profile:
                    return None
                return str(profile).strip()

            project_id_value = schedule.project_id
            try:
                if project_id_value is not None and project_id_value != "":
                    project_id_value = int(str(project_id_value))
            except Exception:
                project_id_value = None
            openvas_scanner(
                schedule.target,
                project_id_value,
                sel_profile=_cfg_profile(),
                user=user,
                request=_request_for(user),
            )
        elif scanner_name.lower() == "nmap":
            _run_scheduled_nmap(schedule, user)
        else:
            _log(f"Scanner {schedule.scanner} not supported for scheduling.")
    except Exception as exc:
        _log(f"Scheduled network scan {schedule_id} failed: {exc}")
        _notify_user(
            user,
            f"Scheduled network scan for {schedule.target} failed to start: {exc}",
        )
    finally:
        if scanner_name.lower() == "nmap":
            _notify_user(
                user,
                f"Scheduled network scan for {schedule.target} completed.",
            )
        _schedule_next(schedule, "net")


def _schedule_timer(kind, schedule_id, run_at):
    delay = max((run_at - timezone.now()).total_seconds(), 1)
    target = _execute_web if kind == "web" else _execute_network
    timer = threading.Timer(delay, target, args=(schedule_id,))
    timer.daemon = True
    with _LOCK:
        existing = _TIMERS[kind].pop(schedule_id, None)
        if existing:
            existing.cancel()
        _TIMERS[kind][schedule_id] = timer
    timer.start()


def register_web_schedule(schedule):
    _ensure_schedule_fields(schedule)
    if not schedule.schedule_time_utc:
        return
    _schedule_timer("web", schedule.id, schedule.schedule_time_utc)


def register_network_schedule(schedule):
    _ensure_schedule_fields(schedule)
    if not schedule.schedule_time_utc:
        return
    _schedule_timer("net", schedule.id, schedule.schedule_time_utc)


def cancel_schedule(kind, schedule_id):
    with _LOCK:
        timer = _TIMERS.get(kind, {}).pop(schedule_id, None)
    if timer:
        timer.cancel()


def bootstrap():
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    if os.environ.get("DISABLE_SCHEDULER") == "1":
        return
    if settings.DEBUG and os.environ.get("RUN_MAIN") != "true" and os.environ.get("FORCE_SCHEDULER") != "1":
        _log("Scheduler skipped: DEBUG=True and RUN_MAIN!=true (set FORCE_SCHEDULER=1 to override)")
        return
    _BOOTSTRAPPED = True
    try:
        from webscanners.models import task_schedule_db
        from networkscanners.models import TaskScheduleDb

        for schedule in task_schedule_db.objects.filter(is_active=True):
            register_web_schedule(schedule)
        for schedule in TaskScheduleDb.objects.filter(is_active=True):
            register_network_schedule(schedule)
        _log("Scheduler bootstrapped")
    except Exception as exc:
        _log(f"Scheduler bootstrap failed: {exc}")
