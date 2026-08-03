import logging

from django.conf import settings
from django.core.mail import send_mail
from django.core import signing
from django.db import IntegrityError

logger = logging.getLogger(__name__)


def _get_email_config(organization_id):
    from archerysettings.models import EmailDb
    cfg = EmailDb.objects.filter(
        organization_id=organization_id, is_active=True
    ).first()
    return cfg


def _send_email(to_emails, subject, message, organization_id=None):
    if not to_emails:
        return False
    cfg = _get_email_config(organization_id) if organization_id else None
    if cfg and cfg.smtp_host:
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = cfg.sender_email or cfg.smtp_user or settings.EMAIL_HOST_USER
            msg["To"] = ", ".join(to_emails)
            smtp_args = {"host": cfg.smtp_host, "port": int(cfg.smtp_port or 587)}
            if cfg.smtp_user:
                password = signing.loads(cfg.smtp_password) if cfg.smtp_password else None
                smtp_args["user"] = cfg.smtp_user
                smtp_args["password"] = password
            server = smtplib.SMTP(**smtp_args)
            if cfg.smtp_use_tls:
                server.starttls()
            if cfg.smtp_user:
                password = signing.loads(cfg.smtp_password) if cfg.smtp_password else None
                server.login(cfg.smtp_user, password)
            server.sendmail(msg["From"], to_emails, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.warning("Email send failed via SMTP config: %s", e)
            return False
    try:
        send_mail(subject, message, settings.EMAIL_HOST_USER, to_emails)
        return True
    except Exception as e:
        logger.warning("Email send failed via default backend: %s", e)
        return False


def send_notification(user, verb, action="info", resource_type="", resource_id="", description=""):
    if not user:
        return
    if not getattr(user, "notify_in_app", True):
        pass
    if not getattr(user, "notify_email", True) and verb == "notification":
        pass
    _pref_on = {
        "scan_start": "notify_on_scan_start",
        "scan_complete": "notify_on_scan_complete",
        "scan_fail": "notify_on_scan_fail",
    }
    pref_attr = _pref_on.get(action)
    if pref_attr and not getattr(user, pref_attr, True):
        return
    try:
        from notifications.signals import notify
        notify.send(user, recipient=user, verb=verb, description=description)
    except Exception as e:
        logger.warning("In-app notification failed: %s", e)
    if getattr(user, "notify_email", True):
        org_id = getattr(getattr(user, "organization", None), "id", None)
        _send_email(
            to_emails=[user.email],
            subject=f"[ArcherySec] {verb}",
            message=description or verb,
            organization_id=org_id,
        )


def send_scan_notification(user, scan_type, target, scan_id, status="started"):
    action_map = {
        "started": ("scan_start", "Scan started"),
        "completed": ("scan_complete", "Scan completed"),
        "failed": ("scan_fail", "Scan failed"),
    }
    action, verb = action_map.get(status, ("scan_start", "Scan started"))
    desc = f"{verb}: {scan_type} scan on {target or 'N/A'} ({scan_id})"
    send_notification(
        user=user,
        verb=desc[:255],
        action=action,
        resource_type=f"scan_{scan_type}",
        resource_id=str(scan_id),
        description=desc,
    )
