from django.conf import settings
from django.core.mail import send_mail
from django.core import signing

from archerysettings.models import EmailDb


def email_sch_notify(subject, message):
    all_emails = EmailDb.objects.filter(is_active=True)
    if not all_emails:
        return False
    recipients = []
    cfg = all_emails.first()
    for email in all_emails:
        if email.recipient_list:
            parts = [r.strip() for r in email.recipient_list.split(",") if r.strip()]
            recipients.extend(parts)
    recipients = list(dict.fromkeys(recipients))
    if not recipients:
        return False
    if cfg.smtp_host:
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = cfg.sender_email or cfg.smtp_user or settings.EMAIL_HOST_USER
            msg["To"] = ", ".join(recipients)
            smtp_args = {"host": cfg.smtp_host, "port": int(cfg.smtp_port or 587)}
            server = smtplib.SMTP(**smtp_args)
            if cfg.smtp_use_tls:
                server.starttls()
            if cfg.smtp_user:
                password = signing.loads(cfg.smtp_password) if cfg.smtp_password else None
                server.login(cfg.smtp_user, password)
            server.sendmail(msg["From"], recipients, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            print(f"Email send via SMTP failed: {e}")
    email_from = settings.EMAIL_HOST_USER
    try:
        send_mail(subject, message, email_from, recipients)
        return True
    except Exception as e:
        print(f"Email send via default backend failed: {e}")
        return False
