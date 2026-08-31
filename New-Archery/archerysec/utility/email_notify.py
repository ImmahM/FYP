from django.conf import settings
from django.core.mail import send_mail
from django.core import signing
from html import escape as _escape

from archerysettings.models import EmailDb


def _pretty_status(value):
    """Map stored scan-status values (e.g. '100', 'Completed') to clean display text."""
    s = str(value or "").strip()
    if not s:
        return "Completed"
    low = s.lower()
    if low in ("completed", "complete", "done", "finishing", "finished", "success", "successful"):
        return "Completed"
    try:
        num = float(s)
    except (TypeError, ValueError):
        return s
    if num >= 100:
        return "Completed"
    if num > 0:
        return "{:.0f}%".format(num)
    return s


def email_sch_notify(subject, message, html=None):
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
            msg = MIMEText(message, "html" if html else "plain")
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


def email_scan_summary(subject, scan_id, target_url, organization_id=None):
    """Send a rich HTML scan-completion email with status, score and findings."""
    from webscanners.models import WebScanResultsDb, WebScansDb

    total = crit = high = med = low = info = 0
    cvss_vals = []
    risk_vals = []
    findings = []
    lookup_error = False
    try:
        qs = WebScanResultsDb.objects.filter(scan_id=scan_id)
        if organization_id:
            qs = qs.filter(organization_id=organization_id)
        total = qs.count()
        crit = qs.filter(severity__iexact="Critical").count()
        high = qs.filter(severity__iexact="High").count()
        med = qs.filter(severity__iexact="Medium").count()
        low = qs.filter(severity__iexact="Low").count()
        info = qs.filter(severity__istartswith="Info").count()
        rows = list(qs.order_by("-risk_score", "-cvss_score")[:25])
        for r in rows:
            if r.cvss_score:
                cvss_vals.append(r.cvss_score)
            if r.risk_score:
                risk_vals.append(r.risk_score)
            findings.append(r)
    except Exception as e:
        lookup_error = True
        print(f"Scan summary query failed: {e}")

    status = "Completed"
    scanner = "ZAP"
    try:
        scan_row = WebScansDb.objects.filter(scan_id=scan_id).first()
        if scan_row is not None:
            status = _pretty_status(scan_row.scan_status)
            scanner = scan_row.scanner or scanner
    except Exception:
        pass

    sev_score_map = {
        "Critical": 10.0,
        "High": 8.1,
        "Medium": 5.3,
        "Low": 2.6,
        "Informational": 0.0,
        "Info": 0.0,
    }

    def _score_for(sev):
        return sev_score_map.get(str(sev or "").strip())

    derived = []
    derived += [_score_for("Critical")] * crit
    derived += [_score_for("High")] * high
    derived += [_score_for("Medium")] * med
    derived += [_score_for("Low")] * low
    derived += [_score_for("Info")] * info
    derived = [x for x in derived if x is not None]
    if not cvss_vals:
        cvss_vals = derived
    if not risk_vals:
        risk_vals = derived

    max_cvss = max(cvss_vals) if cvss_vals else None
    avg_cvss = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None
    max_risk = max(risk_vals) if risk_vals else None
    avg_risk = round(sum(risk_vals) / len(risk_vals), 2) if risk_vals else None

    sev_colors = {
        "Critical": "#d32f2f",
        "High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#7cb342",
        "Informational": "#90a4ae",
        "Info": "#90a4ae",
    }

    rows_html = []
    for i, r in enumerate(findings, 1):
        sev = r.severity or ""
        color = sev_colors.get(sev, "#333333")
        rows_html.append(
            "<tr>"
            "<td>{}</td>"
            "<td style='color:{}; font-weight:bold;'>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "</tr>".format(
                i,
                color,
                _escape(sev),
                _escape(r.title or ""),
                _escape(r.url or "")[:90],
                r.cvss_score if r.cvss_score is not None else "-",
                _escape(r.mitre_techniques or "")[:60],
                r.risk_score if r.risk_score is not None else "-",
            )
        )
    if not rows_html:
        rows_html.append(
            "<tr><td colspan='7' style='text-align:center;'>No findings for this scan.</td></tr>"
        )

    html_body = (
        "<div style='font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222222;'>"
        "<h2 style='color:#333333;border-bottom:2px solid #4a90d9;padding-bottom:8px;'>"
        "{scanner} Scan Completed</h2>"
        "<table cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:13px;'>"
        "<tr><td style='width:170px;'><b>Status:</b></td><td>{status}</td></tr>"
        "<tr><td><b>Target URL:</b></td><td>{target_url}</td></tr>"
        "<tr><td><b>Scan ID:</b></td><td>{scan_id}</td></tr>"
        "<tr><td><b>Total Findings:</b></td><td>{total}</td></tr>"
        "<tr><td><b>Critical / High / Medium / Low / Info:</b></td><td>{crit} / {high} / {med} / {low} / {info}</td></tr>"
        "<tr><td><b>Max CVSS Score:</b></td><td>{max_cvss}</td></tr>"
        "<tr><td><b>Avg CVSS Score:</b></td><td>{avg_cvss}</td></tr>"
        "<tr><td><b>Max Risk Score:</b></td><td>{max_risk}</td></tr>"
        "<tr><td><b>Avg Risk Score:</b></td><td>{avg_risk}</td></tr>"
        "</table>"
        "<h3>Findings (top {shown} of {total})</h3>"
        "<table border='1' cellspacing='0' cellpadding='6' "
        "style='border-collapse:collapse;width:100%;font-size:12px;'>"
        "<thead style='background:#4a90d9;color:#ffffff;'>"
        "<tr><th>#</th><th>Severity</th><th>Title</th><th>URL</th>"
        "<th>CVSS</th><th>MITRE</th><th>Risk</th></tr>"
        "</thead><tbody>{rows}</tbody></table>"
        "</div>"
    ).format(
        scanner=_escape(str(scanner)),
        status=_escape(str(status)),
        target_url=_escape(str(target_url)),
        scan_id=_escape(str(scan_id)),
        total=total,
        crit=crit,
        high=high,
        med=med,
        low=low,
        info=info,
        max_cvss=max_cvss if max_cvss is not None else "-",
        avg_cvss=avg_cvss if avg_cvss is not None else "-",
        max_risk=max_risk if max_risk is not None else "-",
        avg_risk=avg_risk if avg_risk is not None else "-",
        shown=len(findings),
        rows="".join(rows_html),
    )

    if lookup_error:
        message = "Scan completed. Total: %s | Critical: %s | High: %s | Medium: %s | Low: %s" % (
            total, crit, high, med, low
        )
        return email_sch_notify(subject=subject, message=message)

    return email_sch_notify(subject=subject, message=html_body, html=True)


def email_network_scan_summary(subject, scan_id, target_url="", organization_id=None):
    """Send a rich HTML scan-completion email for network scanners
    (OpenVAS, Nmap) using NetworkScanDb / NetworkScanResultsDb."""
    from networkscanners.models import NetworkScanResultsDb, NetworkScanDb

    total = crit = high = med = low = info = 0
    findings = []
    lookup_error = False
    try:
        qs = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        if organization_id:
            qs = qs.filter(organization_id=organization_id)
        total = qs.count()
        crit = qs.filter(severity__iexact="Critical").count()
        high = qs.filter(severity__iexact="High").count()
        med = qs.filter(severity__iexact="Medium").count()
        low = qs.filter(severity__iexact="Low").count()
        info = qs.filter(severity__istartswith="Info").count()
        findings = list(qs.order_by("-severity")[:25])
    except Exception as e:
        lookup_error = True
        print(f"Network scan summary query failed: {e}")

    status = "Completed"
    scanner = "Network"
    scan_row_ip = None
    try:
        scan_row = NetworkScanDb.objects.filter(scan_id=scan_id).first()
        if scan_row is not None:
            status = _pretty_status(scan_row.scan_status)
            scanner = scan_row.scanner or scanner
            scan_row_ip = scan_row.ip or None
    except Exception:
        pass

    if not target_url:
        target_url = str(scan_row_ip) if scan_row_ip else str(scan_id)

    sev_colors = {
        "Critical": "#d32f2f",
        "High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#7cb342",
        "Informational": "#90a4ae",
        "Info": "#90a4ae",
    }

    rows_html = []
    for i, r in enumerate(findings, 1):
        sev = r.severity or ""
        color = sev_colors.get(sev, "#333333")
        rows_html.append(
            "<tr>"
            "<td>{}</td>"
            "<td style='color:{}; font-weight:bold;'>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "<td>{}</td>"
            "</tr>".format(
                i,
                color,
                _escape(sev),
                _escape(r.title or ""),
                _escape(str(r.ip or "")),
                _escape(str(r.port or "")),
            )
        )
    if not rows_html:
        rows_html.append(
            "<tr><td colspan='5' style='text-align:center;'>No findings for this scan.</td></tr>"
        )

    html_body = (
        "<div style='font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222222;'>"
        "<h2 style='color:#333333;border-bottom:2px solid #4a90d9;padding-bottom:8px;'>"
        "{scanner} Scan Completed</h2>"
        "<table cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:13px;'>"
        "<tr><td style='width:170px;'><b>Status:</b></td><td>{status}</td></tr>"
        "<tr><td><b>Target:</b></td><td>{target_url}</td></tr>"
        "<tr><td><b>Scan ID:</b></td><td>{scan_id}</td></tr>"
        "<tr><td><b>Total Findings:</b></td><td>{total}</td></tr>"
        "<tr><td><b>Critical / High / Medium / Low / Info:</b></td><td>{crit} / {high} / {med} / {low} / {info}</td></tr>"
        "</table>"
        "<h3>Findings (top {shown} of {total})</h3>"
        "<table border='1' cellspacing='0' cellpadding='6' "
        "style='border-collapse:collapse;width:100%;font-size:12px;'>"
        "<thead style='background:#4a90d9;color:#ffffff;'>"
        "<tr><th>#</th><th>Severity</th><th>Title</th><th>IP</th><th>Port</th></tr>"
        "</thead><tbody>{rows}</tbody></table>"
        "<p style='font-size:11px;color:#777777;'>"
        "Note: network scanner findings carry no CVSS/risk score in ArcherySec.</p>"
        "</div>"
    ).format(
        scanner=_escape(str(scanner)),
        status=_escape(str(status)),
        target_url=_escape(str(target_url)),
        scan_id=_escape(str(scan_id)),
        total=total,
        crit=crit,
        high=high,
        med=med,
        low=low,
        info=info,
        shown=len(findings),
        rows="".join(rows_html),
    )

    if lookup_error:
        message = "Scan completed. Total: %s | Critical: %s | High: %s | Medium: %s | Low: %s" % (
            total, crit, high, med, low
        )
        return email_sch_notify(subject=subject, message=message)

    return email_sch_notify(subject=subject, message=html_body, html=True)


def email_scan_started(subject, target_url, scanner, scheduled_for=None):
    """Send a formatted 'scan started' email for scheduled scans."""
    html_body = (
        "<div style='font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222222;'>"
        "<h2 style='color:#333333;border-bottom:2px solid #4a90d9;padding-bottom:8px;'>"
        "{scanner} Scan Started</h2>"
        "<table cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:13px;'>"
        "<tr><td style='width:170px;'><b>Status:</b></td><td>Started</td></tr>"
        "<tr><td><b>Target:</b></td><td>{target_url}</td></tr>"
        "<tr><td><b>Scanner:</b></td><td>{scanner}</td></tr>"
        "<tr><td><b>Scheduled for:</b></td><td>{scheduled_for}</td></tr>"
        "</table>"
        "<p>Your scheduled scan has started. You will receive a second email with the "
        "status, score and full findings when it completes.</p>"
        "</div>"
    ).format(
        scanner=_escape(str(scanner)),
        target_url=_escape(str(target_url)),
        scheduled_for=_escape(str(scheduled_for or "-")),
    )
    return email_sch_notify(subject=subject, message=html_body, html=True)