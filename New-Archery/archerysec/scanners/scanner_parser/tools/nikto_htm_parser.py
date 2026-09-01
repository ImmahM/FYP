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

import hashlib
import uuid
import defusedxml.ElementTree as ET
from archeryapi.models import OrgAPIKey
from tools.models import NiktoVulnDb, NiktoResultDb
from webscanners.models import WebScansDb, WebScanResultsDb
from bs4 import BeautifulSoup 
from django.utils import timezone
import re

# --- Advanced severity mapping rules (shared by HTML and XML parsing) ---
BASE_SCORES = {"Info": 0, "Low": 10, "Medium": 20, "High": 40, "Critical": 70}
CONF_MOD = {"High": 1.2, "Medium": 1.0, "Low": 0.7}
CORRELATION_BOOST = 1.15

# Precompile regex patterns
RX = {
    # 1
    "secrets": re.compile(r"(password=|passwd:|root:|AWS_ACCESS_KEY_ID|SECRET_KEY|BEGIN RSA PRIVATE KEY)", re.I),
    # 2
    "phpinfo": re.compile(r"(<title>phpinfo\(|<h1>PHP Version|phpinfo\(\)|Fatal error on line|Stacktrace)", re.I),
    # 3
    "dir_index": re.compile(r"(Index of /|directory indexing|is browsable)", re.I),
    # 4
    "exposed_src": re.compile(r"(\.git/|\.svn/|\.env|\.bak|\.sql)", re.I),
    # 5
    "xss": re.compile(r"<script>\s*alert\(1\)\s*</script>", re.I),
    # 6
    "sql_errors": re.compile(r"(SQL syntax|You have an error in your SQL syntax|ORA-|Warning:\s*mysql_)", re.I),
    # 7
    "server_banner": re.compile(r"Server:\s*(Apache|nginx|IIS)/[0-9]+\.[0-9]+", re.I),
    # 8
    "robots": re.compile(r"Disallow:\s*/(admin|private|cms|secret)", re.I),
    # 9
    "admin": re.compile(r"(phpMyAdmin|/admin/|Default admin:admin)", re.I),
    # 10
    "headers": re.compile(r"(X-Frame-Options|Content-Security-Policy|Strict-Transport-Security)", re.I),
    # 11
    "weak_tls": re.compile(r"(SSL certificate verify failed|expired certificate|TLSv1|RC4|weak cipher)", re.I),
    # 12
    "redir": re.compile(r"redirect=.*(http|https)://", re.I),
    # 13
    "comments": re.compile(r"<!--.*?(password|TODO|FIXME).*?-->", re.I | re.S),
    # 14
    "paths": re.compile(r"(/var/www/|C:\\inetpub|192\.168\.)", re.I),
    # 15
    "set_cookie": re.compile(r"Set-Cookie:\s*", re.I),
    # 16
    "cms": re.compile(r"(wp-content/|Joomla|Drupal|Magento)", re.I),
    # 17
    "archives": re.compile(r"(\.zip|\.tar\.gz|\.7z|\.rar|\.bak)", re.I),
    # 18
    "methods": re.compile(r"Allow:\s*(?:.*\b)?(PUT|DELETE|TRACE)\b|(PUT|DELETE|TRACE)\s+method\s+(?:is\s+)?(?:enabled|allowed)", re.I),
    # 19
    "sensitive_files": re.compile(r"(/config\.php|/wp-config\.php|/id_rsa|/database\.yml)", re.I),
    # 20
    "keywords": re.compile(r"(confidential|internal use only|do not distribute)", re.I),
}


def _score_to_sev(score):
    if score >= 49:
        return "Critical"
    if score >= 25:
        return "High"
    if score >= 13:
        return "Medium"
    if score >= 5:
        return "Low"
    return "Info"


def nikto_sev_color(label):
    return {
        "Critical": "critical",
        "High": "danger",
        "Medium": "warning",
        "Low": "info",
        "Info": "info",
    }.get(label, "info")


def nikto_risk(description, uri=""):
    """Evaluate Nikto finding text through the rule engine and return a severity label.

    Scores are calibrated so that a single rule match resolves to its intended
    tier (Low match -> Low, Medium match -> Medium, ...) instead of being buried
    under an aggregate cutoff.
    """
    text = (description or "") + "\n" + (uri or "")
    found = []
    add = lambda sev, conf: BASE_SCORES[sev] * CONF_MOD[conf]

    if RX["secrets"].search(text):
        found.append(add("Critical", "High"))
    if RX["phpinfo"].search(text):
        found.append(add("High", "High"))
    if RX["dir_index"].search(text):
        if re.search(r"(backup|\.env|db\.sql)", text, re.I):
            found.append(add("High", "Medium"))
        else:
            found.append(add("Low", "Medium"))
    if RX["exposed_src"].search(text):
        if RX["secrets"].search(text):
            found.append(add("Critical", "High"))
        else:
            found.append(add("High", "High"))
    if RX["xss"].search(text):
        found.append(add("Medium", "High"))
    if RX["sql_errors"].search(text):
        found.append(add("Medium", "High"))
    if RX["server_banner"].search(text):
        found.append(add("Medium", "Medium"))
    if RX["robots"].search(text):
        found.append(add("Low", "Medium"))
    if RX["admin"].search(text):
        found.append(add("High", "High"))
    if RX["headers"].search(text):
        matches = len(RX["headers"].findall(text))
        if matches >= 2:
            found.append(add("Medium", "Medium"))
        else:
            found.append(add("Low", "Medium"))
    if RX["weak_tls"].search(text):
        if re.search(r"expired|self-signed", text, re.I):
            found.append(add("High", "Medium"))
        else:
            found.append(add("Medium", "Medium"))
    if RX["redir"].search(text):
        found.append(add("Low", "Medium"))
    if RX["comments"].search(text):
        if RX["secrets"].search(text):
            found.append(add("High", "Medium"))
        else:
            found.append(add("Low", "Medium"))
    if RX["paths"].search(text):
        found.append(add("Medium", "High"))
    if RX["set_cookie"].search(text):
        if re.search(r"HttpOnly.*not set", text, re.I) and re.search(r"Secure.*not set", text, re.I):
            found.append(add("Medium", "Medium"))
        else:
            found.append(add("Low", "Medium"))
    if RX["cms"].search(text):
        if re.search(r"outdated|vulnerable", text, re.I):
            found.append(add("High", "Medium"))
        else:
            found.append(add("Medium", "Medium"))
    if RX["archives"].search(text):
        if RX["secrets"].search(text):
            found.append(add("Critical", "High"))
        else:
            found.append(add("High", "High"))
    if RX["methods"].search(text):
        found.append(add("Medium", "Medium"))
    if RX["sensitive_files"].search(text):
        if RX["secrets"].search(text):
            found.append(add("Critical", "High"))
        else:
            found.append(add("High", "High"))
    if RX["keywords"].search(text):
        found.append(add("Medium", "Medium"))

    if not found:
        return "Info"
    score = sum(found)
    if len(found) >= 2:
        score *= CORRELATION_BOOST  # correlation multiplier
    return _score_to_sev(score)


def nikto_html_parser(data, project_id, scan_id, request=None):
    discription = "None"
    targetip = "None"
    hostname = "None"
    port = "None"
    uri = "None"
    httpmethod = "None"
    testlinks = "None"
    osvdb = "None"
    soup = BeautifulSoup(data, "html.parser")

    # Determine organization from request or from existing NiktoResult row
    organization = None
    if request is not None:
        try:
            api_key = request.META.get("HTTP_X_API_KEY")
            key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
            if str(getattr(request, 'user', '')) == 'AnonymousUser':
                organization = getattr(key_object, 'organization', None)
            else:
                organization = getattr(request.user, 'organization', None)
        except Exception:
            organization = None
    if organization is None:
        try:
            nr = NiktoResultDb.objects.filter(scan_id=scan_id).first()
            organization = getattr(nr, 'organization', None)
        except Exception:
            organization = None

    # Create (or ensure) the WebScansDb summary row exists early
    try:
        WebScansDb.objects.get_or_create(
            scan_id=scan_id,
            organization=organization,
            defaults={
                "project_id": project_id,
                "scan_url": "",
                "scan_status": "0",
                "rescan": "No",
                "scanner": "Nikto",
            },
        )
    except Exception:
        pass

    total = 0
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    scan_url_detected = None

    for link in soup.find_all(class_="dataTable"):
        # print "------------------------"
        table_rows = link.find_all("tr")
        for tr in table_rows:
            for tt in tr.find_all(class_="column-head"):
                if tt.text == "Description":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "Description:", ttt.text
                    discription = ttt.text
                if tt.text == "Target IP":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "Target IP", ttt.text
                    targetip = ttt.text
                if tt.text == "Target hostname":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "Target hostname", ttt.text
                    hostname = ttt.text
                if tt.text == "Target Port":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "Target Port", ttt.text
                    port = ttt.text

                if tt.text == "URI":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "URI:", ttt.text
                    uri = ttt.text
                if tt.text == "HTTP Method":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "HTTP Method:", ttt.text
                    httpmethod = ttt.text
                if tt.text == "Test Links":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "Test Links:", ttt.text
                    testlinks = ttt.text
                if tt.text == "OSVDB Entries":
                    for ttt in tr.find_all("td"):
                        for tttt in ttt.find_all("b"):
                            del tttt
                    # print "OSVDB Entries:", ttt.text
                    osvdb = ttt.text

        # Track an inferred URL from hostname/ip
        if not scan_url_detected:
            scan_url_detected = hostname or targetip or uri

        vuln_id = uuid.uuid4()

        dup_data = discription + hostname
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = (
            NiktoVulnDb.objects.filter(
                dup_hash=duplicate_hash, organization=organization
            )
            .values("dup_hash")
            .distinct()
        )
        lenth_match = len(match_dup)

        if lenth_match == 1:
            duplicate_vuln = "Yes"
        elif lenth_match == 0:
            duplicate_vuln = "No"
        else:
            duplicate_vuln = "None"

        false_p = NiktoVulnDb.objects.filter(
            false_positive_hash=duplicate_hash, organization=organization
        )
        fp_lenth_match = len(false_p)

        global false_positive
        if fp_lenth_match == 1:
            false_positive = "Yes"
        elif lenth_match == 0:
            false_positive = "No"
        else:
            false_positive = "No"

        # Save to NiktoVulnDb (original model)
        if NiktoVulnDb.objects.filter(
            scan_id=scan_id,
            dup_hash=duplicate_hash,
            organization=organization,
        ).exists():
            continue
        dump_data = NiktoVulnDb(
            vuln_id=vuln_id,
            scan_id=scan_id,
            project_id=project_id,
            discription=discription,
            targetip=targetip,
            hostname=hostname,
            port=port,
            uri=uri,
            httpmethod=httpmethod,
            testlinks=testlinks,
            osvdb=osvdb,
            false_positive=false_positive,
            dup_hash=duplicate_hash,
            vuln_duplicate=duplicate_vuln,
            vuln_status="Open",
            organization=organization,
        )
        dump_data.save()

        # Compute severity using advanced mapping rules
        risk = nikto_risk(discription, uri or "")
        vul_col = nikto_sev_color(risk)

        # Save to WebScanResultsDb so Web Scans table shows the findings
        try:
            # Avoid duplicate inserts if backfilling multiple times
            exists = WebScanResultsDb.objects.filter(
                scan_id=scan_id,
                dup_hash=duplicate_hash,
                scanner="Nikto",
                organization=organization,
            ).exists()
            if not exists:
                WebScanResultsDb.objects.create(
                    vuln_id=vuln_id,
                    severity_color=vul_col,
                    scan_id=scan_id,
                    date_time=timezone.now(),
                    project_id=project_id,
                    url=hostname or targetip or uri,
                    title=(discription or "")[0:100],
                    solution="",
                    instance=[{"uri": uri, "method": httpmethod}],
                    reference="",
                    description=discription,
                    severity=risk,
                    false_positive="No",
                    jira_ticket="",
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate="No",
                    scanner="Nikto",
                    organization=organization,
                    created_by=getattr(getattr(request, 'user', None), 'pk', None) and getattr(request, 'user') or None,
                    updated_by=getattr(getattr(request, 'user', None), 'pk', None) and getattr(request, 'user') or None,
                )
                total += 1
                sev_counts[risk if risk in sev_counts else "Info"] += 1
        except Exception:
            pass

    # Finalize the WebScansDb summary with counts and status
    try:
        WebScansDb.objects.filter(scan_id=scan_id, organization=organization).update(
            scan_url=scan_url_detected or "",
            scan_status="100",
            scanner="Nikto",
            total_vul=total,
            critical_vul=sev_counts.get("Critical", 0),
            high_vul=sev_counts.get("High", 0),
            medium_vul=sev_counts.get("Medium", 0),
            low_vul=sev_counts.get("Low", 0),
            info_vul=sev_counts.get("Info", 0),
        )
    except Exception:
        pass


def nikto_xml_parser(root, project_id, scan_id, request):
    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization if key_object else None
    else:
        organization = request.user.organization

    # Save the scan summary (if not already present)
    WebScansDb.objects.get_or_create(
        scan_id=scan_id,
        defaults={
            "scan_url": "",  # You can extract from XML if available
            "date_time": timezone.now(),
            "project_id": project_id,
            "scan_status": "100",
            "rescan": "No",
            "scanner": "Nikto",
            "organization": organization,
        }
    )

    # Find the <scandetails> node
    for scandetails in root.iter("scandetails"):
        scan_url = scandetails.attrib.get("sitename", "")
        for item in scandetails.findall("item"):
            discription = item.findtext("description", default="None")
            uri = item.findtext("uri", default="None")
            httpmethod = item.attrib.get("method", "None")
            hostname = scandetails.attrib.get("targethostname", "None")
            targetip = scandetails.attrib.get("targetip", "None")
            port = scandetails.attrib.get("targetport", "None")

            # Assign risk using the shared rule engine (same as HTML path)
            risk = nikto_risk(discription, uri or "")
            vul_col = nikto_sev_color(risk)

            vuln_id = uuid.uuid4()
            duplicate_hash = hashlib.sha256((discription + hostname).encode("utf-8")).hexdigest()

            # Avoid duplicate inserts if this report was parsed before
            if WebScanResultsDb.objects.filter(
                scan_id=scan_id,
                dup_hash=duplicate_hash,
                scanner="Nikto",
                organization=organization,
            ).exists():
                continue

            # Save each finding in WebScanResultsDb
            WebScanResultsDb.objects.create(
                vuln_id=vuln_id,
                severity_color=vul_col,
                scan_id=scan_id,
                date_time=timezone.now(),
                project_id=project_id,
                url=scan_url,
                title=discription[:100],  # Use first 100 chars as title
                solution="",
                instance=[{"uri": uri, "method": httpmethod}],
                reference="",
                description=discription,
                severity=risk,
                false_positive="No",
                jira_ticket="",
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate="No",
                scanner="Nikto",
                organization=organization,
                created_by=getattr(getattr(request, 'user', None), 'pk', None) and getattr(request, 'user') or None,
                updated_by=getattr(getattr(request, 'user', None), 'pk', None) and getattr(request, 'user') or None,
            )


parser_header_dict = {
    "nikto_scan": {
        "displayName": "Nikto",
        "dbtype": "WebScans",  
        "dbname": "Nikto",
        "icon": "/static/tools/nikto.svg",
        "type": "XML",
        "parserFunction": nikto_xml_parser,
    }
}

