import logging
import re

logger = logging.getLogger(__name__)

CWE_MITRE_MAP = {
    # Injection (TA0001 - Initial Access, TA0002 - Execution)
    "CWE-77": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-78": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-79": [
        {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"},
        {"id": "T1204.001", "name": "Malicious Link", "tactic": "Initial Access"},
    ],
    "CWE-80": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-89": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-90": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-91": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-94": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-95": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-99": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-113": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],

    # Path Traversal / File Inclusion (TA0005 - Defense Evasion)
    "CWE-22": [{"id": "T1612", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"}],
    "CWE-23": [{"id": "T1612", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"}],
    "CWE-36": [{"id": "T1612", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"}],
    "CWE-73": [{"id": "T1612", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"}],
    "CWE-98": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],

    # Information Disclosure (TA0007 - Discovery)
    "CWE-200": [{"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"}],
    "CWE-201": [{"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"}],
    "CWE-203": [{"id": "T1589", "name": "Gather Victim Identity Information", "tactic": "Reconnaissance"}],
    "CWE-209": [{"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}],
    "CWE-215": [{"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}],
    "CWE-497": [{"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}],
    "CWE-540": [{"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}],
    "CWE-548": [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}],

    # Cryptographic Issues (TA0040 - Impact)
    "CWE-310": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-311": [{"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"}],
    "CWE-312": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-319": [{"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"}],
    "CWE-320": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-321": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-322": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-323": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-325": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-326": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-327": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-328": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-330": [{"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"}],

    # Cross-Site Request Forgery (TA0001 - Initial Access)
    "CWE-352": [{"id": "T1204.001", "name": "Malicious Link", "tactic": "Initial Access"}],

    # Authentication / Session Issues (TA0006 - Credential Access)
    "CWE-255": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-256": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-257": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-258": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-259": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-261": [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-287": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-288": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-295": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-296": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-297": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-298": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-306": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-307": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-308": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-385": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-521": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-522": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-613": [{"id": "T1525", "name": "Impersonation", "tactic": "Credential Access"}],
    "CWE-620": [{"id": "T1525", "name": "Impersonation", "tactic": "Credential Access"}],

    # Access Control / Authorization (TA0005 - Defense Evasion)
    "CWE-264": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-266": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-269": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-272": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-273": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-276": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-277": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-284": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-285": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-434": [{"id": "T1604", "name": "Upload or Modify Files", "tactic": "Impact"}],
    "CWE-639": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-732": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-862": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-863": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],

    # Input Validation / Output Encoding (various)
    "CWE-20": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-116": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-120": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-126": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-129": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-134": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-170": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-172": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-190": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-191": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-193": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-242": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-252": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-253": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-369": [{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}],
    "CWE-400": [{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}],
    "CWE-415": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-416": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-426": [{"id": "T1574", "name": "Hijack Execution Flow", "tactic": "Defense Evasion"}],

    # Buffer Overflows / Memory Safety (TA0002 - Execution)
    "CWE-119": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-121": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-122": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-1325": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-787": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-788": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],
    "CWE-805": [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}],

    # Permission / Privilege (TA0005 - Defense Evasion)
    "CWE-250": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"}],
    "CWE-347": [{"id": "T1553", "name": "Subvert Trust Controls", "tactic": "Defense Evasion"}],
    "CWE-348": [{"id": "T1553", "name": "Subvert Trust Controls", "tactic": "Defense Evasion"}],
    "CWE-349": [{"id": "T1553", "name": "Subvert Trust Controls", "tactic": "Defense Evasion"}],
    "CWE-350": [{"id": "T1553", "name": "Subvert Trust Controls", "tactic": "Defense Evasion"}],
    "CWE-351": [{"id": "T1553", "name": "Subvert Trust Controls", "tactic": "Defense Evasion"}],
    "CWE-362": [{"id": "T1574", "name": "Hijack Execution Flow", "tactic": "Defense Evasion"}],
    "CWE-367": [{"id": "T1574", "name": "Hijack Execution Flow", "tactic": "Defense Evasion"}],

    # Cloud-specific (TA0040 - Impact, TA0007 - Discovery)
    "CWE-1033": [{"id": "T1525", "name": "Impersonation", "tactic": "Credential Access"}],
    "CWE-1034": [{"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"}],
    "CWE-1035": [{"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"}],
    "CWE-1036": [{"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"}],
    "CWE-1037": [{"id": "T1525", "name": "Impersonation", "tactic": "Credential Access"}],
    "CWE-1104": [{"id": "T1613", "name": "Container and Resource Discovery", "tactic": "Discovery"}],

    # XSS variations
    "CWE-81": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-82": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-83": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-84": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-85": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-86": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "CWE-87": [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
}

CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

_MITRE_TECH_RE = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)

SEVERITY_MITRE_MAP = {
    "critical": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "high": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
}

KEYWORD_MITRE_MAP = [
    (re.compile(r"(xss|cross.?site.?script)", re.IGNORECASE),
     [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}]),
    (re.compile(r"(sql.?inject|sqli)", re.IGNORECASE),
     [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]),
    (re.compile(r"(command.?inject|rce|remote.?code.?exec|code.?exec)", re.IGNORECASE),
     [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}]),
    (re.compile(r"(path.?traversal|directory.?traversal|lfi|file.?inclusion)", re.IGNORECASE),
     [{"id": "T1612", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"}]),
    (re.compile(r"(csrf|request.?forger|cross.?site.?request)", re.IGNORECASE),
     [{"id": "T1204.001", "name": "Malicious Link", "tactic": "Initial Access"}]),
    (re.compile(r"(ssl|tls|certificate|weak.?crypto|deprecated.?protocol)", re.IGNORECASE),
     [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}]),
    (re.compile(r"(password|credential|brute.?force|auth.?bypass)", re.IGNORECASE),
     [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}]),
    (re.compile(r"(information.?disclos|path.?disclos|directory.?list)", re.IGNORECASE),
     [{"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"}]),
    (re.compile(r"(open.?redirect)", re.IGNORECASE),
     [{"id": "T1204.001", "name": "Malicious Link", "tactic": "Initial Access"}]),
    (re.compile(r"(ssrf|server.?side.?request.?forger)", re.IGNORECASE),
     [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]),
    (re.compile(r"(xxe|xml.?extern)", re.IGNORECASE),
     [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]),
    (re.compile(r"(buffer.?overflow|stack.?overflow|heap.?overflow)", re.IGNORECASE),
     [{"id": "T1200", "name": "Hardware Additions", "tactic": "Initial Access"}]),
    (re.compile(r"(deserializ)", re.IGNORECASE),
     [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]),
    (re.compile(r"(dos|denial.?of.?service|resource.?exhaustion)", re.IGNORECASE),
     [{"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}]),
    (re.compile(r"(clickjack|click.?jack|framing|ui.?redress)", re.IGNORECASE),
     [{"id": "T1204.001", "name": "Malicious Link", "tactic": "Initial Access"}]),
    (re.compile(r"(misconfig|misconfigur)", re.IGNORECASE),
     [{"id": "T1525", "name": "Impersonation", "tactic": "Credential Access"}]),
    (re.compile(r"(ssti|template.?inject)", re.IGNORECASE),
     [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}]),
    (re.compile(r"(ldap.?inject)", re.IGNORECASE),
     [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]),
]


def lookup_by_cwe(cwe_id):
    if not cwe_id:
        return None
    cwe_id = cwe_id.strip().upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = "CWE-" + cwe_id
    return CWE_MITRE_MAP.get(cwe_id)


def lookup_by_keywords(text):
    if not text:
        return None
    for pattern, techniques in KEYWORD_MITRE_MAP:
        if pattern.search(text):
            return techniques
    return None


def extract_cwes(text):
    if not text:
        return []
    return ["CWE-" + m for m in CWE_RE.findall(text)]


def enrich_finding(finding_data):
    cwe_id = finding_data.get("cwe_id")
    title = finding_data.get("title") or ""
    description = finding_data.get("description") or ""
    severity = (finding_data.get("severity") or "").lower()

    techniques = None

    if cwe_id:
        techniques = lookup_by_cwe(cwe_id)

    if not techniques:
        extracted = extract_cwes(title + " " + description)
        for cwe in extracted:
            techniques = lookup_by_cwe(cwe)
            if techniques:
                break

    if not techniques:
        search_text = title + " " + description
        techniques = lookup_by_keywords(search_text)

    if not techniques and severity in SEVERITY_MITRE_MAP:
        techniques = SEVERITY_MITRE_MAP[severity]

    if techniques:
        finding_data["mitre_techniques"] = techniques
        finding_data["mitre_has_data"] = True
    else:
        finding_data["mitre_techniques"] = []
        finding_data["mitre_has_data"] = False

    return finding_data


def enrich_model_instance(obj):
    techniques = None
    cwe_texts = []

    cwe_id = getattr(obj, "cwe_id", None) or ""
    title = getattr(obj, "title", None) or ""
    description = getattr(obj, "description", None) or ""

    if cwe_id:
        techniques = lookup_by_cwe(cwe_id.strip())

    if not techniques:
        extracted = extract_cwes(title + " " + description)
        for cwe in extracted:
            techniques = lookup_by_cwe(cwe)
            if techniques:
                break

    if not techniques:
        search_text = title + " " + description
        techniques = lookup_by_keywords(search_text)

    severity = (getattr(obj, "severity", None) or "").lower()
    if not techniques and severity in SEVERITY_MITRE_MAP:
        techniques = SEVERITY_MITRE_MAP[severity]

    if techniques:
        obj.mitre_techniques = techniques
        obj.mitre_has_data = True
    else:
        obj.mitre_techniques = []
        obj.mitre_has_data = False

    return obj
