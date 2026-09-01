# archerysec/reports/views.py
# ===========================
from collections import OrderedDict
from urllib.parse import urlencode

from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Q, Sum, Max, Case, When, Value, IntegerField, Count, F, OuterRef, Subquery
from django.db.models.functions import Coalesce
from weasyprint import HTML

# Jinja2 support for flexible report templates
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from projects.models import ProjectDb
from scanners.analysis import RiskScorer, VulnerabilityPrioritizer, ReportNarrativeGenerator, CvssCalculator, NvdLookup
from scanners.audit import log_action
from webscanners.models import WebScansDb, WebScanResultsDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from notifications.models import Notification


SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_WEIGHTS = {
    "critical": 9,
    "high": 5,
    "medium": 3,
    "low": 1,
}
RISK_LEVEL_SCALE = (
    ("Critical", 400, "danger"),
    ("High", 200, "warning"),
    ("Medium", 80, "info"),
    ("Low", 0, "success"),
)
RESULT_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
SEVERITY_DISPLAY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#facc15",
    "low": "#22c55e",
    "informational": "#64748b",
    "other": "#475569",
}
RESULT_SEVERITY_ALIASES = {
    "informational": "informational",
    "info": "informational",
    "information": "informational",
    "inform": "informational",
}
RESULT_SEVERITY_WEIGHTS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


def _strip_scanner_prefix(value, fallback="Scan"):
    """Return a scanner-agnostic scan type string.

    Strips known scanner name prefixes like "ZAP ", "Nikto ", "OpenVAS ", "Nmap ".
    Mirrors the behavior of the user_scan_type template filter so that
    server-side generated fields (e.g., PDF detailed findings) also display
    scanner-agnostic values for non-admin users.
    """
    try:
        s = (value or "").strip()
    except Exception:
        s = ""
    if not s:
        return fallback
    low = s.lower()
    prefixes = [
        "zap",
        "nikto",
        "openvas",
        "nmap",
        "openvas-scanner",
        "openvasscanner",
        "owasp zap",
        "owasp-zap",
    ]
    for p in prefixes:
        if low.startswith(p):
            s = s[len(p):]
            s = s.lstrip("-: ")
            break
    s = s.strip()
    return s or fallback

INSTANCE_FIELD_LABELS = {
    "uri": "URI",
    "url": "URL",
    "method": "Method",
    "param": "Parameter",
    "attack": "Attack",
    "evidence": "Evidence",
    "otherinfo": "Other Info",
}


# Map scan tables to their corresponding results tables
def _result_model_for_scan_model(scan_model):
    if scan_model is WebScansDb:
        return WebScanResultsDb
    if scan_model is NetworkScanDb:
        return NetworkScanResultsDb
    if scan_model is StaticScansDb:
        return StaticScanResultsDb
    if scan_model is CloudScansDb:
        return CloudScansResultsDb
    return None
REPORT_SECTION_OPTIONS = OrderedDict(
    [
        (
            "overview",
            {
                "label": "Executive Summary",
                "description": "Totals, risk score, and severity distribution",
            },
        ),
        (
            "coverage",
            {
                "label": "Scan Coverage",
                "description": "Coverage table across active scan types",
            },
        ),
        (
            "priority_targets",
            {
                "label": "Priority Targets",
                "description": "Top assets ranked by risk weighting",
            },
        ),
        (
            "web",
            {
                "label": "Web (DAST) Findings",
                "description": "Runtime web application findings and highlights",
            },
        ),
        (
            "network",
            {
                "label": "Network Findings",
                "description": "Network scan results",
            },
        ),
        (
            "static",
            {
                "label": "Static (SAST) Findings",
                "description": "Code analysis issues captured during SAST",
            },
        ),
        (
            "cloud",
            {
                "label": "Cloud Findings",
                "description": "Cloud configuration and posture insights",
            },
        ),
    ]
)
DEFAULT_REPORT_SECTIONS = [
    key for key in REPORT_SECTION_OPTIONS.keys() if key not in ("static", "cloud")
]


SUMMARY_FIELD_OPTIONS = OrderedDict(
    [
        ("url", {"label": "URL"}),
        ("status", {"label": "Status"}),
        ("scanner", {"label": "Scanner"}),
        ("total", {"label": "Total Vulnerabilities"}),
        ("critical", {"label": "Critical"}),
        ("high", {"label": "High"}),
        ("medium", {"label": "Medium"}),
        ("low", {"label": "Low"}),
        ("info", {"label": "Info"}),
        ("duplicates", {"label": "Duplicates"}),
    ]
)
DEFAULT_SUMMARY_FIELDS = [
    "url",
    "status",
    "scanner",
    "total",
    "high",
    "medium",
    "low",
    "duplicates",
]


VULN_TABLE_FIELD_OPTIONS = OrderedDict(
    [
        ("title", {"label": "Vulnerability"}),
        ("cvss_score", {"label": "CVSS Score"}),
        ("cvss_severity", {"label": "CVSS Severity"}),
        ("mitre_techniques", {"label": "MITRE ATT&CK"}),
        ("status", {"label": "Status"}),
        ("risk", {"label": "Risk"}),
    ]
)
DEFAULT_VULN_TABLE_FIELDS = list(VULN_TABLE_FIELD_OPTIONS.keys())


VULN_META_FIELD_OPTIONS = OrderedDict(
    [
        ("title", {"label": "Vulnerability"}),
        ("risk", {"label": "Risk"}),
        ("jira_ticket", {"label": "JIRA Ticket"}),
        ("status", {"label": "Status"}),
        ("false_positive", {"label": "False Positive"}),
    ]
)
DEFAULT_VULN_META_FIELDS = ["title", "risk", "status"]


VULN_DETAIL_SECTION_OPTIONS = OrderedDict(
    [
        ("description", {"label": "Description"}),
        ("instance", {"label": "Instance"}),
        ("solution", {"label": "Solutions"}),
        ("reference", {"label": "Reference"}),
    ]
)
DEFAULT_VULN_DETAIL_SECTIONS = ["description", "solution", "reference"]


# âœ… Helper: Filter queryset by severity selection
def _filter_by_severity(qs, severities):
    if not severities:
        return qs

    # Prefer filtering by counts derived from the results table so scans
    # with empty per-scan counters are not dropped.
    res_model = _result_model_for_scan_model(qs.model)
    severities = [str(s or "").strip().lower() for s in severities]
    sev_label = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    if res_model is not None:
        base_res = res_model.objects.filter(scan_id=OuterRef("scan_id"))
        annotations = {}
        for key, label in sev_label.items():
            cnt_sq = (
                base_res.filter(severity__iexact=label)
                .values("scan_id")
                .annotate(cnt=Count("id"))
                .values("cnt")[:1]
            )
            annotations[f"res_{key}"] = Coalesce(Subquery(cnt_sq, output_field=IntegerField()), 0)
        qs = qs.annotate(**annotations)
        q = Q()
        for s in severities:
            if s in sev_label:
                q |= Q(**{f"res_{s}__gt": 0})
        return qs.filter(q) if q else qs

    # Fallback to model counters if there is no results model
    field_map = {
        "critical": "critical_vul",
        "high": "high_vul",
        "medium": "medium_vul",
        "low": "low_vul",
    }
    q = Q()
    for s in severities:
        field = field_map.get(s)
        if field:
            q |= Q(**{f"{field}__gt": 0})
    return qs.filter(q) if q else qs


# âœ… Helper: Aggregate counts and metadata for scan querysets
def _summarize_queryset(qs):
    model_fields = {field.name for field in qs.model._meta.get_fields()}

    aggregates = {
        "critical": Coalesce(Sum("critical_vul"), 0),
        "high": Coalesce(Sum("high_vul"), 0),
        "medium": Coalesce(Sum("medium_vul"), 0),
        "low": Coalesce(Sum("low_vul"), 0),
        "reported_total": Coalesce(Sum("total_vul"), 0),
    }

    timestamp_fields = [
        field for field in ("date_time", "updated_time", "created_time") if field in model_fields
    ]
    for field in timestamp_fields:
        aggregates[f"max_{field}"] = Max(field)

    aggregate_values = qs.aggregate(**aggregates)

    counts = {
        severity: int(aggregate_values.get(severity, 0) or 0) for severity in SEVERITY_ORDER
    }
    counts["total"] = sum(counts.values())
    counts["reported_total"] = int(
        aggregate_values.get("reported_total") or counts["total"]
    )

    # Fallback: some scanners donâ€™t populate per-scan severity counters
    # on their scan tables. The listing UIs derive counts from the
    # corresponding Results tables, so mirror that behavior here to avoid
    # "No scan data" even when findings exist.

    try:
        if counts["total"] <= 0:
            scan_ids = list(
                qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True)
            )
            if scan_ids:
                result_model = _result_model_for_scan_model(qs.model)
                res_qs = result_model.objects.filter(scan_id__in=scan_ids) if result_model else None
                if res_qs is None:
                    raise Exception("No result model for scan model")
                alt_counts = {
                    "critical": int(res_qs.filter(severity__iexact="Critical").count()),
                    "high": int(res_qs.filter(severity__iexact="High").count()),
                    "medium": int(res_qs.filter(severity__iexact="Medium").count()),
                    "low": int(res_qs.filter(severity__iexact="Low").count()),
                }
                alt_total = sum(alt_counts.values())
                if alt_total > 0:
                    counts.update(alt_counts)
                    counts["total"] = alt_total
                    counts["reported_total"] = int(res_qs.count())
    except Exception:
        # Keep existing counts if fallback fails for any reason
        pass

    timestamps = [
        aggregate_values.get(f"max_{field}") for field in timestamp_fields
        if aggregate_values.get(f"max_{field}")
    ]
    last_scan = max(timestamps) if timestamps else None

    # If no timestamp on the scan table, try latest finding timestamp
    try:
        if last_scan is None:
            scan_ids = list(
                qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True)
            )
            if scan_ids:
                result_model = _result_model_for_scan_model(qs.model)
                if result_model:
                    last_scan = (
                        result_model.objects.filter(scan_id__in=scan_ids)
                        .order_by("-date_time")
                        .values_list("date_time", flat=True)
                        .first()
                    )
    except Exception:
        pass

    return {
        "counts": counts,
        "asset_count": qs.count(),
        "last_scan": last_scan,
    }


def _target_snapshot(records, label_getter, limit=5):
    snapshots = []
    for record in records:
        counts = {
            severity: int(getattr(record, f"{severity}_vul", 0) or 0)
            for severity in SEVERITY_ORDER
        }
        counts["total"] = sum(counts.values())
        if counts["total"] <= 0:
            continue
        snapshots.append({"name": label_getter(record), "counts": counts})

    snapshots.sort(
        key=lambda snap: (
            snap["counts"]["critical"],
            snap["counts"]["high"],
            snap["counts"]["medium"],
            snap["counts"]["total"],
        ),
        reverse=True,
    )
    return snapshots[:limit]


def _collect_scanners(records):
    scanners = {
        getattr(record, "scanner", None)
        for record in records
        if getattr(record, "scanner", None)
    }
    return sorted(scanners)


def _collect_scan_types(records):
    types = set()
    for record in records:
        val = getattr(record, "scan_type", None)
        if val:
            types.add(val)
    # Fallback to scanner names if no scan_type recorded for a section
    if not types:
        for record in records:
            val = getattr(record, "scanner", None)
            if val:
                types.add(val)
    return sorted(types)


def _risk_score(counts):
    return sum(counts.get(severity, 0) * weight for severity, weight in SEVERITY_WEIGHTS.items())


def _risk_level(score):
    for label, threshold, css in RISK_LEVEL_SCALE:
        if score >= threshold:
            return {"label": label, "css": css}
    return {"label": "Low", "css": "success"}


CVSS_MIDPOINTS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.0,
}

def _average_cvss_from_counts(counts):
    total_count = sum(counts.get(s, 0) for s in CVSS_MIDPOINTS)
    if total_count <= 0:
        return 0.0
    weighted = sum(counts.get(s, 0) * m for s, m in CVSS_MIDPOINTS.items())
    return round(weighted / total_count, 1)


def _severity_percentages(counts):
    total = counts.get("total") or 0
    if total <= 0:
        return {severity: 0 for severity in SEVERITY_ORDER}
    return {
        severity: round(counts.get(severity, 0) * 100.0 / total, 1)
        for severity in SEVERITY_ORDER
    }


def _normalize_result_severity(value):
    normalized = (value or "").strip().lower()
    return RESULT_SEVERITY_ALIASES.get(normalized, normalized)


def _annotate_severity_rank(qs, field_name="severity"):
    clauses = [
        When(**{f"{field_name}__iexact": label}, then=Value(weight))
        for label, weight in RESULT_SEVERITY_WEIGHTS.items()
    ]
    if not clauses:
        return qs
    return qs.annotate(
        severity_rank=Case(
            *clauses,
            default=Value(0),
            output_field=IntegerField(),
        )
    )


def _field(label, value):
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return {"label": label, "value": value}


def _parse_instance_details(raw_value):
    """Return normalized table rows for instance metadata along with plain text."""
    if raw_value is None:
        return {"text": None, "rows": []}

    import ast
    import json
    import re

    if isinstance(raw_value, (dict, list)):
        candidate = raw_value
        raw_text = json.dumps(raw_value, ensure_ascii=False)
    else:
        raw_text = str(raw_value)
        stripped = raw_text.strip()
        candidate = None
        if stripped:
            try:
                candidate = json.loads(stripped)
            except Exception:
                candidate = None
            if candidate is None:
                literal_source = stripped.lstrip(", ")
                if literal_source:
                    if not literal_source.startswith("[") and not literal_source.startswith("{"):
                        literal_source = f"[{literal_source}]"
                    try:
                        candidate = ast.literal_eval(literal_source)
                    except Exception:
                        candidate = None
                raw_text = literal_source or raw_text

    rows = []

    def add_row(key, value):
        if value is None:
            return
        text_value = str(value).strip()
        if not text_value:
            return
        label = INSTANCE_FIELD_LABELS.get(key.lower(), key.title())
        rows.append({"label": label, "value": text_value})

    if isinstance(candidate, dict):
        handled = set()
        for key in INSTANCE_FIELD_LABELS:
            if key in candidate:
                add_row(key, candidate[key])
                handled.add(key)
        for key, value in candidate.items():
            if key in handled:
                continue
            add_row(key, value)
    elif isinstance(candidate, list):
        for item in candidate:
            if isinstance(item, dict):
                for key, value in item.items():
                    add_row(key, value)
            else:
                add_row("Value", item)
    else:
        text = raw_text
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</?[^>]+>", "", text)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                add_row(key.strip(), value.strip())
            elif "=" in line:
                key, value = line.split("=", 1)
                add_row(key.strip(), value.strip())

    if rows:
        return {"text": None, "rows": rows}
    return {"text": raw_text, "rows": rows}


def _normalize_selection(values, allowed, default=None):
    normalized = [value for value in values if value in allowed]
    if normalized:
        return normalized
    if default is not None:
        return list(default)
    return []


def _annotate_duplicate_fields(grouped):
    trackers = {
        "description": {},
        "solution": {},
        "instance": {},
        "reference": {},
    }

    for group in grouped:
        group_label = group.get("label", "")
        for item in group.get("items", []):
            duplicates = []
            title = item.get("title") or "this finding"
            origin = f"{group_label} â€º {title}" if group_label else title

            for field_key, tracker in trackers.items():
                value = (item.get(field_key) or "").strip()
                if not value:
                    continue
                key = (field_key, value)
                if key in tracker:
                    duplicates.append(
                        {
                            "field": field_key,
                            "reference": tracker[key],
                        }
                    )
                    item[field_key] = None
                    if field_key == "instance":
                        item["instance_rows"] = []
                    if field_key == "reference" and item.get("fields"):
                        item["fields"] = [
                            field
                            for field in item["fields"]
                            if not (field.get("label") == "Reference" and (field.get("value") or "").strip() == value)
                        ]
                else:
                    tracker[key] = origin

            if duplicates:
                item["duplicate_notes"] = duplicates

    return grouped


def _mitre_csv_value(techniques):
    return "; ".join(t["id"] for t in techniques if "id" in t)


def _serialize_web_result(record):
    fields = [
        _field("Affected URL", record.url),
        _field("Scanner", record.scanner),
        _field("Project", record.project.project_name if getattr(record, "project", None) else None),
        _field("Reference", record.reference),
    ]
    fields = [f for f in fields if f]
    severity = _normalize_result_severity(record.severity)
    severity_label = record.severity or SEVERITY_DISPLAY.get(severity, None)
    instance_info = _parse_instance_details(getattr(record, "instance", None))
    cvss_info = CvssCalculator().compute(severity=severity_label)
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "cvss_score": cvss_info["score"],
        "cvss_severity": cvss_info["severity"],
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": instance_info["text"],
        "instance_rows": instance_info["rows"],
        "reference": record.reference,
        "scanner": record.scanner,
        "url": record.url,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
        "mitre_has_data": getattr(record, "mitre_has_data", False),
        "mitre_techniques": getattr(record, "mitre_techniques", []),
    }


def _serialize_network_result(record):
    location = ":".join(filter(None, [record.ip or None, record.port or None]))
    fields = [
        _field("Target", record.ip),
        _field("Port", record.port),
        _field("Scanner", record.scanner),
        _field("Project", record.project.project_name if getattr(record, "project", None) else None),
        _field("Location", location if location else None),
    ]
    fields = [f for f in fields if f]
    severity = _normalize_result_severity(record.severity)
    severity_label = record.severity or SEVERITY_DISPLAY.get(severity, None)
    cvss_info = CvssCalculator().compute(severity=severity_label)
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "cvss_score": cvss_info["score"],
        "cvss_severity": cvss_info["severity"],
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": None,
        "instance_rows": [],
        "reference": None,
        "scanner": record.scanner,
        "url": record.ip,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
        "mitre_has_data": getattr(record, "mitre_has_data", False),
        "mitre_techniques": getattr(record, "mitre_techniques", []),
    }


def _serialize_static_result(record):
    location = record.filePath or record.fileName
    fields = [
        _field("File", record.fileName),
        _field("Path", record.filePath),
        _field("Scanner", record.scanner),
        _field("Project", record.project.project_name if getattr(record, "project", None) else None),
        _field("Reference", record.references),
    ]
    fields = [f for f in fields if f]
    severity = _normalize_result_severity(record.severity)
    severity_label = record.severity or SEVERITY_DISPLAY.get(severity, None)
    instance_info = _parse_instance_details(location)
    cvss_info = CvssCalculator().compute(severity=severity_label)
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "cvss_score": cvss_info["score"],
        "cvss_severity": cvss_info["severity"],
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": instance_info["text"],
        "instance_rows": instance_info["rows"],
        "reference": record.references,
        "scanner": record.scanner,
        "url": location,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
        "mitre_has_data": getattr(record, "mitre_has_data", False),
        "mitre_techniques": getattr(record, "mitre_techniques", []),
    }


def _serialize_cloud_result(record):
    fields = [
        _field("Cloud Account", record.cloudAccountId),
        _field("Resource", record.resourceName),
        _field("Resource ID", record.resourceId),
        _field("Cloud Provider", record.cloudType),
        _field("Scanner", record.scanner),
        _field("Project", record.project.project_name if getattr(record, "project", None) else None),
        _field("Reference", record.references),
    ]
    fields = [f for f in fields if f]
    severity = _normalize_result_severity(record.severity)
    severity_label = record.severity or SEVERITY_DISPLAY.get(severity, None)
    instance_info = _parse_instance_details(getattr(record, "resourceName", None))
    cvss_info = CvssCalculator().compute(severity=severity_label)
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "cvss_score": cvss_info["score"],
        "cvss_severity": cvss_info["severity"],
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": instance_info["text"],
        "instance_rows": instance_info["rows"],
        "reference": record.references,
        "scanner": record.scanner,
        "url": getattr(record, "resourceId", None) or getattr(record, "resourceName", None),
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
        "mitre_has_data": getattr(record, "mitre_has_data", False),
        "mitre_techniques": getattr(record, "mitre_techniques", []),
    }


def _collect_detail_findings(scan_qs, severities, config, request=None, status=None):
    scan_ids = list(
        scan_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True)
    )
    if not scan_ids:
        return {"total": 0, "grouped": []}

    severity_field = config.get("severity_field", "severity")
    # Build a map of scan_id -> scan_type from the base scan queryset so we can
    # reference it while serializing individual findings.
    try:
        scan_type_map = {
            str(row["scan_id"]): row.get("scan_type") for row in
            scan_qs.values("scan_id", "scan_type")
        }
    except Exception:
        scan_type_map = {}
    # Determine if caller should see scanner names (admins) or scan types (others)
    try:
        is_admin = bool(getattr(getattr(request, 'user', None), 'is_superuser', False)) or (
            str(getattr(getattr(request, 'user', None), 'role', '')) == 'Admin'
        )
    except Exception:
        is_admin = False
    result_qs = config["model"].objects.filter(scan_id__in=scan_ids)

    # Optional status filter: when provided as 'open' or 'closed',
    # limit results so counts and detailed rows stay consistent.
    status_norm = (status or "").strip().lower() if status is not None else None
    if status_norm in {"open", "closed"}:
        result_qs = result_qs.filter(vuln_status__iexact=status_norm)

    if severities:
        severity_filter = Q()
        for severity in severities:
            severity_filter |= Q(**{f"{severity_field}__iexact": severity})
        if severity_filter:
            result_qs = result_qs.filter(severity_filter)

    if config.get("select_related"):
        result_qs = result_qs.select_related(*config["select_related"])

    if config.get("only"):
        result_qs = result_qs.only(*config["only"])

    result_qs = _annotate_severity_rank(result_qs, field_name=severity_field)

    order_by = config.get("order_by")
    if not order_by:
        order_by = ["-severity_rank"]
        date_field = config.get("date_field")
        if date_field:
            order_by.append(f"-{date_field}")
    result_qs = result_qs.order_by(*order_by)

    max_total = config.get("max_total", 200)
    max_per_group = config.get("max_per_group", 50)

    grouped_map = OrderedDict((severity, []) for severity in RESULT_SEVERITY_ORDER)
    severity_counts_total = {severity: 0 for severity in grouped_map}
    severity_counts_shown = {severity: 0 for severity in grouped_map}
    other_items = []
    other_total = 0
    other_shown = 0

    serializer = config["serializer"]
    emitted = 0  # number of items rendered into table/detail blocks
    truncated = False  # whether we skipped unique findings because of limits
    timeline_map = OrderedDict()
    date_field = config.get("date_field")
    seen_titles = set()
    total_records = 0  # unique findings by vulnerability title

    for record in result_qs.iterator():
        severity = _normalize_result_severity(getattr(record, severity_field, None))
        entry = serializer(record)

        # Skip duplicate vulnerability names (keep the first/highest-priority entry)
        title_key = (entry.get("title") or "").strip().lower()
        if title_key and title_key in seen_titles:
            continue
        if title_key:
            seen_titles.add(title_key)

        # For Organization Admin and User: replace "Scanner" field with
        # "Scan Type" using the parent scan row's scan_type, when available.
        if not is_admin:
            sid = str(getattr(record, 'scan_id', ''))
            scan_type_val = scan_type_map.get(sid) or None
            fields = entry.get("fields", []) or []
            new_fields = []
            for f in fields:
                if (f or {}).get("label") == "Scanner":
                    label = "Scan Type"
                    # Prefer the scan_type from the parent scan row; fall back to
                    # the original value and strip scanner name prefixes so
                    # non-admin users only see the functional type (e.g., "Active").
                    raw_value = scan_type_val or f.get("value")
                    value = _strip_scanner_prefix(raw_value, fallback="Scan")
                    if value:
                        new_fields.append({"label": label, "value": value})
                else:
                    new_fields.append(f)
            entry["fields"] = new_fields

        if date_field:
            detected = getattr(record, date_field, None)
            if detected:
                label = detected.strftime("%Y-%m")
                timeline_map[label] = timeline_map.get(label, 0) + 1
        total_records += 1

        # Track total counts by severity, even when we do not render the row
        if severity in grouped_map:
            severity_counts_total[severity] += 1
        else:
            other_total += 1

        # Enforce global and per-group render limits without losing count accuracy
        if max_total and emitted >= max_total:
            truncated = True
            continue

        if severity in grouped_map:
            if max_per_group and severity_counts_shown[severity] >= max_per_group:
                truncated = True
                continue
            grouped_map[severity].append(entry)
            severity_counts_shown[severity] += 1
        else:
            if max_per_group and other_shown >= max_per_group:
                truncated = True
                continue
            other_items.append(entry)
            other_shown += 1

        emitted += 1

    if total_records == 0:
        return {"total": 0, "grouped": []}

    grouped = []
    for severity, items in grouped_map.items():
        total = severity_counts_total.get(severity, 0)
        if total:
            grouped.append(
                {
                    "slug": severity,
                    "label": SEVERITY_DISPLAY.get(severity, severity.title()),
                    "items": items,
                    "count": total,
                    "shown_count": len(items),
                    "truncated": total > len(items),
                }
            )

    if other_total > 0 or other_items:
        grouped.append(
            {
                "slug": "other",
                "label": "Other",
                "items": other_items,
                "count": max(other_total, len(other_items)),
                "shown_count": len(other_items),
                "truncated": max(other_total, len(other_items)) > len(other_items),
            }
        )

    grouped = _annotate_duplicate_fields(grouped)

    severity_segments = []
    gradient_parts = []
    chart_total = total_records
    if chart_total > 0:
        start = 0.0
        for severity in RESULT_SEVERITY_ORDER:
            count = severity_counts_total.get(severity, 0)
            if count <= 0:
                continue
            percent = round(count * 100.0 / chart_total, 2)
            end = min(start + percent, 100.0)
            color = SEVERITY_COLORS.get(severity, "#1f2937")
            severity_segments.append(
                {
                    "slug": severity,
                    "label": SEVERITY_DISPLAY.get(severity, severity.title()),
                    "count": count,
                    "percent": percent,
                    "start": start,
                    "end": end,
                    "color": color,
                }
            )
            gradient_parts.append(f"{color} {start}% {end}%")
            start = end

        other_total = chart_total - sum(seg["count"] for seg in severity_segments)
        if other_total > 0:
            percent = round(other_total * 100.0 / chart_total, 2)
            end = min(start + percent, 100.0)
            color = SEVERITY_COLORS.get("other")
            severity_segments.append(
                {
                    "slug": "other",
                    "label": "Other",
                    "count": other_total,
                    "percent": percent,
                    "start": start,
                    "end": end,
                    "color": color,
                }
            )
            gradient_parts.append(f"{color} {start}% {end}%")
            start = end

    timeline_points = []
    timeline_bars = []
    if timeline_map:
        unique_items = sorted(timeline_map.items())
        max_count = max(timeline_map.values())
        count_items = len(unique_items)
        bar_width = 100.0 / max(count_items, 1)
        timeline_points = []
        for idx, (label, count) in enumerate(unique_items):
            x = idx * bar_width + bar_width * 0.15
            width = bar_width * 0.7
            height = ((count / max_count) * 80.0) if max_count > 0 else 0
            y = 90.0 - height
            timeline_points.append({"label": label, "count": count, "x": x + width / 2, "y": y})
            timeline_bars.append({
                "label": label,
                "count": count,
                "x": x,
                "y": y,
                "width": width,
                "height": height,
            })
    else:
        max_count = 0

    chart = {
        "total": chart_total,
        "severity": {
            "segments": severity_segments,
            "gradient": ", ".join(gradient_parts),
        },
        "timeline": {
            "points": timeline_points,
            "bars": timeline_bars,
            "max": max_count,
        },
    }

    return {
        "total": total_records,
        "grouped": grouped,
        "truncated": truncated or any(group["truncated"] for group in grouped),
        "chart": chart,
    }


DETAIL_CONFIGS = {
    "web": {
        "model": WebScanResultsDb,
        "serializer": _serialize_web_result,
        "select_related": ["project"],
        "date_field": "date_time",
        "only": (
            "title",
            "severity",
            "description",
            "solution",
            "url",
            "instance",
            "reference",
            "scanner",
            "project__project_name",
            "date_time",
            "vuln_id",
            "vuln_status",
            "jira_ticket",
            "false_positive",
            "vuln_duplicate",
            "dup_hash",
            "note",
        ),
        "max_total": 150,
        "max_per_group": 40,
    },
    "network": {
        "model": NetworkScanResultsDb,
        "serializer": _serialize_network_result,
        "select_related": ["project"],
        "date_field": "date_time",
        "only": (
            "title",
            "severity",
            "description",
            "solution",
            "ip",
            "port",
            "scanner",
            "project__project_name",
            "date_time",
            "vuln_id",
            "vuln_status",
            "jira_ticket",
            "false_positive",
            "vuln_duplicate",
            "dup_hash",
            "note",
        ),
        "max_total": 150,
        "max_per_group": 40,
    },
    "static": {
        "model": StaticScanResultsDb,
        "serializer": _serialize_static_result,
        "select_related": ["project"],
        "date_field": "date_time",
        "only": (
            "title",
            "severity",
            "description",
            "solution",
            "fileName",
            "filePath",
            "references",
            "scanner",
            "project__project_name",
            "date_time",
            "vuln_id",
            "vuln_status",
            "jira_ticket",
            "false_positive",
            "vuln_duplicate",
            "dup_hash",
            "note",
        ),
        "max_total": 150,
        "max_per_group": 40,
    },
    "cloud": {
        "model": CloudScansResultsDb,
        "serializer": _serialize_cloud_result,
        "select_related": ["project"],
        "date_field": "date_time",
        "only": (
            "title",
            "severity",
            "description",
            "solution",
            "cloudAccountId",
            "resourceName",
            "resourceId",
            "cloudType",
            "references",
            "scanner",
            "project__project_name",
            "date_time",
            "vuln_id",
            "vuln_status",
            "jira_ticket",
            "false_positive",
            "vuln_duplicate",
            "dup_hash",
            "note",
        ),
        "max_total": 150,
        "max_per_group": 40,
    },
}


def _build_scan_summary(qs, label, slug, label_getter, severities=None, detail_config=None, request=None, status=None):
    summary = _summarize_queryset(qs)
    records = list(qs)
    summary.update(
        {
            "label": label,
            "slug": slug,
            "records": records,
            "scanners": _collect_scanners(records),
            "scan_types": _collect_scan_types(records),
            "top_targets": _target_snapshot(records, label_getter),
            "findings": _collect_detail_findings(qs, severities, detail_config, request=request, status=status)
            if detail_config
            else None,
        }
    )
    return summary


def _merge_counts(scan_summaries):
    totals = {severity: 0 for severity in SEVERITY_ORDER}
    totals["total"] = 0
    for summary in scan_summaries:
        for severity in SEVERITY_ORDER:
            totals[severity] += summary["counts"].get(severity, 0)
        totals["total"] += summary["counts"].get("total", 0)
    return totals


def _empty_report_payload(projects, selected_projects=None, all_projects_selected=False):
    selected_projects = list(selected_projects or [])
    single_project = selected_projects[0] if len(selected_projects) == 1 else None
    overall_counts = {severity: 0 for severity in SEVERITY_ORDER}
    overall_counts["total"] = 0
    return {
        "selected_project": single_project,
        "selected_projects": selected_projects,
        "selected_project_names": [project.project_name for project in selected_projects],
        "all_projects_selected": all_projects_selected,
        "projects": projects,
        "web_results": [],
        "network_results": [],
        "static_results": [],
        "cloud_results": [],
        "scan_summaries": [],
        "scan_summary_map": {},
        "overall_counts": overall_counts,
        "severity_percentages": {severity: 0 for severity in SEVERITY_ORDER},
        "risk_overview": {"score": 0, "label": "Low", "css": "success"},
        "priority_targets": [],
        "has_scan_data": False,
    }


# âœ… Helper: Build filtered results for template
def _collect_report_data(
    request=None,
    project_ids=None,
    scan_types=None,
    severities=None,
    sections=None,
    projects=None,
    selected_projects=None,
    all_projects_selected=False,
    scan_urls=None,
    all_urls_selected=False,
    infra_targets=None,
    all_infra_selected=False,
    static_targets=None,
    all_static_selected=False,
    cloud_targets=None,
    all_cloud_selected=False,
    status=None,
):
    scan_types = scan_types or []
    severities = severities or []
    # Normalize section keys to new slugs (web/network)
    SECTION_KEY_ALIASES = {"dynamic": "web", "infrastructure": "network"}
    section_keys = list(sections) if sections else DEFAULT_REPORT_SECTIONS
    section_keys = [SECTION_KEY_ALIASES.get(k, k) for k in section_keys]
    # Hide static and cloud sections from rendering
    section_keys = [k for k in section_keys if k not in ('static', 'cloud')]
    section_set = set(section_keys)

    selected_projects = list(selected_projects or [])

    if not selected_projects and project_ids and not all_projects_selected:
        ids = project_ids
        if isinstance(ids, (str, int)):
            ids = [str(ids)]
        selected_projects = list(ProjectDb.objects.filter(pk__in=ids))

    if projects is None:
        projects = ProjectDb.objects.all()

    single_project = selected_projects[0] if len(selected_projects) == 1 else None

    def _with_projects(queryset):
        if selected_projects and not all_projects_selected:
            return queryset.filter(project__in=selected_projects)
        return queryset

    # Determine user/org and admin status for scoping
    org = getattr(getattr(request, 'user', None), 'organization', None) if request else None
    try:
        is_admin = (
            str(getattr(getattr(request, 'user', None), 'role', '')) == 'Admin'
        ) or bool(getattr(getattr(request, 'user', None), 'is_superuser', False))
    except Exception:
        is_admin = False
    # For the report view, force owner-only scoping for all roles
    is_admin = False
    # Enforce per-user isolation for the report UI: regardless of role,
    # scope selectable projects and resources to the current user only.
    is_admin = False

    include_web = (
        "web" in section_set
        and (
            not scan_types
            or "web" in scan_types
            or "dynamic" in scan_types
        )
    )
    include_network = (
        "network" in section_set
        and (
            not scan_types
            or "network" in scan_types
            or "infrastructure" in scan_types
        )
    )
    include_static = (
        "static" in section_set
        and (not scan_types or "static" in scan_types)
    )
    include_cloud = (
        "cloud" in section_set
        and (not scan_types or "cloud" in scan_types)
    )
    scan_urls = list(scan_urls or [])
    infra_targets = list(infra_targets or [])
    static_targets = list(static_targets or [])
    cloud_targets = list(cloud_targets or [])

    # âœ… Query + filter for each scan type
    web_qs = WebScansDb.objects.none()
    if include_web:
        base_web = WebScansDb.objects.all()
        if org is not None:
            base_web = base_web.filter(organization=org)
        base_web = base_web.filter(created_by=getattr(request, 'user', None))
        web_qs = _with_projects(base_web)
        # Apply severity filter first (preferred path)
        web_qs = _filter_by_severity(web_qs, severities)
        if scan_urls and not all_urls_selected:
            web_qs = web_qs.filter(scan_url__in=scan_urls)
        # Fallback: if no scans matched after severity filtering but a specific
        # target URL was selected, relax the severity filter so the report still
        # shows the scans and derives counts from results.
        try:
            if (scan_urls and not all_urls_selected) and not web_qs.exists():
                # Bypass project scoping if it yields nothing for an explicitly
                # selected URL; keep org/owner scoping intact.
                relaxed = base_web
                web_qs = relaxed.filter(scan_url__in=scan_urls)
        except Exception:
            pass

    network_qs = NetworkScanDb.objects.none()
    if include_network:
        base_network = NetworkScanDb.objects.all()
        if org is not None:
            base_network = base_network.filter(organization=org)
        base_network = base_network.filter(created_by=getattr(request, 'user', None))
        network_qs = _with_projects(base_network)
        network_qs = _filter_by_severity(network_qs, severities)
        if infra_targets and not all_infra_selected:
            network_qs = network_qs.filter(ip__in=infra_targets)
        # Fallback: relax severity if target filters are present but nothing matched
        try:
            if (infra_targets and not all_infra_selected) and not network_qs.exists():
                relaxed = base_network
                network_qs = relaxed.filter(ip__in=infra_targets)
        except Exception:
            pass

    static_qs = StaticScansDb.objects.none()
    if include_static:
        base_static = StaticScansDb.objects.all()
        if org is not None:
            base_static = base_static.filter(organization=org)
        base_static = base_static.filter(created_by=getattr(request, 'user', None))
        static_qs = _with_projects(base_static)
        static_qs = _filter_by_severity(static_qs, severities)
        if static_targets and not all_static_selected:
            from django.db.models import Q as _Q
            static_qs = static_qs.filter(_Q(project_name__in=static_targets) | _Q(project__project_name__in=static_targets))
        try:
            if (static_targets and not all_static_selected) and not static_qs.exists():
                relaxed = base_static
                from django.db.models import Q as _Q
                static_qs = relaxed.filter(_Q(project_name__in=static_targets) | _Q(project__project_name__in=static_targets))
        except Exception:
            pass

    cloud_qs = CloudScansDb.objects.none()
    if include_cloud:
        base_cloud = CloudScansDb.objects.all()
        if org is not None:
            base_cloud = base_cloud.filter(organization=org)
        base_cloud = base_cloud.filter(created_by=getattr(request, 'user', None))
        cloud_qs = _with_projects(base_cloud)
        cloud_qs = _filter_by_severity(cloud_qs, severities)
        if cloud_targets and not all_cloud_selected:
            cloud_qs = cloud_qs.filter(cloudAccountId__in=cloud_targets)
        try:
            if (cloud_targets and not all_cloud_selected) and not cloud_qs.exists():
                relaxed = base_cloud
                cloud_qs = relaxed.filter(cloudAccountId__in=cloud_targets)
        except Exception:
            pass

    scan_summaries = []

    web_results = []
    if include_web:
        web_summary = _build_scan_summary(
            web_qs,
            label="Web Application Scans",
            slug="web",
            label_getter=lambda record: record.scan_url
            or (record.project.project_name if record.project else "Unassigned Target"),
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("web"), request=request, status=status,
        )
        web_results = web_summary.pop("records", [])
        scan_summaries.append(web_summary)

    network_results = []
    if include_network:
        network_summary = _build_scan_summary(
            network_qs,
            label="Network Scans",
            slug="network",
            label_getter=lambda record: record.ip or "Unassigned Target",
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("network"), request=request, status=status,
        )
        network_results = network_summary.pop("records", [])
        scan_summaries.append(network_summary)

    static_results = []
    if include_static:
        static_summary = _build_scan_summary(
            static_qs,
            label="Static Analysis Scans",
            slug="static",
            label_getter=lambda record: record.project_name
            or (record.project.project_name if record.project else "Unassigned Project"),
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("static"), request=request, status=status,
        )
        static_results = static_summary.pop("records", [])
        scan_summaries.append(static_summary)

    cloud_results = []
    if include_cloud:
        cloud_summary = _build_scan_summary(
            cloud_qs,
            label="Cloud Security Scans",
            slug="cloud",
            label_getter=lambda record: record.cloudAccountId
            or (record.project.project_name if record.project else "Unassigned Account"),
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("cloud"), request=request, status=status,
        )
        cloud_results = cloud_summary.pop("records", [])
        scan_summaries.append(cloud_summary)

    overall_counts = (
        _merge_counts(scan_summaries)
        if scan_summaries
        else {severity: 0 for severity in SEVERITY_ORDER}
    )
    if scan_summaries:
        overall_counts["total"] = sum(
            summary["counts"]["total"] for summary in scan_summaries
        )
    else:
        overall_counts["total"] = 0

    severity_percentages = _severity_percentages(overall_counts)
    score = _risk_score(overall_counts)
    risk = _risk_level(score)

    priority_targets = []
    if "priority_targets" in section_set:
        for summary in scan_summaries:
            for target in summary.get("top_targets", []):
                entry_counts = target["counts"]
                priority_targets.append(
                    {
                        "type": summary["label"],
                        "name": target["name"],
                        "counts": entry_counts,
                        "score": _risk_score(entry_counts),
                        "cvss_score": _average_cvss_from_counts(entry_counts),
                    }
                )

        priority_targets.sort(
            key=lambda target: (
                target["score"],
                target["counts"]["critical"],
                target["counts"]["high"],
            ),
            reverse=True,
        )
        priority_targets = priority_targets[:5]

    summary_map = {summary["slug"]: summary for summary in scan_summaries}

    selected_project_names = [project.project_name for project in selected_projects]

    # Diagnostics: build warnings when nothing matches per section
    no_scan_warnings = []
    def _project_scope_label():
        return " in the selected project(s)" if (selected_projects and not all_projects_selected) else " for the current scope"

    if include_web and not web_results:
        if scan_urls or all_urls_selected:
            no_scan_warnings.append("No web scans found for the selected URL(s).")
        else:
            no_scan_warnings.append("No web scans found" + _project_scope_label() + ".")
    if include_network and not network_results:
        if infra_targets or all_infra_selected:
            no_scan_warnings.append("No network scans found for the selected target IPs.")
        else:
            no_scan_warnings.append("No network scans found" + _project_scope_label() + ".")
    if include_static and not static_results:
        if static_targets or all_static_selected:
            no_scan_warnings.append("No static analysis scans found for the selected projects.")
        else:
            no_scan_warnings.append("No static analysis scans found" + _project_scope_label() + ".")
    if include_cloud and not cloud_results:
        if cloud_targets or all_cloud_selected:
            no_scan_warnings.append("No cloud scans found for the selected cloud accounts.")
        else:
            no_scan_warnings.append("No cloud scans found" + _project_scope_label() + ".")

    # Debug counts: scans matched and findings matched per type
    debug_counts = []
    def _severity_filter_for_results(res_qs):
        if not severities:
            return res_qs
        filt = Q()
        for s in severities:
            lab = str(s or "").strip().lower()
            if lab == "critical":
                filt |= Q(severity__iexact="Critical")
            elif lab == "high":
                filt |= Q(severity__iexact="High")
            elif lab == "medium":
                filt |= Q(severity__iexact="Medium")
            elif lab == "low":
                filt |= Q(severity__iexact="Low")
        return res_qs.filter(filt) if filt else res_qs

    if include_web:
        web_ids = list(web_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True))
        d_res = _severity_filter_for_results(WebScanResultsDb.objects.filter(scan_id__in=web_ids))
        debug_counts.append({"type": "web", "scans": len(set(web_ids)), "findings": d_res.count()})
    if include_network:
        net_ids = list(network_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True))
        n_res = _severity_filter_for_results(NetworkScanResultsDb.objects.filter(scan_id__in=net_ids))
        debug_counts.append({"type": "network", "scans": len(set(net_ids)), "findings": n_res.count()})
    if include_static:
        sta_ids = list(static_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True))
        s_res = _severity_filter_for_results(StaticScanResultsDb.objects.filter(scan_id__in=sta_ids))
        debug_counts.append({"type": "static", "scans": len(set(sta_ids)), "findings": s_res.count()})
    if include_cloud:
        clo_ids = list(cloud_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True))
        c_res = _severity_filter_for_results(CloudScansResultsDb.objects.filter(scan_id__in=clo_ids))
        debug_counts.append({"type": "cloud", "scans": len(set(clo_ids)), "findings": c_res.count()})

    # Human-friendly filter summary lines
    type_labels = []
    if include_web:
        type_labels.append("Web")
    if include_network:
        type_labels.append("Network")
    if include_static:
        type_labels.append("Static")
    if include_cloud:
        type_labels.append("Cloud")
    filter_summary = []
    filter_summary.append("Projects: " + (", ".join(selected_project_names) if (selected_project_names and not all_projects_selected) else "All Projects"))
    filter_summary.append("Scan types: " + (", ".join(type_labels) if type_labels else "None"))
    if include_web:
        filter_summary.append("Web URLs: " + ("All URLs" if all_urls_selected else (", ".join(scan_urls) if scan_urls else "None")))
    if include_network:
        filter_summary.append("Network Targets: " + ("All Targets" if all_infra_selected else (", ".join(infra_targets) if infra_targets else "None")))
    if include_static:
        filter_summary.append("Static Projects: " + ("All" if all_static_selected else (", ".join(static_targets) if static_targets else "None")))
    if include_cloud:
        filter_summary.append("Cloud Accounts: " + ("All" if all_cloud_selected else (", ".join(cloud_targets) if cloud_targets else "None")))
    filter_summary.append("Severities: " + (", ".join(severities) if severities else "All"))

    # --- AI-Assisted Analysis (rule-based prioritization + NLG) ---
    scorer = RiskScorer()
    prioritizer = VulnerabilityPrioritizer()
    nlg = ReportNarrativeGenerator()

    analysis_score = scorer.score_summary(overall_counts)
    raw_findings = []
    if "priority_targets" in section_set:
        for target in priority_targets:
            target["analysis_score"] = scorer.score_summary(target.get("counts", {}))
        for slug, summary in (summary_map or {}).items():
            for group in (summary.get("findings", {}).get("grouped", []) or []):
                for item in (group.get("items", []) or []):
                    raw_findings.append(item)

    # --- NVD CVSS Enrichment ---
    nvd = NvdLookup()
    for item in raw_findings:
        nvd.enrich_finding(item)

    priority_analysis = prioritizer.prioritize_scan_summary(raw_findings)

    scan_type_labels = [s["label"] for s in (scan_summaries or []) if s.get("label")]
    executive_narrative = nlg.executive_summary(
        total_findings=overall_counts.get("total", 0),
        severity_counts=overall_counts,
        risk_tier=analysis_score.tier.value,
        risk_score=analysis_score.score,
        scan_types=scan_type_labels,
        project_names=selected_project_names,
        top_priorities=priority_analysis.get("top_priorities"),
    )

    return {
        "selected_project": single_project,
        "selected_projects": selected_projects,
        "selected_project_names": selected_project_names,
        "all_projects_selected": all_projects_selected,
        "projects": projects,
        "web_results": web_results,
        "network_results": network_results,
        "static_results": static_results,
        "cloud_results": cloud_results,
        "scan_summaries": scan_summaries if "coverage" in section_set else [],
        "scan_summary_map": summary_map,
        "overall_counts": overall_counts,
        "severity_percentages": severity_percentages,
        "risk_overview": {
            "score": analysis_score.score,
            "label": analysis_score.tier.value.capitalize(),
            "css": risk["css"],
            "priority_score": analysis_score.score,
            "priority_tier": analysis_score.tier.value,
            "confidence": analysis_score.confidence,
        },
        "priority_targets": priority_targets if "priority_targets" in section_set else [],
        "priority_analysis": priority_analysis,
        "executive_narrative": executive_narrative,
        "has_scan_data": overall_counts.get("total", 0) > 0,
        "no_scan_warnings": no_scan_warnings,
        "debug_counts": debug_counts,
        "filter_summary": filter_summary,
    }


# âœ… Main: Generate & preview report
def _build_query_string(
    project_ids,
    scan_types,
    severities,
    sections,
    summary_fields,
    vuln_table_fields,
    vuln_meta_fields,
    vuln_detail_sections,
    # New optional filters
    scan_urls=None,
    all_urls_selected=False,
    infra_targets=None,
    all_infra_selected=False,
    static_targets=None,
    all_static_selected=False,
    cloud_targets=None,
    all_cloud_selected=False,
):
    params = []
    if project_ids:
        if isinstance(project_ids, (str, int)):
            params.append(("project_id", project_ids))
        else:
            for value in project_ids:
                params.append(("project_id", value))
    for value in scan_types:
        params.append(("scan_types", value))
    for value in severities:
        params.append(("severity", value))
    for value in sections:
        params.append(("sections", value))
    for value in summary_fields:
        params.append(("summary_fields", value))
    for value in vuln_table_fields:
        params.append(("vuln_table_fields", value))
    for value in vuln_meta_fields:
        params.append(("vuln_meta_fields", value))
    for value in vuln_detail_sections:
        params.append(("vuln_detail_sections", value))
    # New: append resource filters
    scan_urls = list(scan_urls or [])
    infra_targets = list(infra_targets or [])
    static_targets = list(static_targets or [])
    cloud_targets = list(cloud_targets or [])

    if all_urls_selected:
        params.append(("scan_urls", "__all__"))
    for value in scan_urls:
        params.append(("scan_urls", value))

    if all_infra_selected:
        params.append(("infra_targets", "__all__"))
        params.append(("network_targets", "__all__"))
    for value in infra_targets:
        params.append(("infra_targets", value))
        params.append(("network_targets", value))

    if all_static_selected:
        params.append(("static_targets", "__all__"))
    for value in static_targets:
        params.append(("static_targets", value))

    if all_cloud_selected:
        params.append(("cloud_targets", "__all__"))
    for value in cloud_targets:
        params.append(("cloud_targets", value))

    return urlencode(params)


def generate_report(request):
    requested_project_ids = request.GET.getlist("project_id")
    if not requested_project_ids:
        single_project = request.GET.get("project_id")
        if single_project:
            requested_project_ids = [single_project]

    all_projects_selected = "__all__" in requested_project_ids
    project_filter_ids = [str(pid) for pid in requested_project_ids if pid and pid != "__all__"]
    if all_projects_selected:
        project_filter_ids = []
    selected_project_tokens = list(requested_project_ids)

    # Scan types selection
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")
    section_selection = request.GET.getlist("sections")
    preview_requested = request.GET.get("preview") == "1"
    # Status filter for detailed findings. Default to 'open' so non-admin
    # roles see the same scope as Admin (open issues only). Accept 'all' to
    # disable filtering or 'closed' for closed-only if needed later.
    raw_status = (request.GET.get("status") or "open").strip().lower()
    status_filter = None if raw_status == "all" else raw_status

    # Scope projects by organization and ownership for non-admins
    try:
        is_admin = (
            str(getattr(getattr(request, 'user', None), 'role', '')) == 'Admin'
        ) or bool(getattr(getattr(request, 'user', None), 'is_superuser', False))
    except Exception:
        is_admin = False
    org = getattr(getattr(request, 'user', None), 'organization', None)

    allowed_projects = ProjectDb.objects.all()
    # Scope to current user's organization and ownership (owner-only visibility)
    if org is not None:
        allowed_projects = allowed_projects.filter(organization=org)
    allowed_projects = allowed_projects.filter(created_by=getattr(request, 'user', None))

    projects = allowed_projects
    selected_projects_qs = allowed_projects.filter(pk__in=project_filter_ids) if project_filter_ids else ProjectDb.objects.none()
    selected_projects = list(selected_projects_qs)

    # Determine organization for later use
    org = getattr(getattr(request, 'user', None), 'organization', None)

    # Normalize legacy section keys to new slugs
    SECTION_KEY_ALIASES = {"dynamic": "web", "infrastructure": "network"}
    selected_sections = [SECTION_KEY_ALIASES.get(s, s) for s in (section_selection or DEFAULT_REPORT_SECTIONS)]
    selected_sections = [s for s in selected_sections if s not in ('static', 'cloud')]
    summary_fields = _normalize_selection(
        request.GET.getlist("summary_fields"),
        SUMMARY_FIELD_OPTIONS,
    )
    vuln_table_fields = _normalize_selection(
        request.GET.getlist("vuln_table_fields"),
        VULN_TABLE_FIELD_OPTIONS,
    )
    vuln_meta_fields = _normalize_selection(
        request.GET.getlist("vuln_meta_fields"),
        VULN_META_FIELD_OPTIONS,
    )
    vuln_detail_sections = _normalize_selection(
        request.GET.getlist("vuln_detail_sections"),
        VULN_DETAIL_SECTION_OPTIONS,
    )

    # If no explicit scan_types provided, default to all
    if not scan_types:
        scan_types = ["web", "network", "static", "cloud"]

    allow_project = all_projects_selected or bool(project_filter_ids)
    form_errors = []
    columns_selected = any(
        [
            summary_fields,
            vuln_table_fields,
            vuln_meta_fields,
            vuln_detail_sections,
        ]
    )

    # Defer adding errors for target filters until after we parse them below
    report_ready = False

    # Build resource filter selections and options (dependent on selected projects when applicable)
    # Read selections
    selected_scan_urls = [v for v in request.GET.getlist("scan_urls") if v and v != "__all__"]
    all_urls_selected = "__all__" in request.GET.getlist("scan_urls")

    # Accept both legacy 'infra_targets' and new 'network_targets'
    _infra_sel = [v for v in request.GET.getlist("infra_targets") if v and v != "__all__"]
    _network_sel = [v for v in request.GET.getlist("network_targets") if v and v != "__all__"]
    selected_infra_targets = list(dict.fromkeys(_infra_sel + _network_sel))
    all_infra_selected = ("__all__" in request.GET.getlist("infra_targets")) or ("__all__" in request.GET.getlist("network_targets"))

    selected_static_targets = [v for v in request.GET.getlist("static_targets") if v and v != "__all__"]
    all_static_selected = "__all__" in request.GET.getlist("static_targets")

    selected_cloud_targets = [v for v in request.GET.getlist("cloud_targets") if v and v != "__all__"]
    all_cloud_selected = "__all__" in request.GET.getlist("cloud_targets")

    # Build options
    def _project_filter(qs):
        if selected_projects and not all_projects_selected:
            return qs.filter(project__in=selected_projects)
        return qs

    # Web URLs (scope to org and owner)
    _dyn_base = WebScansDb.objects.all()
    if org is not None:
        _dyn_base = _dyn_base.filter(organization=org)
    _dyn_base = _dyn_base.filter(created_by=getattr(request, 'user', None))
    web_url_options = list(filter(None, _project_filter(_dyn_base).values_list("scan_url", flat=True).distinct()))

    # Network targets (IPs)
    _net_base = NetworkScanDb.objects.all()
    if org is not None:
        _net_base = _net_base.filter(organization=org)
    _net_base = _net_base.filter(created_by=getattr(request, 'user', None))
    network_target_options = list(filter(None, _project_filter(_net_base).values_list("ip", flat=True).distinct()))

    # Static projects (names)
    _static_base = StaticScansDb.objects.all()
    if org is not None:
        _static_base = _static_base.filter(organization=org)
    _static_base = _static_base.filter(created_by=getattr(request, 'user', None))
    static_names_a = list(filter(None, _project_filter(_static_base).values_list("project_name", flat=True).distinct()))
    static_names_b = list(filter(None, _project_filter(_static_base).values_list("project__project_name", flat=True).distinct()))
    static_target_options = sorted(set(static_names_a) | set(static_names_b))

    # Cloud accounts
    _cloud_base = CloudScansDb.objects.all()
    if org is not None:
        _cloud_base = _cloud_base.filter(organization=org)
    _cloud_base = _cloud_base.filter(created_by=getattr(request, 'user', None))
    cloud_target_options = list(filter(None, _project_filter(_cloud_base).values_list("cloudAccountId", flat=True).distinct()))

    # Validation: must also select at least one target filter (Web URL or Network Target)
    has_target_filter = (
        all_urls_selected or bool(selected_scan_urls) or
        all_infra_selected or bool(selected_infra_targets)
    )

    # Gate scan types by target filter selection so sections without chosen targets vanish
    effective_scan_types = []
    # web
    if all_urls_selected or selected_scan_urls:
        effective_scan_types.append("web")
    # network
    if all_infra_selected or selected_infra_targets:
        effective_scan_types.append("network")
    # Note: static/cloud are intentionally excluded from preview gating per request

    if preview_requested:
        if not allow_project:
            form_errors.append(
                "Select at least one project (or choose All Projects)."
            )
        if not has_target_filter:
            form_errors.append(
                "Select at least one target: a Web URL or a Network Target (or select the 'All' option)."
            )
        if not columns_selected:
            form_errors.append(
                "Select at least one column from Summary/Table/Metadata/Detail sections."
            )

    can_preview = allow_project and has_target_filter and columns_selected

    if preview_requested and not form_errors:
        project_tokens_for_query = ["__all__"] if all_projects_selected else project_filter_ids

        report_payload = _collect_report_data(
            request=request,
            project_ids=project_tokens_for_query,
            scan_types=effective_scan_types,
            severities=severities,
            sections=selected_sections,
            projects=projects,
            selected_projects=selected_projects,
            all_projects_selected=all_projects_selected,
            scan_urls=selected_scan_urls,
            all_urls_selected=all_urls_selected,
            infra_targets=selected_infra_targets,
            all_infra_selected=all_infra_selected,
            static_targets=selected_static_targets,
            all_static_selected=all_static_selected,
            cloud_targets=selected_cloud_targets,
            all_cloud_selected=all_cloud_selected,
        )
        query_string = _build_query_string(
            project_tokens_for_query,
            effective_scan_types,
            severities,
            selected_sections,
            summary_fields,
            vuln_table_fields,
            vuln_meta_fields,
            vuln_detail_sections,
            # include resource filters
            scan_urls=selected_scan_urls,
            all_urls_selected=all_urls_selected,
            infra_targets=selected_infra_targets,
            all_infra_selected=all_infra_selected,
            static_targets=selected_static_targets,
            all_static_selected=all_static_selected,
            cloud_targets=selected_cloud_targets,
            all_cloud_selected=all_cloud_selected,
        )
        report_ready = True
    else:
        report_payload = _empty_report_payload(
            projects,
            selected_projects,
            all_projects_selected=all_projects_selected,
        )
        query_string = ""

    detailed_sections_selected = any(
        section in selected_sections
        for section in ("web", "network", "static", "cloud")
    )

    # Keep pickers sourced from the global available lists at all times
    # (do not narrow them to only items in the current preview payload)

    context = {
        **report_payload,
        "selected_scan_types": effective_scan_types,
        "selected_sections": selected_sections,
        "summary_field_options": SUMMARY_FIELD_OPTIONS,
        "selected_summary_fields": summary_fields,
        "default_summary_fields": DEFAULT_SUMMARY_FIELDS,
        "vuln_table_field_options": VULN_TABLE_FIELD_OPTIONS,
        "selected_vuln_table_fields": vuln_table_fields,
        "default_vuln_table_fields": DEFAULT_VULN_TABLE_FIELDS,
        "vuln_meta_field_options": VULN_META_FIELD_OPTIONS,
        "selected_vuln_meta_fields": vuln_meta_fields,
        "default_vuln_meta_fields": DEFAULT_VULN_META_FIELDS,
        "vuln_detail_section_options": VULN_DETAIL_SECTION_OPTIONS,
        "selected_vuln_detail_sections": vuln_detail_sections,
        "default_vuln_detail_sections": DEFAULT_VULN_DETAIL_SECTIONS,
        "query_string": query_string,
        "now": timezone.now(),
        "export_mode": False,
        "report_ready": report_ready,
        "preview_requested": preview_requested,
        "can_preview": can_preview,
        "detailed_sections_selected": detailed_sections_selected,
        "form_errors": form_errors,
        "selected_project_ids": project_filter_ids,
        "selected_project_tokens": selected_project_tokens,
        "all_projects_selected": all_projects_selected,
        # Resource filters (options + selections)
        "web_url_options": web_url_options,
        "selected_scan_urls": selected_scan_urls,
        "all_urls_selected": all_urls_selected,
        "network_target_options": network_target_options,
        "selected_infra_targets": selected_infra_targets,
        "all_infra_selected": all_infra_selected,
        "static_target_options": static_target_options,
        "selected_static_targets": selected_static_targets,
        "all_static_selected": all_static_selected,
        "cloud_target_options": cloud_target_options,
        "selected_cloud_targets": selected_cloud_targets,
        "all_cloud_selected": all_cloud_selected,
        "message": Notification.objects.unread(),
    }
    return render(request, "reports/report.html", context)


# âœ… Download HTML or PDF
def download_report(request):
    requested_project_ids = request.GET.getlist("project_id")
    if not requested_project_ids:
        single_project = request.GET.get("project_id")
        if single_project:
            requested_project_ids = [single_project]

    all_projects_selected = "__all__" in requested_project_ids
    project_filter_ids = [str(pid) for pid in requested_project_ids if pid and pid != "__all__"]
    if all_projects_selected:
        project_filter_ids = []

    # Scan types for export: derive from filters if not explicitly provided
    scan_types = request.GET.getlist("scan_types")  # must match frontend name!
    severities = request.GET.getlist("severity")
    requested_format = request.GET.get("format", "pdf")
    if requested_format not in ("pdf", "html", "csv", "xml", "jinja2_pdf", "jinja2_html", "jinja2_csv", "jinja2_xml", "jinja2_json"):
        requested_format = "pdf"
    sections = request.GET.getlist("sections") or DEFAULT_REPORT_SECTIONS
    # Normalize legacy section keys coming from URL: dynamic->web, infrastructure->network
    SECTION_KEY_ALIASES = {"dynamic": "web", "infrastructure": "network"}
    sections = [SECTION_KEY_ALIASES.get(s, s) for s in sections]
    sections = [s for s in sections if s not in ('static', 'cloud')]
    detailed_sections_selected = any(
        section in sections
        for section in ("web", "network", "static", "cloud")
    )
    summary_fields = _normalize_selection(
        request.GET.getlist("summary_fields"),
        SUMMARY_FIELD_OPTIONS,
    )
    vuln_table_fields = _normalize_selection(
        request.GET.getlist("vuln_table_fields"),
        VULN_TABLE_FIELD_OPTIONS,
    )
    vuln_meta_fields = _normalize_selection(
        request.GET.getlist("vuln_meta_fields"),
        VULN_META_FIELD_OPTIONS,
    )
    vuln_detail_sections = _normalize_selection(
    request.GET.getlist("vuln_detail_sections"),
    VULN_DETAIL_SECTION_OPTIONS,
    )

    # Status filter for export. Default to 'open' for Org Admin/User
    # to mirror the UI expectation. Use 'all' to disable filtering or
    # 'closed' for closed-only exports.
    _raw_status = (request.GET.get("status") or "open").strip().lower()
    status_filter = None if _raw_status == "all" else _raw_status

    # Resource filters for export
    selected_scan_urls = [v for v in request.GET.getlist("scan_urls") if v and v != "__all__"]
    all_urls_selected = "__all__" in request.GET.getlist("scan_urls")

    # Accept both legacy 'infra_targets' and new 'network_targets'
    _infra_sel = [v for v in request.GET.getlist("infra_targets") if v and v != "__all__"]
    _network_sel = [v for v in request.GET.getlist("network_targets") if v and v != "__all__"]
    selected_infra_targets = list(dict.fromkeys(_infra_sel + _network_sel))
    all_infra_selected = ("__all__" in request.GET.getlist("infra_targets")) or ("__all__" in request.GET.getlist("network_targets"))

    selected_static_targets = [v for v in request.GET.getlist("static_targets") if v and v != "__all__"]
    all_static_selected = "__all__" in request.GET.getlist("static_targets")

    selected_cloud_targets = [v for v in request.GET.getlist("cloud_targets") if v and v != "__all__"]
    all_cloud_selected = "__all__" in request.GET.getlist("cloud_targets")

    # If no scan_types provided for export, default to all
    if not scan_types:
        scan_types = ["web", "network", "static", "cloud"]
    
    # Scope selected projects by organization and ownership for non-admins
    try:
        is_admin = (
            str(getattr(getattr(request, 'user', None), 'role', '')) == 'Admin'
        ) or bool(getattr(getattr(request, 'user', None), 'is_superuser', False))
    except Exception:
        is_admin = False
    org = getattr(getattr(request, 'user', None), 'organization', None)
    allowed_projects = ProjectDb.objects.all()
    if org is not None:
        allowed_projects = allowed_projects.filter(organization=org)
    if not is_admin:
        allowed_projects = allowed_projects.filter(created_by=getattr(request, 'user', None))
    selected_projects_qs = allowed_projects.filter(pk__in=project_filter_ids) if project_filter_ids else ProjectDb.objects.none()
    selected_projects = list(selected_projects_qs)
    project_tokens_for_query = ["__all__"] if all_projects_selected else project_filter_ids

    # Gate scan types by target filter selection for exports as well
    effective_scan_types = []
    if all_urls_selected or selected_scan_urls:
        effective_scan_types.append("web")
    if all_infra_selected or selected_infra_targets:
        effective_scan_types.append("network")
    if all_static_selected or selected_static_targets:
        effective_scan_types.append("static")
    if all_cloud_selected or selected_cloud_targets:
        effective_scan_types.append("cloud")

    # âœ… Build the full context with real data
    context = {
        **_collect_report_data(
            request=request,
            project_ids=project_tokens_for_query,
            scan_types=effective_scan_types,
            severities=severities,
            sections=sections,
            projects=allowed_projects,
            selected_projects=selected_projects,
            all_projects_selected=all_projects_selected,
            scan_urls=selected_scan_urls,
            all_urls_selected=all_urls_selected,
            infra_targets=selected_infra_targets,
            all_infra_selected=all_infra_selected,
            static_targets=selected_static_targets,
            all_static_selected=all_static_selected,
            cloud_targets=selected_cloud_targets,
            all_cloud_selected=all_cloud_selected,
            status=status_filter,
        ),
        "selected_project_ids": project_filter_ids,
        "selected_project_tokens": requested_project_ids,
        "all_projects_selected": all_projects_selected,
        "selected_scan_types": effective_scan_types,
        "selected_sections": sections,
        "summary_field_options": SUMMARY_FIELD_OPTIONS,
        "selected_summary_fields": summary_fields,
        "default_summary_fields": DEFAULT_SUMMARY_FIELDS,
        "vuln_table_field_options": VULN_TABLE_FIELD_OPTIONS,
        "selected_vuln_table_fields": vuln_table_fields,
        "default_vuln_table_fields": DEFAULT_VULN_TABLE_FIELDS,
        "vuln_meta_field_options": VULN_META_FIELD_OPTIONS,
        "selected_vuln_meta_fields": vuln_meta_fields,
        "default_vuln_meta_fields": DEFAULT_VULN_META_FIELDS,
        "vuln_detail_section_options": VULN_DETAIL_SECTION_OPTIONS,
        "selected_vuln_detail_sections": vuln_detail_sections,
        "default_vuln_detail_sections": DEFAULT_VULN_DETAIL_SECTIONS,
        "now": timezone.now(),
        "export_mode": True,  # tells template to render data for PDF
        "detailed_sections_selected": detailed_sections_selected,
        "selected_status": status_filter or "all",
    }

    # âœ… Add absolute image path for WeasyPrint
    import os
    import csv as csv_module
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    static_dir = os.path.join(os.path.dirname(__file__), '../templates/static')
    image_path = os.path.abspath(os.path.join(static_dir, 'archerysec-logo.png'))
    context["archerysec_image_path"] = f"file://{image_path}"

    # âœ… De-duplicate rows by Status for PDF tables, when a Status column is included
    def _unique_by_attr(items, attr):
        seen = set()
        result = []
        for obj in items or []:
            # support dicts and objects
            val = None
            if isinstance(obj, dict):
                val = obj.get(attr)
            else:
                val = getattr(obj, attr, None)
            key = str(val).strip().lower() if val is not None else ""
            # Only dedupe non-empty statuses; keep empty ones as-is
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            result.append(obj)
        return result

    def _only_open_closed(items):
        allowed = {"open", "closed"}
        filtered = []
        for obj in items or []:
            val = None
            if isinstance(obj, dict):
                val = obj.get("status")
            else:
                val = getattr(obj, "status", None)
            key = str(val).strip().lower() if val is not None else ""
            if key in allowed:
                filtered.append(obj)
        return filtered

    # Summary tables per scan type: do not dedupe by status; keep all records

    # Detailed findings tables per severity group
    # Previously we filtered to only "Open" items here. That caused Org
    # Admin and normal users to see fewer items than the counts shown in
    # the headings. To keep the tables consistent with the counts, render
    # the grouped items as-is (they are already limited by
    # max_total/max_per_group earlier in the pipeline).
    for slug, summary in (context.get("scan_summary_map") or {}).items():
        findings = summary.get("findings") or {}
        for group in findings.get("grouped") or []:
            items = group.get("items") or []
            group["table_items"] = list(items)

    # âœ… Render HTML
    html_content = render_to_string("reports/report_export.html", context)
    
    # Jinja2 rendering for flexible templates
    jinja2_html_content = None
    if JINJA2_AVAILABLE:
        try:
            import os
            
            def floatformat(value, arg=1):
                """Jinja2 filter equivalent to Django's floatformat"""
                try:
                    return f"{float(value):.{arg}f}"
                except (ValueError, TypeError):
                    return value
            
            def floatformat_no_trailing(value, arg=1):
                """Jinja2 filter equivalent to Django's floatformat with -g (no trailing zeros)"""
                try:
                    formatted = f"{float(value):.{arg}f}"
                    return formatted.rstrip('0').rstrip('.') if '.' in formatted else formatted
                except (ValueError, TypeError):
                    return value
            
            jinja2_env = Environment(
                loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '../templates')),
                autoescape=select_autoescape(['html', 'xml'])
            )
            jinja2_env.filters['floatformat'] = floatformat
            jinja2_env.filters['floatformat_no_trailing'] = floatformat_no_trailing
            jinja2_template = jinja2_env.get_template("reports/jinja2/report_export.html")
            jinja2_html_content = jinja2_template.render(**context)
        except Exception as e:
            print(f"Jinja2 rendering failed: {e}")
            jinja2_html_content = None

    log_action(request, "report_download", "report", f"{requested_format}:{','.join(project_tokens_for_query) if project_tokens_for_query else 'all'}", {
        "format": requested_format,
        "scan_types": effective_scan_types,
        "severities": severities,
    })

    timestamp = timezone.now().strftime('%Y-%m-%d_%H:%M')
    default_filename = f"security_report_{timestamp}.{requested_format}"
    download_name = request.GET.get("filename") or default_filename
    # ensure extension matches requested_format
    requested_ext = f".{requested_format}" if requested_format else ""
    if not download_name.lower().endswith(requested_ext):
        download_name = f"{download_name}{requested_ext}"

    # If user wants HTML preview
    if requested_format == "html":
        response = HttpResponse(html_content)
        response["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return response

    # âœ… Convert to CSV
    elif requested_format == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="{download_name}"'
        writer = csv_module.writer(response)
        writer.writerow(["Project", "Target", "Vulnerability", "Severity", "Risk", "CVSS Score", "CVSS Severity", "MITRE ATT&CK", "Status", "Scanner", "Description", "Solution"])
        for slug, summary in (context.get("scan_summary_map") or {}).items():
            for group in (summary.get("findings") or {}).get("grouped") or []:
                for item in group.get("items") or []:
                    writer.writerow([
                        item.get("project_name", ""),
                        item.get("target", ""),
                        item.get("title", ""),
                        item.get("severity", ""),
                        item.get("risk", ""),
                        item.get("cvss_score", ""),
                        item.get("cvss_severity", ""),
                        _mitre_csv_value(item.get("mitre_techniques", [])) if item.get("mitre_has_data") else "",
                        item.get("status", ""),
                        item.get("scanner", ""),
                        str(item.get("description") or "").replace("\n", " ").replace("\r", " "),
                        str(item.get("solution") or "").replace("\n", " ").replace("\r", " "),
                    ])
        return response

    # âœ… Convert to XML
    elif requested_format == "xml":
        root = ET.Element("report")
        meta = ET.SubElement(root, "metadata")
        ET.SubElement(meta, "generated").text = timezone.now().strftime('%Y-%m-%d %H:%M')
        ET.SubElement(meta, "total_findings").text = str(context.get("overall_counts", {}).get("total", 0))
        findings_elem = ET.SubElement(root, "findings")
        seen_titles = set()
        for slug, summary in (context.get("scan_summary_map") or {}).items():
            for group in (summary.get("findings") or {}).get("grouped") or []:
                for item in group.get("items") or []:
                    title = item.get("title", "")
                    if title and title in seen_titles:
                        continue
                    if title:
                        seen_titles.add(title)
                    f = ET.SubElement(findings_elem, "finding")
                    ET.SubElement(f, "title").text = title
                    ET.SubElement(f, "severity").text = item.get("severity", "")
                    ET.SubElement(f, "risk").text = item.get("risk", "")
                    ET.SubElement(f, "cvss_score").text = str(item.get("cvss_score", "") or "")
                    ET.SubElement(f, "cvss_severity").text = item.get("cvss_severity", "") or ""
                    mitre_el = ET.SubElement(f, "mitre_techniques")
                    if item.get("mitre_has_data"):
                        for t in item.get("mitre_techniques", []):
                            mt = ET.SubElement(mitre_el, "technique")
                            ET.SubElement(mt, "id").text = t.get("id", "")
                            ET.SubElement(mt, "name").text = t.get("name", "")
                            ET.SubElement(mt, "tactic").text = t.get("tactic", "")
                    ET.SubElement(f, "status").text = item.get("status", "")
                    ET.SubElement(f, "scanner").text = item.get("scanner", "")
                    ET.SubElement(f, "target").text = item.get("target", "")
                    desc = ET.SubElement(f, "description")
                    desc.text = item.get("description", "")
                    sol = ET.SubElement(f, "solution")
                    sol.text = item.get("solution", "")
                    ref = ET.SubElement(f, "reference")
                    ref.text = item.get("reference", "")
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        response = HttpResponse(xml_str, content_type="application/xml")
        response["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return response

    # âœ… Convert to PDF
    elif requested_format == "pdf":
        pdf_file = HTML(string=html_content).write_pdf()
        response = HttpResponse(pdf_file, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return response

    # âœ… Convert to PDF using Jinja2 template
    elif requested_format == "jinja2_pdf":
        if jinja2_html_content:
            pdf_file = HTML(string=jinja2_html_content).write_pdf()
            response = HttpResponse(pdf_file, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
        else:
            # Fallback to Django template
            pdf_file = HTML(string=html_content).write_pdf()
            response = HttpResponse(pdf_file, content_type="application/pdf")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response

    # âœ… HTML using Jinja2 template
    elif requested_format == "jinja2_html":
        if jinja2_html_content:
            response = HttpResponse(jinja2_html_content)
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
        else:
            # Fallback to Django template
            response = HttpResponse(html_content)
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response

    # âœ… CSV using Jinja2 template
    elif requested_format == "jinja2_csv":
        try:
            import os
            jinja2_env = Environment(
                loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '../templates')),
                autoescape=select_autoescape(['html', 'xml'])
            )
            jinja2_env.filters['floatformat'] = floatformat
            csv_content = jinja2_env.get_template("reports/jinja2/report_export.csv").render(**context)
            response = HttpResponse(csv_content, content_type="text/csv")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
        except Exception as e:
            print(f"Jinja2 CSV rendering failed: {e}")
            # Fallback to Django CSV
            response = HttpResponse(content_type="text/csv")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            writer = csv_module.writer(response)
            writer.writerow(["Project", "Target", "Vulnerability", "Severity", "Risk", "CVSS Score", "CVSS Severity", "MITRE ATT&CK", "Status", "Scanner", "Description", "Solution"])
            for slug, summary in (context.get("scan_summary_map") or {}).items():
                for group in (summary.get("findings") or {}).get("grouped") or []:
                    for item in group.get("items") or []:
                        writer.writerow([
                            item.get("project_name", ""),
                            item.get("target", ""),
                            item.get("title", ""),
                            item.get("severity", ""),
                            item.get("risk", ""),
                            item.get("cvss_score", ""),
                            item.get("cvss_severity", ""),
                            _mitre_csv_value(item.get("mitre_techniques", [])) if item.get("mitre_has_data") else "",
                            item.get("status", ""),
                            item.get("scanner", ""),
                            item.get("description", "").replace("\n", " ").replace("\r", " "),
                            item.get("solution", "").replace("\n", " ").replace("\r", " "),
                        ])
            return response

    # âœ… XML using Jinja2 template
    elif requested_format == "jinja2_xml":
        try:
            import os
            jinja2_env = Environment(
                loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '../templates')),
                autoescape=select_autoescape(['html', 'xml'])
            )
            jinja2_env.filters['floatformat'] = floatformat
            xml_content = jinja2_env.get_template("reports/jinja2/report_export.xml").render(**context)
            response = HttpResponse(xml_content, content_type="application/xml")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
        except Exception as e:
            print(f"Jinja2 XML rendering failed: {e}")
            # Fallback to Django XML
            root = ET.Element("report")
            meta = ET.SubElement(root, "metadata")
            ET.SubElement(meta, "generated").text = timezone.now().strftime('%Y-%m-%d %H:%M')
            ET.SubElement(meta, "total_findings").text = str(context.get("overall_counts", {}).get("total", 0))
            findings_elem = ET.SubElement(root, "findings")
            seen_titles = set()
            for slug, summary in (context.get("scan_summary_map") or {}).items():
                for group in (summary.get("findings") or {}).get("grouped") or []:
                    for item in group.get("items") or []:
                        title = item.get("title", "")
                        if title and title in seen_titles:
                            continue
                        if title:
                            seen_titles.add(title)
                        f = ET.SubElement(findings_elem, "finding")
                        ET.SubElement(f, "title").text = title
                        ET.SubElement(f, "severity").text = item.get("severity", "")
                        ET.SubElement(f, "risk").text = item.get("risk", "")
                        ET.SubElement(f, "cvss_score").text = str(item.get("cvss_score", "") or "")
                        ET.SubElement(f, "cvss_severity").text = item.get("cvss_severity", "") or ""
                        mitre_el = ET.SubElement(f, "mitre_techniques")
                        if item.get("mitre_has_data"):
                            for t in item.get("mitre_techniques", []):
                                mt = ET.SubElement(mitre_el, "technique")
                                ET.SubElement(mt, "id").text = t.get("id", "")
                                ET.SubElement(mt, "name").text = t.get("name", "")
                                ET.SubElement(mt, "tactic").text = t.get("tactic", "")
                        ET.SubElement(f, "status").text = item.get("status", "")
                        ET.SubElement(f, "scanner").text = item.get("scanner", "")
                        ET.SubElement(f, "target").text = item.get("target", "")
                        desc = ET.SubElement(f, "description")
                        desc.text = item.get("description", "")
                        sol = ET.SubElement(f, "solution")
                        sol.text = item.get("solution", "")
                        ref = ET.SubElement(f, "reference")
                        ref.text = item.get("reference", "")
            xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
            response = HttpResponse(xml_str, content_type="application/xml")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response

    # âœ… JSON using Jinja2 template
    elif requested_format == "jinja2_json":
        try:
            import os
            jinja2_env = Environment(
                loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '../templates')),
                autoescape=select_autoescape(['html', 'xml'])
            )
            jinja2_env.filters['floatformat'] = floatformat
            json_content = jinja2_env.get_template("reports/jinja2/report_export.json").render(**context)
            response = HttpResponse(json_content, content_type="application/json")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
        except Exception as e:
            print(f"Jinja2 JSON rendering failed: {e}")
            # Fallback - basic JSON
            import json
            fallback_data = {
                "metadata": {
                    "generated": timezone.now().strftime('%Y-%m-%d %H:%M'),
                    "total_findings": context.get("overall_counts", {}).get("total", 0),
                },
                "findings": []
            }
            for slug, summary in (context.get("scan_summary_map") or {}).items():
                for group in (summary.get("findings") or {}).get("grouped") or []:
                    for item in group.get("items") or []:
                        fallback_data["findings"].append({
                            "title": item.get("title", ""),
                            "severity": item.get("severity", ""),
                            "target": item.get("target", ""),
                        })
            response = HttpResponse(json.dumps(fallback_data, indent=2), content_type="application/json")
            response["Content-Disposition"] = f'attachment; filename="{download_name}"'
            return response
