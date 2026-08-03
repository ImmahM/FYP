# archerysec/reports/views.py
# ===========================
from collections import OrderedDict
from urllib.parse import urlencode

from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Q, Sum, Max, Case, When, Value, IntegerField, Count
from django.db.models.functions import Coalesce
from weasyprint import HTML

from projects.models import ProjectDb
from webscanners.models import WebScansDb, WebScanResultsDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from cloudscanners.models import CloudScansDb, CloudScansResultsDb


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
            "dynamic",
            {
                "label": "Dynamic (DAST) Findings",
                "description": "Runtime application findings and highlights",
            },
        ),
        (
            "infrastructure",
            {
                "label": "Infrastructure Findings",
                "description": "Network and infrastructure scan results",
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
DEFAULT_REPORT_SECTIONS = list(REPORT_SECTION_OPTIONS.keys())


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
DEFAULT_SUMMARY_FIELDS = list(SUMMARY_FIELD_OPTIONS.keys())


VULN_TABLE_FIELD_OPTIONS = OrderedDict(
    [
        ("title", {"label": "Vulnerability"}),
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
DEFAULT_VULN_META_FIELDS = ["title", "risk", "status", "jira_ticket", "false_positive"]


VULN_DETAIL_SECTION_OPTIONS = OrderedDict(
    [
        ("description", {"label": "Description"}),
        ("instance", {"label": "Instance"}),
        ("solution", {"label": "Solutions"}),
        ("reference", {"label": "Reference"}),
    ]
)
DEFAULT_VULN_DETAIL_SECTIONS = list(VULN_DETAIL_SECTION_OPTIONS.keys())


# ✅ Helper: Filter queryset by severity selection
def _filter_by_severity(qs, severities):
    if not severities:
        return qs
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


# ✅ Helper: Aggregate counts and metadata for scan querysets
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

    timestamps = [
        aggregate_values.get(f"max_{field}") for field in timestamp_fields
        if aggregate_values.get(f"max_{field}")
    ]
    last_scan = max(timestamps) if timestamps else None

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


def _risk_score(counts):
    return sum(counts.get(severity, 0) * weight for severity, weight in SEVERITY_WEIGHTS.items())


def _risk_level(score):
    for label, threshold, css in RISK_LEVEL_SCALE:
        if score >= threshold:
            return {"label": label, "css": css}
    return {"label": "Low", "css": "success"}


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
            origin = f"{group_label} › {title}" if group_label else title

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
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": getattr(record, "instance", None),
        "reference": record.reference,
        "scanner": record.scanner,
        "url": record.url,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
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
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": None,
        "reference": None,
        "scanner": record.scanner,
        "url": record.ip,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
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
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": location,
        "reference": record.references,
        "scanner": record.scanner,
        "url": location,
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
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
    return {
        "title": record.title or "Unnamed Finding",
        "severity": severity,
        "severity_label": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "risk": severity_label or SEVERITY_DISPLAY.get(severity, severity.title()),
        "status": getattr(record, "vuln_status", None),
        "jira_ticket": getattr(record, "jira_ticket", None),
        "false_positive": getattr(record, "false_positive", None),
        "duplicate": getattr(record, "vuln_duplicate", None) or getattr(record, "dup_hash", None),
        "description": record.description,
        "solution": record.solution,
        "instance": getattr(record, "resourceName", None),
        "reference": record.references,
        "scanner": record.scanner,
        "url": getattr(record, "resourceId", None) or getattr(record, "resourceName", None),
        "fields": fields,
        "detected": record.date_time,
        "identifier": str(record.vuln_id) if getattr(record, "vuln_id", None) else None,
    }


def _collect_detail_findings(scan_qs, severities, config):
    scan_ids = list(
        scan_qs.exclude(scan_id__isnull=True).values_list("scan_id", flat=True)
    )
    if not scan_ids:
        return {"total": 0, "grouped": []}

    severity_field = config.get("severity_field", "severity")
    result_qs = config["model"].objects.filter(scan_id__in=scan_ids)

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

    breakdown = (
        result_qs.values(severity_field)
        .annotate(count=Count("id"))
    )
    totals_by_severity = {}
    total_records = 0
    for row in breakdown:
        normalized = _normalize_result_severity(row[severity_field])
        totals_by_severity[normalized] = totals_by_severity.get(normalized, 0) + row["count"]
        total_records += row["count"]

    if total_records == 0:
        return {"total": 0, "grouped": []}

    max_total = config.get("max_total", 200)
    max_per_group = config.get("max_per_group", 50)

    grouped_map = OrderedDict((severity, []) for severity in RESULT_SEVERITY_ORDER)
    severity_counts = {severity: 0 for severity in grouped_map}
    other_items = []
    other_total = total_records - sum(totals_by_severity.get(severity, 0) for severity in grouped_map)
    other_shown = 0

    serializer = config["serializer"]
    emitted = 0
    truncated = False
    timeline_map = OrderedDict()
    date_field = config.get("date_field")

    for record in result_qs.iterator():
        severity = _normalize_result_severity(getattr(record, severity_field, None))
        entry = serializer(record)

        if date_field:
            detected = getattr(record, date_field, None)
            if detected:
                label = detected.strftime("%Y-%m")
                timeline_map[label] = timeline_map.get(label, 0) + 1

        if severity in grouped_map:
            if max_per_group and severity_counts[severity] >= max_per_group:
                truncated = True
                continue
            grouped_map[severity].append(entry)
            severity_counts[severity] += 1
        else:
            if max_per_group and other_shown >= max_per_group:
                truncated = True
                continue
            other_items.append(entry)
            other_shown += 1

        emitted += 1
        if max_total and emitted >= max_total:
            if emitted < total_records:
                truncated = True
            break

    grouped = []
    for severity, items in grouped_map.items():
        total = totals_by_severity.get(severity, 0)
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
            count = totals_by_severity.get(severity, 0)
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
    "dynamic": {
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
    "infrastructure": {
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


def _build_scan_summary(qs, label, slug, label_getter, severities=None, detail_config=None):
    summary = _summarize_queryset(qs)
    records = list(qs)
    summary.update(
        {
            "label": label,
            "slug": slug,
            "records": records,
            "scanners": _collect_scanners(records),
            "top_targets": _target_snapshot(records, label_getter),
            "findings": _collect_detail_findings(qs, severities, detail_config)
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


def _empty_report_payload(projects, selected_project):
    overall_counts = {severity: 0 for severity in SEVERITY_ORDER}
    overall_counts["total"] = 0
    return {
        "selected_project": selected_project,
        "projects": projects,
        "dynamic_results": [],
        "infrastructure_results": [],
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


# ✅ Helper: Build filtered results for template
def _collect_report_data(
    project_id=None,
    scan_types=None,
    severities=None,
    sections=None,
    projects=None,
    selected_project=None,
):
    scan_types = scan_types or []
    severities = severities or []
    section_keys = list(sections) if sections else DEFAULT_REPORT_SECTIONS
    section_set = set(section_keys)

    if selected_project is None and project_id:
        try:
            selected_project = ProjectDb.objects.get(pk=project_id)
        except ProjectDb.DoesNotExist:
            selected_project = None

    if projects is None:
        projects = ProjectDb.objects.all()

    include_dynamic = (
        "dynamic" in section_set
        and (
            not scan_types
            or "web" in scan_types
            or "dynamic" in scan_types
        )
    )
    include_infra = (
        "infrastructure" in section_set
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

    # ✅ Query + filter for each scan type
    dynamic_qs = WebScansDb.objects.none()
    if include_dynamic:
        dynamic_qs = (
            WebScansDb.objects.filter(project=selected_project)
            if selected_project
            else WebScansDb.objects.all()
        )
        dynamic_qs = _filter_by_severity(dynamic_qs, severities)

    infra_qs = NetworkScanDb.objects.none()
    if include_infra:
        infra_qs = (
            NetworkScanDb.objects.filter(project=selected_project)
            if selected_project
            else NetworkScanDb.objects.all()
        )
        infra_qs = _filter_by_severity(infra_qs, severities)

    static_qs = StaticScansDb.objects.none()
    if include_static:
        static_qs = (
            StaticScansDb.objects.filter(project=selected_project)
            if selected_project
            else StaticScansDb.objects.all()
        )
        static_qs = _filter_by_severity(static_qs, severities)

    cloud_qs = CloudScansDb.objects.none()
    if include_cloud:
        cloud_qs = (
            CloudScansDb.objects.filter(project=selected_project)
            if selected_project
            else CloudScansDb.objects.all()
        )
        cloud_qs = _filter_by_severity(cloud_qs, severities)

    scan_summaries = []

    dynamic_results = []
    if include_dynamic:
        dynamic_summary = _build_scan_summary(
            dynamic_qs,
            label="Dynamic Application Scans",
            slug="dynamic",
            label_getter=lambda record: record.scan_url
            or (record.project.project_name if record.project else "Unassigned Target"),
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("dynamic"),
        )
        dynamic_results = dynamic_summary.pop("records", [])
        scan_summaries.append(dynamic_summary)

    infrastructure_results = []
    if include_infra:
        infra_summary = _build_scan_summary(
            infra_qs,
            label="Infrastructure Scans",
            slug="infrastructure",
            label_getter=lambda record: record.ip or "Unassigned Target",
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("infrastructure"),
        )
        infrastructure_results = infra_summary.pop("records", [])
        scan_summaries.append(infra_summary)

    static_results = []
    if include_static:
        static_summary = _build_scan_summary(
            static_qs,
            label="Static Analysis Scans",
            slug="static",
            label_getter=lambda record: record.project_name
            or (record.project.project_name if record.project else "Unassigned Project"),
            severities=severities,
            detail_config=DETAIL_CONFIGS.get("static"),
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
            detail_config=DETAIL_CONFIGS.get("cloud"),
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

    return {
        "selected_project": selected_project,
        "projects": projects,
        "dynamic_results": dynamic_results,
        "infrastructure_results": infrastructure_results,
        "static_results": static_results,
        "cloud_results": cloud_results,
        "scan_summaries": scan_summaries if "coverage" in section_set else [],
        "scan_summary_map": summary_map,
        "overall_counts": overall_counts,
        "severity_percentages": severity_percentages,
        "risk_overview": {
            "score": score,
            "label": risk["label"],
            "css": risk["css"],
        },
        "priority_targets": priority_targets if "priority_targets" in section_set else [],
        "has_scan_data": overall_counts.get("total", 0) > 0,
    }


# ✅ Main: Generate & preview report
def _build_query_string(
    project_id,
    scan_types,
    severities,
    sections,
    summary_fields,
    vuln_table_fields,
    vuln_meta_fields,
    vuln_detail_sections,
):
    params = []
    if project_id:
        params.append(("project_id", project_id))
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
    return urlencode(params)


def generate_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")
    section_selection = request.GET.getlist("sections")
    preview_requested = request.GET.get("preview") == "1"

    projects = ProjectDb.objects.all()
    selected_project = (
        ProjectDb.objects.filter(pk=project_id).first() if project_id else None
    )

    selected_sections = section_selection or DEFAULT_REPORT_SECTIONS
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

    if preview_requested:
        report_payload = _collect_report_data(
            project_id,
            scan_types,
            severities,
            sections=selected_sections,
            projects=projects,
            selected_project=selected_project,
        )
        query_string = _build_query_string(
            project_id,
            scan_types,
            severities,
            selected_sections,
            summary_fields,
            vuln_table_fields,
            vuln_meta_fields,
            vuln_detail_sections,
        )
    else:
        report_payload = _empty_report_payload(projects, selected_project)
        query_string = ""

    detailed_sections_selected = any(
        section in selected_sections
        for section in ("dynamic", "infrastructure", "static", "cloud")
    )

    context = {
        **report_payload,
        "selected_scan_types": scan_types,
        "selected_sections": selected_sections,
        "summary_field_options": SUMMARY_FIELD_OPTIONS,
        "selected_summary_fields": summary_fields,
        "vuln_table_field_options": VULN_TABLE_FIELD_OPTIONS,
        "selected_vuln_table_fields": vuln_table_fields,
        "vuln_meta_field_options": VULN_META_FIELD_OPTIONS,
        "selected_vuln_meta_fields": vuln_meta_fields,
        "vuln_detail_section_options": VULN_DETAIL_SECTION_OPTIONS,
        "selected_vuln_detail_sections": vuln_detail_sections,
        "query_string": query_string,
        "now": timezone.now(),
        "export_mode": False,
        "report_ready": preview_requested,
        "preview_requested": preview_requested,
        "detailed_sections_selected": detailed_sections_selected,
    }
    return render(request, "reports/report.html", context)


# ✅ Download HTML or PDF
def download_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")  # must match frontend name!
    severities = request.GET.getlist("severity")
    format = request.GET.get("format", "pdf")
    sections = request.GET.getlist("sections") or DEFAULT_REPORT_SECTIONS
    detailed_sections_selected = any(
        section in sections
        for section in ("dynamic", "infrastructure", "static", "cloud")
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

    # ✅ Build the full context with real data
    context = {
        **_collect_report_data(
            project_id,
            scan_types,
            severities,
            sections=sections,
        ),
        "selected_project_id": project_id,
        "selected_scan_types": scan_types,
        "selected_sections": sections,
        "summary_field_options": SUMMARY_FIELD_OPTIONS,
        "selected_summary_fields": summary_fields,
        "vuln_table_field_options": VULN_TABLE_FIELD_OPTIONS,
        "selected_vuln_table_fields": vuln_table_fields,
        "vuln_meta_field_options": VULN_META_FIELD_OPTIONS,
        "selected_vuln_meta_fields": vuln_meta_fields,
        "vuln_detail_section_options": VULN_DETAIL_SECTION_OPTIONS,
        "selected_vuln_detail_sections": vuln_detail_sections,
        "now": timezone.now(),
        "export_mode": True,  # tells template to render data for PDF
        "detailed_sections_selected": detailed_sections_selected,
    }

    # ✅ Add absolute image path for WeasyPrint
    import os
    static_dir = os.path.join(os.path.dirname(__file__), '../templates/static')
    image_path = os.path.abspath(os.path.join(static_dir, 'teamcloud.jpg'))
    context["teamcloud_image_path"] = f"file://{image_path}"

    # ✅ Render HTML
    html_content = render_to_string("reports/report_export.html", context)

    timestamp = timezone.now().strftime('%Y-%m-%d_%H:%M')
    default_filename = f"security_report_{timestamp}.pdf"
    download_name = request.GET.get("filename") or default_filename
    # ensure extension
    if not download_name.lower().endswith(".pdf"):
        download_name = f"{download_name}.pdf"

    # If user wants HTML preview
    if format == "html":
        response = HttpResponse(html_content)
        response["Content-Disposition"] = f'attachment; filename="{download_name.replace(".pdf", ".html")}"'
        return response

    # ✅ Convert to PDF
    elif format == "pdf":
        pdf_file = HTML(string=html_content).write_pdf()
        response = HttpResponse(pdf_file, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return response
