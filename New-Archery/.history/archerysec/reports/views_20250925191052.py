# archerysec/reports/views.py
# ===========================
# NEW / UPDATED file - replaces the older simpler handlers.
# It keeps the same route names (generate_report, download_html_report, download_pdf_report)
# but adds filtering logic and shared helper.

from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Q
from weasyprint import HTML

from projects.models import ProjectDb
from webscanners.models import WebScansDb
from networkscanners.models import NetworkScanDb
from staticscanners.models import StaticScansDb
from cloudscanners.models import CloudScansDb


def _filter_by_severity(qs, severities, model_type):
    """
    Helper: given a queryset and list of severity keys e.g. ['critical','high'],
    return qs filtered to entries that have >0 for any of the requested severity counts.
    model_type is a short string only for clarity (not strictly required).
    """
    if not severities:
        return qs

    # mapping from our severity names to model fields
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
    if q:
        return qs.filter(q)
    return qs


def _collect_report_data(project_id=None, scan_types=None, severities=None):
    """
    Build the querysets based on selected project and scan_types/severities.
    Returns a dict ready for template context.
    - project_id: str or None
    - scan_types: list of values among ['web','network','static','cloud'] or None/empty => all
    - severities: list of ['critical','high','medium','low'] or None/empty => all
    """
    # Selected project object (if any)
    selected_project = None
    if project_id:
        try:
            selected_project = ProjectDb.objects.get(pk=project_id)
        except ProjectDb.DoesNotExist:
            selected_project = None

    # Default: include all types if none specified
    include_web = not scan_types or "web" in scan_types
    include_network = not scan_types or "network" in scan_types
    include_static = not scan_types or "static" in scan_types
    include_cloud = not scan_types or "cloud" in scan_types

    # Projects list for the dropdown (always available)
    projects = ProjectDb.objects.all()

    # Build querysets, apply project filter if requested
    web_qs = WebScansDb.objects.none()
    if include_web:
        web_qs = WebScansDb.objects.filter(project=selected_project) if selected_project else WebScansDb.objects.all()
        web_qs = _filter_by_severity(web_qs, severities, "web")

    infra_qs = NetworkScanDb.objects.none()
    if include_network:
        infra_qs = NetworkScanDb.objects.filter(project=selected_project) if selected_project else NetworkScanDb.objects.all()
        infra_qs = _filter_by_severity(infra_qs, severities, "network")

    static_qs = StaticScansDb.objects.none()
    if include_static:
        static_qs = StaticScansDb.objects.filter(project=selected_project) if selected_project else StaticScansDb.objects.all()
        static_qs = _filter_by_severity(static_qs, severities, "static")

    cloud_qs = CloudScansDb.objects.none()
    if include_cloud:
        cloud_qs = CloudScansDb.objects.filter(project=selected_project) if selected_project else CloudScansDb.objects.all()
        cloud_qs = _filter_by_severity(cloud_qs, severities, "cloud")

    return {
        "selected_project": selected_project,
        "projects": projects,
        "web_scans": web_qs,
        "infra_scans": infra_qs,
        "static_scans": static_qs,
        "cloud_scans": cloud_qs,
    }


# --- Generate / Preview page ---
def generate_report(request):
    """
    Render the report page. If GET contains filters the page acts as a preview for those filters.
    Filters are sent as query params (method=GET):
      - project_id (int)
      - scan_types (multiple) -> values: web, network, static, cloud
      - severity (multiple) -> values: critical, high, medium, low
    """
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")  # e.g. ['web','cloud']
    severities = request.GET.getlist("severity")    # e.g. ['critical','high']

    data = _collect_report_data(project_id=project_id, scan_types=scan_types, severities=severities)

    # add helpful items for template rendering
    context = {
        **data,
        "selected_scan_types": scan_types,
        "selected_severities": severities,
        "query_string": request.META.get("QUERY_STRING", ""),
        "now": timezone.now(),
    }

    return render(request, "reports/report.html", context)


# --- Download HTML (respects filters) ---
def download_html_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")

    data = _collect_report_data(project_id=project_id, scan_types=scan_types, severities=severities)
    context = {
        **data,
        "now": timezone.now(),
        "export_mode": True,      # ✅ NEW: tells template we're exporting
    }

    html_content = render_to_string("reports/report.html", context)

    filename = "security_report"
    if data["selected_project"]:
        filename += "-" + data["selected_project"].project_name.replace(" ", "_")
    filename += "-" + timezone.now().strftime("%Y%m%d-%H%M%S") + ".html"

    response = HttpResponse(html_content, content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response



# --- Download PDF (respects filters) ---
def download_pdf_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")

    data = _collect_report_data(project_id=project_id, scan_types=scan_types, severities=severities)
    context = {
        **data,
        "now": timezone.now(),
        "export_mode": True,     # ✅ NEW here too
    }

    html_string = render_to_string("reports/report.html", context)
    base_url = request.build_absolute_uri("/")
    pdf_bytes = HTML(string=html_string, base_url=base_url).write_pdf()

    filename = "security_report"
    if data["selected_project"]:
        filename += "-" + data["selected_project"].project_name.replace(" ", "_")
    filename += "-" + timezone.now().strftime("%Y%m%d-%H%M%S") + ".pdf"

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response