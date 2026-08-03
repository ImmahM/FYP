# archerysec/reports/views.py
# ===========================
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


# ✅ Helper: Build filtered results for template
def _collect_report_data(project_id=None, scan_types=None, severities=None):
    selected_project = None
    if project_id:
        try:
            selected_project = ProjectDb.objects.get(pk=project_id)
        except ProjectDb.DoesNotExist:
            selected_project = None

    include_dynamic = not scan_types or "web" in scan_types or "dynamic" in scan_types
    include_infra = not scan_types or "network" in scan_types or "infrastructure" in scan_types
    include_static = not scan_types or "static" in scan_types
    include_cloud = not scan_types or "cloud" in scan_types

    # ✅ Query + filter for each scan type
    dynamic_qs = WebScansDb.objects.none()
    if include_dynamic:
        dynamic_qs = WebScansDb.objects.filter(project=selected_project) if selected_project else WebScansDb.objects.all()
        dynamic_qs = _filter_by_severity(dynamic_qs, severities)

    infra_qs = NetworkScanDb.objects.none()
    if include_infra:
        infra_qs = NetworkScanDb.objects.filter(project=selected_project) if selected_project else NetworkScanDb.objects.all()
        infra_qs = _filter_by_severity(infra_qs, severities)

    static_qs = StaticScansDb.objects.none()
    if include_static:
        static_qs = StaticScansDb.objects.filter(project=selected_project) if selected_project else StaticScansDb.objects.all()
        static_qs = _filter_by_severity(static_qs, severities)

    cloud_qs = CloudScansDb.objects.none()
    if include_cloud:
        cloud_qs = CloudScansDb.objects.filter(project=selected_project) if selected_project else CloudScansDb.objects.all()
        cloud_qs = _filter_by_severity(cloud_qs, severities)

    return {
        "selected_project": selected_project,
        "projects": ProjectDb.objects.all(),
        "dynamic_results": dynamic_qs,
        "infrastructure_results": infra_qs,
        "static_results": static_qs,
        "cloud_results": cloud_qs,
    }


# ✅ Main: Generate & preview report
def generate_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")

    context = {
        **_collect_report_data(project_id, scan_types, severities),
        "selected_scan_types": scan_types,
        "selected_severities": severities,
        "query_string": request.META.get("QUERY_STRING", ""),
        "now": timezone.now(),
        "export_mode": False,
    }
    return render(request, "reports/report.html", context)


# ✅ Download HTML or PDF
def download_report(request):
    project_id = request.GET.get("project_id") or None
    scan_types = request.GET.getlist("scan_types")
    severities = request.GET.getlist("severity")
    fmt = request.GET.get("format", "html")

    context = {
        **_collect_report_data(project_id, scan_types, severities),
        "now": timezone.now(),
        "export_mode": True,  # ⬅️ Hide filters in template
    }

    # ✅ Generate HTML string
    html_string = render_to_string("reports/report.html", context)
    timestamp = timezone.now().strftime("%Y%m%d-%H%M%S")
    base_name = "security_report"
    if context["selected_project"]:
        base_name += "-" + context["selected_project"].project_name.replace(" ", "_")

    # ✅ If PDF
    if fmt == "pdf":
        pdf_bytes = HTML(string=html_string, base_url=request.build_absolute_uri("/")).write_pdf()
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{base_name}-{timestamp}.pdf"'
        return response

    # ✅ Default: HTML
    response = HttpResponse(html_string, content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{base_name}-{timestamp}.html"'
    return response
