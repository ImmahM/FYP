from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from projects.models import ProjectDb
from webscanners.models import WebScansDb
from networkscanners.models import NetworkScanDb
from staticscanners.models import StaticScansDb
from cloudscanners.models import CloudScansDb
from django.utils import timezone

# --- 1. Generate Report (Rendered Inline or in Modal) ---
def generate_report(request):
    """
    Gathers all vulnerability data and renders a unified report page.
    """

    # 📊 Projects overview
    project_id = request.GET.get("project_id")  # optional
    include_web = request.GET.get("include_web", "1") == "1"
    include_infra = request.GET.get("include_infra", "1") == "1"
    include_static = request.GET.get("include_static", "1") == "1"
    include_cloud = request.GET.get("include_cloud", "1") == "1"

    projects = ProjectDb.objects.all()

    # 🌐 Dynamic (Web) scan results
    web_scans = WebScansDb.objects.all() if include_web else WebScansDb.objects.none()

    # 🏗️ Infrastructure / Network scans
    infra_scans = NetworkScanDb.objects.all() if include_infra else NetworkScanDb.objects.none()

    # 🧑‍💻 Static analysis results
    static_scans = StaticScansDb.objects.all() if include_static else StaticScansDb.objects.none()

    # ☁️ Cloud scan results
    cloud_scans = CloudScansDb.objects.all() if include_cloud else CloudScansDb.objects.none()

    context = {
        "projects": projects,
        "web_scans": web_scans,
        "infra_scans": infra_scans,
        "static_scans": static_scans,
        "cloud_scans": cloud_scans,
        "now": timezone.now(),
    }

    # Return HTML content for inline rendering in a modal or on the page
    html_content = render_to_string("reports/report.html", context)
    return HttpResponse(html_content)


# --- 2. Download as HTML ---
def download_html_report(request):
    """
    Generates the report as HTML and allows the user to download it.
    """
    projects = ProjectDb.objects.all()
    web_scans = WebScansDb.objects.all()
    infra_scans = NetworkScanDb.objects.all()
    static_scans = StaticScansDb.objects.all()
    cloud_scans = CloudScansDb.objects.all()

    html_content = render_to_string("reports/report.html", {
        "projects": projects,
        "web_scans": web_scans,
        "infra_scans": infra_scans,
        "static_scans": static_scans,
        "cloud_scans": cloud_scans,
    })

    # Create a response with HTML content and set the filename for download
    response = HttpResponse(html_content, content_type="text/html")
    response['Content-Disposition'] = 'attachment; filename="security_report.html"'
    return response


# --- 3. Download as PDF ---
def download_pdf_report(request):
    """
    Generates the report as a PDF and allows the user to download it.
    """
    projects = ProjectDb.objects.all()
    web_scans = WebScansDb.objects.all()
    infra_scans = NetworkScanDb.objects.all()
    static_scans = StaticScansDb.objects.all()
    cloud_scans = CloudScansDb.objects.all()

    html_string = render_to_string("reports/report.html", {
        "projects": projects,
        "web_scans": web_scans,
        "infra_scans": infra_scans,
        "static_scans": static_scans,
        "cloud_scans": cloud_scans,
    })

    # Generate the PDF from the HTML content
    pdf_file = HTML(string=html_string).write_pdf()

    # Create a response with PDF content and set the filename for download
    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="security_report.pdf"'
    return response
