# docker-compose/archerysec/reports/views.py
from django.shortcuts import render
from django.http import HttpResponse
from projects.models import ProjectDb
from webscanners.models import WebScansDb
from networkscanners.models import NetworkScanDb
from staticscanners.models import StaticScansDb
from cloudscanners.models import CloudScansDb
from django.template.loader import render_to_string
from weasyprint import HTML
from projects.models import ProjectDb, ProjectScanDb 
def generate_report(request):
    """
    Gathers all vulnerability data and renders a unified report page.
    """

    # 📊 Projects overview
    projects = ProjectDb.objects.all()

    # 🌐 Dynamic (Web) scan results
    web_scans = WebScansDb.objects.all()

    # 🏗️ Infrastructure / Network scans
    infra_scans = NetworkScanDb.objects.all()

    # 🧑‍💻 Static analysis results
    static_scans = StaticScansDb.objects.all()

    # ☁️ Cloud scan results
    cloud_scans = CloudScansDb.objects.all()

    context = {
        "projects": projects,
        "web_scans": web_scans,
        "infra_scans": infra_scans,
        "static_scans": static_scans,
        "cloud_scans": cloud_scans,
    }

    return render(request, "reports/report.html", context)

# --- 1. Download as HTML ---
def download_html_report(request):
    projects = ProjectDb.objects.all()
    web_scans = WebScansDb.objects.all()
    infra_scans = NetworkScanDb.objects.all()
    static_scans =StaticScansDb.objects.all()
    cloud_scans =CloudScansDb.objects.all()

    html_content = render_to_string("reports/report.html", {
        "projects": projects,
        "web_scans": web_scans,
        "infra_scans": infra_scans,
        "static_scans": static_scans,
        "cloud_scans": cloud_scans,
    })

    response = HttpResponse(html_content, content_type="text/html")
    response['Content-Disposition'] = 'attachment; filename="security_report.html"'
    return response



# --- 2. Download as PDF ---
def download_pdf_report(request):
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

    pdf_file = HTML(string=html_string).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="security_report.pdf"'
    return response
 