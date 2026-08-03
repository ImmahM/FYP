from django.shortcuts import render
from django.http import HttpResponse
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.renderers import TemplateHTMLRenderer
from projects.models import ProjectDb
from webscanners.models import WebScansDb
from networkscanners.models import NetworkScanDb
from staticscanners.models import StaticScansDb
from cloudscanners.models import CloudScansDb

class GenerateReport(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "reports/report.html"  # Assuming report.html contains the report layout

    def get(self, request):
        # Fetch data for the report (similar to the way data is fetched in SastScanList)
        project_id = request.GET.get("project_id")
        include_web = request.GET.get("include_web", "1") == "1"
        include_infra = request.GET.get("include_infra", "1") == "1"
        include_static = request.GET.get("include_static", "1") == "1"
        include_cloud = request.GET.get("include_cloud", "1") == "1"
        
        # Fetch projects and scans based on filters
        projects = ProjectDb.objects.all()

        web_scans = WebScansDb.objects.filter(project_id=project_id) if include_web else WebScansDb.objects.none()
        infra_scans = NetworkScanDb.objects.filter(project_id=project_id) if include_infra else NetworkScanDb.objects.none()
        static_scans = StaticScansDb.objects.filter(project_id=project_id) if include_static else StaticScansDb.objects.none()
        cloud_scans = CloudScansDb.objects.filter(project_id=project_id) if include_cloud else CloudScansDb.objects.none()

        # Context to pass to the template
        context = {
            "projects": projects,
            "web_scans": web_scans,
            "infra_scans": infra_scans,
            "static_scans": static_scans,
            "cloud_scans": cloud_scans,
        }

        # Render the report content using the context
        return render(request, self.template_name, context)

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
