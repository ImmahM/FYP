# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from webscanners.models import WebScansDb        # ✅ Dynamic (DAST)
from staticscanners.models import StaticScansDb  # ✅ Static (SAST)
from networkscanners.models import NetworkScanDb # ✅ Infrastructure
from cloudscanners.models import CloudScansDb    # ✅ Cloud

# ✅ Main page that shows the filters + preview + download options
def generate_report(request):
    """
    View for the report generator page.
    It loads all scan data from DB and passes it to the template.
    """

    # --- ✅ Query data from all scanners ---
    dynamic_data = WebScansDb.objects.all().values(
        "scan_url", "total_vul", "critical_vul", "high_vul", "medium_vul", "low_vul"
    )

    static_data = StaticScansDb.objects.all().values(
        "project_name", "total_vul", "critical_vul", "high_vul", "medium_vul", "low_vul"
    )

    infra_data = NetworkScanDb.objects.all().values(
        "ip", "total_vul", "critical_vul", "high_vul", "medium_vul", "low_vul"
    )

    cloud_data = CloudScansDb.objects.all().values(
        "cloudAccountId", "total_vul", "critical_vul", "high_vul", "medium_vul", "low_vul"
    )

    # ✅ Pass all results to template context
    return render(request, "reports/report.html", {
        "dynamic_results": dynamic_data,
        "static_results": static_data,
        "infrastructure_results": infra_data,
        "cloud_results": cloud_data
    })


# ✅ Placeholder download endpoint (we'll implement real PDF/HTML download later)
def download_report(request):
    return HttpResponse("This is where the PDF/HTML download will happen.")
