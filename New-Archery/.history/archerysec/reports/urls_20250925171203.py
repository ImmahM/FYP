# reports/urls.py
from django.urls import path
from . import views

app_name = "reports"

urlpatterns = [
    path("generate/", views.GenerateReport.as_view(), name="generate_report"),
    path("download/html/", views.download_html_report, name="download_html"),
    path("download/pdf/", views.download_pdf_report, name="download_pdf"), 
]