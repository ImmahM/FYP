# archerysec/reports/urls.py
from django.urls import path
from . import views

app_name = "reports"

urlpatterns = [
    path("generate/", views.generate_report, name="generate_report"),
    path("download/", views.download_report, name="download_report"),
]
