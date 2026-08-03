# -*- coding: utf-8 -*-
from django.urls import path
from . import views

urlpatterns = [
    # ✅ Main report generator page
    path("generate/", views.generate_report, name="generate_report"),

    # ✅ Download endpoint (HTML/PDF)
    path("download/", views.download_report, name="download_report"),
]
