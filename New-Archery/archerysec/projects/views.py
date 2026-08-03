# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

import datetime
import uuid

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponseRedirect, get_object_or_404, render
from django.urls import reverse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from projects.models import MonthDb, ProjectDb, ProjectScanDb
from projects.serializers import (ProjectCreateSerializers,
                                  ProjectDataSerializers)
from user_management import permissions
from user_management.models import Organization

project_dat = None


def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == "GET":
        project_id = request.GET["project_id"]

        project_dat = ProjectDb.objects.filter(
            project_id=project_id,
            organization=request.user.organization,
        )

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")
        project_disc = request.POST.get("project_disc")

        ProjectDb.objects.filter(project_id=project_id).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc,
            organization=request.user.organization,
        )
        return HttpResponseRedirect(
            reverse("projects:projects") + "?proj_id=%s" % project_id
        )
    return render(request, "projects/project_edit.html", {"project_dat": project_dat})


class ProjectList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        if uu_id == None:
            projects = ProjectDb.objects.filter(organization=request.user.organization)
            serialized_data = ProjectDataSerializers(projects, many=True)
        else:
            try:
                projects = ProjectDb.objects.filter(
                    uu_id=uu_id, organization=request.user.organization
                )
                serialized_data = ProjectDataSerializers(projects, many=True)
            except ProjectDb.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )

        if request.path[:4] == "/api":
            return Response(serialized_data.data)
        else:
            return Response({"serializer": serialized_data, "projects": projects})


class ProjectDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "dashboard/project.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        try:
            project_id = request.data.get("project_id")
            projects = ProjectDb.objects.filter(
                uu_id=project_id, organization=request.user.organization
            )
            projects.delete()
            return HttpResponseRedirect("/dashboard/")
        except ProjectDb.DoesNotExist:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class ProjectCreate(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "projects/project_create.html"

    # Allow Admin and normal Users to create projects
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        org = Organization.objects.all()
        projects = ProjectDb.objects.filter(organization=request.user.organization)
        serialized_data = ProjectDataSerializers(projects, many=True)

        return Response(
            {"serializer": serialized_data, "projects": projects, "org": org}
        )

    def post(self, request):
        serializer = ProjectCreateSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("project_name")
        description = request.data.get("project_disc")

        project = ProjectDb(
            project_name=name,
            project_disc=description,
            created_by=request.user,
            organization=request.user.organization,
            total_vuln=0,
            total_critical=0,
            total_high=0,
            total_medium=0,
            total_low=0,
            total_open=0,
            total_false=0,
            total_close=0,
            total_net=0,
            total_web=0,
            total_static=0,
            critical_net=0,
            critical_web=0,
            critical_static=0,
            high_net=0,
            high_web=0,
            high_static=0,
            medium_net=0,
            medium_web=0,
            medium_static=0,
            low_net=0,
            low_web=0,
            low_static=0,
        )
        project.save()
        all_month_data_display = MonthDb.objects.filter(
            organization=request.user.organization
        )

        if len(all_month_data_display) == 0:
            save_months_data = MonthDb(
                project_id=project.id,
                month=datetime.datetime.now().month,
                critical=0,
                high=0,
                medium=0,
                low=0,
            )
            save_months_data.save()
        messages.success(request, "Project Created")
        return HttpResponseRedirect("/dashboard/")


class ProjectsManage(APIView):
    """Projects page with scan counts.

    - Admin/superuser: sees all projects in org and can bulk delete.
    - Organization Admin/User: sees only projects they created; no delete.
    """
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "projects/projects_manage.html"
    # Allow all authenticated analysts to view; enforce delete rights in post()
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        from django.db.models import OuterRef, Subquery, IntegerField, Count
        from django.db.models.functions import Coalesce
        from networkscanners.models import NetworkScanDb
        from webscanners.models import WebScansDb
        from staticscanners.models import StaticScansDb

        base = ProjectDb.objects.filter(organization=request.user.organization)
        # Non-admins see only their own projects
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        if not is_admin:
            base = base.filter(created_by=request.user)

        net_sq = (
            NetworkScanDb.objects.filter(project_id=OuterRef("id"))
            .values("project_id").annotate(c=Count("id")).values("c")[:1]
        )
        web_sq = (
            WebScansDb.objects.filter(project_id=OuterRef("id"))
            .values("project_id").annotate(c=Count("id")).values("c")[:1]
        )
        sta_sq = (
            StaticScansDb.objects.filter(project_id=OuterRef("id"))
            .values("project_id").annotate(c=Count("id")).values("c")[:1]
        )

        projects = (
            base.annotate(
                net_count=Coalesce(Subquery(net_sq, output_field=IntegerField()), 0),
                web_count=Coalesce(Subquery(web_sq, output_field=IntegerField()), 0),
                static_count=Coalesce(Subquery(sta_sq, output_field=IntegerField()), 0),
            )
            .order_by("project_name")
        )

        return render(request, self.template_name, {"projects": projects})

    def post(self, request):
        # Only Admin/superuser may delete
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        if not is_admin:
            messages.error(request, "You are not allowed to delete projects")
            return HttpResponseRedirect(reverse("projects:manage"))

        ids_raw = request.POST.get("project_ids") or request.data.get("project_ids") or ""
        ids = [s.strip() for s in str(ids_raw).split(",") if s and s.strip()]
        if not ids:
            messages.error(request, "No projects selected")
            return HttpResponseRedirect(reverse("projects:manage"))
        qs = ProjectDb.objects.filter(uu_id__in=ids, organization=request.user.organization)
        deleted = qs.count()
        qs.delete()  # cascades to scans/results via FK
        if deleted:
            messages.success(request, f"Deleted {deleted} project(s)")
        else:
            messages.warning(request, "No matching projects found")
        return HttpResponseRedirect(reverse("projects:manage"))
