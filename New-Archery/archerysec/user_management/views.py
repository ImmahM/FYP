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


from datetime import datetime, timedelta
from django.utils import timezone
import re

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, get_object_or_404, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.db.utils import IntegrityError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from user_management import permissions
from user_management.models import *
from user_management.serializers import *


def _password_strength_valid(pw: str):
    """Validate password strength: >=8 chars, must include a letter, a number, and a symbol."""
    if not pw:
        return False, "Password is required."
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long."
    has_letter = re.search(r"[A-Za-z]", pw) is not None
    has_digit = re.search(r"\d", pw) is not None
    has_symbol = re.search(r"[^A-Za-z0-9]", pw) is not None
    if not (has_letter and has_digit and has_symbol):
        return False, "Password must include a letter, a number, and a symbol."
    return True, "OK"


def _is_ajax(request):
    try:
        return request.headers.get("x-requested-with") == "XMLHttpRequest" or request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest"
    except Exception:
        return False


class Users(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdminOrITUser,
    )

    def get(self, request, uu_id=None):
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(
            request.user, "is_superuser", False
        )
        if uu_id is None:
            qs = UserProfile.objects.all()
            # Organization Admins must be scoped to their own organization
            if not is_admin and str(getattr(request.user, "role", ""))  == "Organization Admin":
                qs = qs.filter(organization=request.user.organization)
            serialized_data = UserProfileSerializers(qs, many=True)
        else:
            try:
                user_profile = UserProfile.objects.get(uu_id=uu_id)
                # Organization Admins cannot access users outside their organization
                if (
                    not is_admin
                    and str(getattr(request.user, "role", ""))  == "Organization Admin"
                    and user_profile.organization_id != request.user.organization_id
                ):
                    return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
                serialized_data = UserProfileSerializers(user_profile, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)

    def delete(self, request, uu_id):
        try:
            target = UserProfile.objects.get(uu_id=uu_id)
        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )

        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(
            request.user, "is_superuser", False
        )
        if not is_admin:
            # Organization Admin can only delete users within same organization
            if str(getattr(request.user, "role", ""))  != "Organization Admin":
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
            if target.organization_id != request.user.organization_id:
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        target.delete()
        return Response({"message": "User Deleted"}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = UserCreatReqSerializers(data=request.data)
        serializer.is_valid()

        email = (request.data.get("email") or "").strip()
        organization = request.data.get("organization")
        password = request.data.get("password") or ""
        role = request.data.get("role")
        name = (request.data.get("name") or "").strip()

        errors = {}

        # Resolve organization for Organization Admins and validate org for Admins
        if str(getattr(request.user, "role", ""))  == "Organization Admin":
            organization = request.user.organization.id
        else:
            if not organization:
                errors["error_org"] = "Please select an organization."

        # Password policy
        ok, msg = _password_strength_valid(password)
        if not ok:
            errors["error_password"] = msg

        # Role policy for Organization Admins
        if str(getattr(request.user, "role", ""))  == "Organization Admin":
            allowed_roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"]).values_list("id", flat=True)
            try:
                role_id = int(role)
            except Exception:
                role_id = None
            if role_id not in list(allowed_roles):
                errors["error_role"] = "Not authorized to assign this role."

        # Email validation
        if not email:
            errors["error_email"] = "Email is required."
        else:
            if organization and UserProfile.objects.filter(email=email, organization_id=organization).exists():
                errors["error_email"] = "Email already used in this organization. Please choose another."
            elif UserProfile.objects.filter(email=email).exists():
                errors["error_email"] = "Email already in use. Please choose another."

        if errors:
            if _is_ajax(request):
                return Response({"ok": False, "errors": errors}, status=status.HTTP_400_BAD_REQUEST)
            for _k, _v in errors.items():
                messages.error(request, _v)
            request.session["add_user_form"] = {"posted_name": name, "posted_email": email, **errors}
            return HttpResponseRedirect(reverse("users:add_user"))

        # Create user
        try:
            UserProfile.objects.create_user(email, name, role, organization, password)
        except IntegrityError:
            if _is_ajax(request):
                return Response({"ok": False, "errors": {"error_email": "Email already in use. Please choose another."}}, status=status.HTTP_400_BAD_REQUEST)
            messages.error(request, "Email already in use. Please choose another.")
            request.session["add_user_form"] = {"posted_name": name, "posted_email": email, "error_email": "Email already in use. Please choose another."}
            return HttpResponseRedirect(reverse("users:add_user"))
        if _is_ajax(request):
            return Response({"ok": True, "redirect_url": "/users/list_user/"}, status=status.HTTP_200_OK)
        messages.success(request, "User Created")
        return HttpResponseRedirect("/users/list_user/")

    def put(self, request, uu_id):
        serializer = UserPutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        raw_password = request.data.get("password")
        password = None
        if raw_password:
            ok, msg = _password_strength_valid(raw_password)
            if not ok:
                return Response({"message": msg}, status=status.HTTP_400_BAD_REQUEST)
            password = make_password(raw_password)
        role = request.data.get("role")
        name = request.data.get("name")
        image = request.data.get("image")
        is_active = request.data.get("is_active")
        is_staff = request.data.get("is_staff")

        # Enforce same-organization constraint for Organization Admin edits
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(
            request.user, "is_superuser", False
        )
        if not is_admin and str(getattr(request.user, "role", ""))  == "Organization Admin":
            target = UserProfile.objects.filter(uu_id=uu_id).first()
            if not target:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
            if target.organization_id != request.user.organization_id:
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        update_map = {
            "email": email,
            "role": role,
            "name": name,
            "image": image,
            "is_active": is_active,
            "is_staff": is_staff,
            "organization": request.user.organization,
        }
        if password:
            update_map["password"] = password
        user_profile = UserProfile.objects.filter(uu_id=uu_id).update(**update_map)
        if user_profile > 0:
            return Response(
                {"message": "User Profile Updated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class InviteUserAPIView(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdminOrITUser,
    )

    def post(self, request):
        email = request.data.get("email")
        role = request.data.get("role")
        name = request.data.get("name")

        # Create a new user object with a random password
        password = UserProfile.objects.make_random_password()
        # Organization Admin can only invite within own organization
        user = UserProfile.objects.create_user(
            email=email,
            password=password,
            organization=request.user.organization.id,
            name=name,
            role=role,
        )
        token = default_token_generator.make_token(user)
        user.pass_token = token
        user.token_time = datetime.now() + timedelta(hours=24)
        user.save()
        user.is_active = False
        user.save()
        activation_link = self.generate_activation_link(request, user)
        try:
            send_invitation_email(user.email, activation_link)
            return Response(
                {
                    "message": "User invited successfully. Please check your email for activation instructions."
                },
                status=status.HTTP_201_CREATED,
            )
        except:
            return Response(
                {
                    "message": "Email Configuration not found",
                    "activation_link": activation_link,
                }
            )

    def generate_activation_link(self, request, user):
        uid = urlsafe_base64_encode(force_bytes(user.uu_id))
        token = user.pass_token
        return request.build_absolute_uri(
            reverse("archeryapi:activate-user", kwargs={"uid": uid, "token": token})
        )


class ResetUserPasswordAPIView(APIView):
    permission_classes = (

    )

    def post(self, request):
        email = request.data.get("email")

        user = UserProfile.objects.get(
            email=email
        )
        token = default_token_generator.make_token(user)
        user.pass_token = token
        user.token_time = datetime.now() + timedelta(hours=24)
        user.save()
        activation_link = self.generate_activation_link(request, user)
        try:
            send_invitation_email(user.email, activation_link)
            return Response(
                {
                    "message": "Reset Link will be sent if user exist. Please check your email for reset instructions."
                },
                status=status.HTTP_201_CREATED,
            )
        except:
            return Response(
                {
                    "message": "Email Configuration not found",
                    "activation_link": activation_link,
                }
            )

    def generate_activation_link(self, request, user):
        uid = urlsafe_base64_encode(force_bytes(user.uu_id))
        token = user.pass_token
        return request.build_absolute_uri(
            reverse("archeryapi:reset-password", kwargs={"uid": uid, "token": token})
        )


class UserActivateAPIView(APIView):
    permission_classes = ()

    def post(self, request, uid, token):
        # Decode user ID from the URL
        user_id = force_str(urlsafe_base64_decode(uid))

        try:
            # Find the user by user_id
            user = UserProfile.objects.get(uu_id=user_id)

        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Verify the token and check if it has expired
        if user.pass_token == token and user.token_time >= datetime.now():
            # Get user data from request body
            password = request.data.get("password")
            ok, msg = _password_strength_valid(password)
            if not ok:
                return Response({"message": msg}, status=status.HTTP_400_BAD_REQUEST)

            # Activate the user and set the new password
            user.is_active = True
            user.pass_token = default_token_generator.make_token(user)
            user.set_password(password)
            user.save()

            return Response(
                {
                    "message": "Account activated successfully. You can now login with your new password."
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"message": "Invalid or expired activation link."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UserPasswordResetAPIView(APIView):
    permission_classes = ()

    def post(self, request, uid, token):
        # Decode user ID from the URL
        user_id = force_str(urlsafe_base64_decode(uid))

        try:
            # Find the user by user_id
            user = UserProfile.objects.get(uu_id=user_id)

        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Verify the token and check if it has expired
        if user.pass_token == token and user.token_time >= datetime.now():
            # Get user data from request body
            password = request.data.get("password")
            ok, msg = _password_strength_valid(password)
            if not ok:
                return Response({"message": msg}, status=status.HTTP_400_BAD_REQUEST)

            # Activate the user and set the new password
            user.is_active = True
            user.pass_token = default_token_generator.make_token(user)
            user.set_password(password)
            user.save()

            return Response(
                {
                    "message": "Password reset successfully. You can now login with your new password."
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"message": "Invalid or expired activation link."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UsersList(APIView):
    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request, uu_id=None):
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        if uu_id == None:
            user_profile = UserProfile.objects.filter()
            # Non-admins (IT/User) see only their own organization
            if not is_admin:
                user_profile = user_profile.filter(organization=request.user.organization)
            serialized_data = UserProfileSerializers(user_profile, many=True)
        else:
            try:
                user_profile = UserProfile.objects.filter(uu_id=uu_id)
                if not is_admin:
                    user_profile = user_profile.filter(organization=request.user.organization)
                serialized_data = UserProfileSerializers(user_profile, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        if request.path[:4] == "/api":
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "users/list_users.html",
                {"all_users": user_profile},
            )

    def post(self, request):
        # Allow Admins or Organization Admins (Organization Admins limited to same organization)
        try:
            is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(
                request.user, "is_superuser", False
            )
        except Exception:
            is_admin = False
        is_it_user = (str(getattr(request.user, "role", "")) == "Organization Admin")
        if not is_admin and not is_it_user:
            messages.error(request, "Not authorized")
            return HttpResponseRedirect("/users/list_user/")
        try:
            user_id = request.data.get("user_id") or request.POST.get("user_id") or ""
            ids = [u.strip() for u in str(user_id).split(",") if u and u.strip()]
            if not ids:
                messages.error(request, "No user id(s) provided")
                return HttpResponseRedirect("/users/list_user/")
            qs = UserProfile.objects.filter(uu_id__in=ids)
            # Organization Admin may only delete users from their own organization
            if is_it_user and not is_admin:
                qs = qs.filter(organization=request.user.organization)
                # And they cannot delete Admin/superuser accounts
                qs = qs.exclude(is_superuser=True).exclude(role__role='Admin')
            deleted_count = qs.count()
            qs.delete()
            if deleted_count:
                messages.success(request, "User(s) deleted")
            else:
                messages.error(request, "User(s) not found")
            return HttpResponseRedirect("/users/list_user/")
        except Exception:
            messages.error(request, "Unable to delete user(s)")
            return HttpResponseRedirect("/users/list_user/")


class UsersEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "users/edit_user.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdminOrITUser,
    )

    def get(self, request, uu_id=None):
        org = Organization.objects.filter()
        is_super = getattr(request.user, "is_superuser", False)
        if (str(getattr(request.user, "role", "")) == "Organization Admin") and (not is_super):
            # Support legacy 'Analyst' naming as normal 'User'
            roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
        else:
            roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
        if uu_id == None:
            user_details = UserProfile.objects.filter()
            serialized_data = UserPutReqSerializers(user_details, many=True)
        else:
            try:
                print(uu_id)
                user_details = UserProfile.objects.filter(uu_id=uu_id)
                serialized_data = UserPutReqSerializers(user_details, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(
            {
                "serializer": serialized_data,
                "user_details": user_details,
                "user_uu_id": uu_id,
                "org": org,
                "roles": roles,
            }
        )

    def post(self, request, uu_id):
        serializer = UserPutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        role = request.data.get("role")
        name = request.data.get("name")
        image = request.data.get("image")
        organization = request.data.get("organization")
        pass_token = request.data.get("pass_token")

        update_fields = {
            "email": email,
            "role": role,
            "name": name,
            "image": image,
            "pass_token": pass_token,
            "organization": organization,
        }
        # Organization Admin: lock organization and restrict role assignment
        if str(getattr(request.user, "role", ""))  == "Organization Admin" and not getattr(request.user, "is_superuser", False):
            update_fields["organization"] = request.user.organization.id
            allowed_roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"]).values_list("id", flat=True)
            try:
                role_id = int(role)
            except Exception:
                role_id = None
            if role_id not in list(allowed_roles):
                if _is_ajax(request):
                    return Response({"ok": False, "errors": {"error_role": "Not authorized to assign this role."}}, status=status.HTTP_400_BAD_REQUEST)
                messages.error(request, "Not authorized to assign this role.")
                return HttpResponseRedirect(reverse("users:edit_user", kwargs={"uu_id": uu_id}))

        # Enforce email uniqueness within organization on edit
        desired_org_id = update_fields.get("organization")
        try:
            desired_org_id = int(getattr(desired_org_id, "id", desired_org_id))
        except Exception:
            pass
        if email:
            if (
                UserProfile.objects.filter(email=email, organization_id=desired_org_id)
                .exclude(uu_id=uu_id)
                .exists()
            ):
                if _is_ajax(request):
                    return Response({"ok": False, "errors": {"error_email": "Email already used in this organization. Please choose another."}}, status=status.HTTP_400_BAD_REQUEST)
                messages.error(request, "Email already used in this organization. Please choose another.")
                return HttpResponseRedirect(reverse("users:edit_user", kwargs={"uu_id": uu_id}))
        try:
            user_profile = UserProfile.objects.filter(uu_id=uu_id).update(**update_fields)
        except IntegrityError:
            if _is_ajax(request):
                return Response({"ok": False, "errors": {"error_email": "Email already in use. Please choose another."}}, status=status.HTTP_400_BAD_REQUEST)
            messages.error(request, "Email already in use. Please choose another.")
            return HttpResponseRedirect(reverse("users:edit_user", kwargs={"uu_id": uu_id}))
        if user_profile > 0:
            if _is_ajax(request):
                return Response({"ok": True, "redirect_url": "/users/list_user/"}, status=status.HTTP_200_OK)
            return HttpResponseRedirect("/users/list_user/")
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class UsersAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer, JSONRenderer]
    # Use a UTF-8 clean template variant with org shown first
    template_name = "users/add_user2.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdminOrITUser,
    )

    def get(self, request):
        org = Organization.objects.all()
        # Superusers should have full Admin capabilities regardless of their assigned role
        is_super = getattr(request.user, "is_superuser", False)
        role_name = str(getattr(request.user, "role", ""))
        if (role_name == "Organization Admin") and (not is_super):
            roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
        else:
            # Admin/superuser: allow assigning Admin too (exclude only Viewer)
            roles = UserRoles.objects.exclude(role__in=["Viewer"]) 

        form_state = request.session.pop("add_user_form", None)
        # Ensure expected keys exist for template defaults
        ctx = {
            "org": org,
            "roles": roles,
            "posted_name": "",
            "posted_email": "",
            "posted_org": "",
            "posted_role": "",
        }
        if form_state:
            ctx.update(form_state)
        return Response(ctx)

    def post(self, request):
        serializer = UserCreatReqSerializers(data=request.data)
        serializer.is_valid()

        email = request.data.get("email")
        organization = request.data.get("organization")
        password = request.data.get("password")
        password2 = request.data.get("password2")
        role = request.data.get("role")
        name = request.data.get("name")

        # Confirm password must match
        if password2 is None or str(password) != str(password2):
            org = Organization.objects.all()
            if str(getattr(request.user, "role", ""))  == "Organization Admin":
                roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
            else:
                roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
            messages.error(request, "Passwords do not match")
            return Response({
                "org": org,
                "roles": roles,
                "error_password2": "Passwords do not match.",
                "posted_name": name,
                "posted_email": email,
                "posted_org": organization,
                "posted_role": role,
            })

        ok, msg = _password_strength_valid(password)
        if not ok:
            # Inline error rendering
            org = Organization.objects.all()
            if str(getattr(request.user, "role", ""))  == "Organization Admin":
                roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
            else:
                roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
            messages.error(request, msg)
            return Response({
                "org": org,
                "roles": roles,
                "error_password": msg,
                "posted_name": name,
                "posted_email": email,
                "posted_org": organization,
                "posted_role": role,
            })

        user_exist = UserProfile.objects.filter(email=email).exists()
        if user_exist:
            # Global email unique exists; show friendly message
            org = Organization.objects.all()
            if str(getattr(request.user, "role", ""))  == "Organization Admin":
                roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
            else:
                roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
            messages.error(request, "Email already in use. Please choose another.")
            return Response({
                "org": org,
                "roles": roles,
                "error_email": "Email already in use. Please choose another.",
                "posted_name": name,
                "posted_email": email,
                "posted_org": organization,
                "posted_role": role,
            })
        else:
            # Organization Admins may only create users in their own organization and cannot assign Admin
            # Superusers are exempt from this restriction
            if str(getattr(request.user, "role", ""))  == "Organization Admin" and not getattr(request.user, "is_superuser", False):
                organization = request.user.organization.id
                allowed_roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"]).values_list("id", flat=True)
                try:
                    role_id = int(role)
                except Exception:
                    role_id = None
                if role_id not in list(allowed_roles):
                    org = Organization.objects.all()
                    roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
                    messages.error(request, "Not authorized to assign this role.")
                    return Response({
                        "org": org,
                        "roles": roles,
                        "error_role": "Not authorized to assign this role.",
                        "posted_name": name,
                        "posted_email": email,
                        "posted_org": organization,
                        "posted_role": role,
                    })
            # Enforce email uniqueness within organization (plus global unique already exists)
            if UserProfile.objects.filter(email=email, organization_id=organization).exists():
                org = Organization.objects.all()
                if str(getattr(request.user, "role", ""))  == "Organization Admin":
                    roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
                else:
                    roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
                messages.error(request, "Email already used in this organization. Please choose another.")
                return Response({
                    "org": org,
                    "roles": roles,
                    "error_email": "Email already used in this organization. Please choose another.",
                    "posted_name": name,
                    "posted_email": email,
                    "posted_org": organization,
                    "posted_role": role,
                })
            try:
                UserProfile.objects.create_user(email, name, role, organization, password)
            except IntegrityError:
                org = Organization.objects.all()
                if str(getattr(request.user, "role", ""))  == "Organization Admin":
                    roles = UserRoles.objects.filter(role__in=["User", "Analyst", "Organization Admin"])  # restrict
                else:
                    roles = UserRoles.objects.exclude(role__in=["Viewer"]) 
                messages.error(request, "Email already in use. Please choose another.")
                return Response({
                    "org": org,
                    "roles": roles,
                    "error_email": "Email already in use. Please choose another.",
                    "posted_name": name,
                    "posted_email": email,
                    "posted_org": organization,
                    "posted_role": role,
                })
            messages.success(request, "User Created")
            return HttpResponseRedirect("/users/list_user/")


class Profile(APIView):
    # renderer_classes = [TemplateHTMLRenderer]
    # template_name = "profile/profile.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsOwnerOrAdminOnly,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        id = request.user.id
        user_profile = UserProfile.objects.filter(id=id)
        serialized_data = UserProfileSerializers(user_profile, many=False)
        if request.path[:4] == "/api":
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return render(request, "profile/profile.html", {"profiles": user_profile})
        # return Response({"serializer": serializer, "profiles": user_profile})

    def put(self, request, uu_id):
        serializer = UserProfilePutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = make_password(request.data.get("password"))
        name = request.data.get("name")
        image = request.data.get("image")

        id = request.user.id

        user_profile = UserProfile.objects.filter(id=id).update(
            password=password,
            name=name,
            image=image,
        )
        if user_profile > 0:
            return Response(
                {"message": "User Profile Updated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )

    def post(self, request):
        """Allow the current user to change their own password via simple form."""
        old_password = request.POST.get("old_password")
        new_password1 = request.POST.get("new_password1")
        new_password2 = request.POST.get("new_password2")
        if not old_password or not new_password1 or not new_password2:
            messages.error(request, "All password fields are required")
            return HttpResponseRedirect(reverse("users:profile"))
        if new_password1 != new_password2:
            messages.error(request, "New passwords do not match")
            return HttpResponseRedirect(reverse("users:profile"))
        if not request.user.check_password(old_password):
            messages.error(request, "Incorrect current password")
            return HttpResponseRedirect(reverse("users:profile"))
        try:
            request.user.set_password(new_password1)
            request.user.save()
            messages.success(request, "Password updated")
            return HttpResponseRedirect(reverse("users:profile"))
        except Exception:
            messages.error(request, "Unable to change password")
            return HttpResponseRedirect(reverse("users:profile"))


class SelfPasswordUpdateView(APIView):
    """
    Allow users, Admins, and Organization Admins to change passwords from the list view modal.
    """

    permission_classes = (IsAuthenticated,)

    def post(self, request):
        redirect_url = reverse("users:list_user")
        target_uuid = request.POST.get("user_uuid")

        if not target_uuid:
            messages.error(request, "Missing user reference.")
            return HttpResponseRedirect(redirect_url)

        target_user = get_object_or_404(UserProfile, uu_id=target_uuid)
        requester = request.user
        role_name = str(getattr(requester, "role", ""))
        is_super = getattr(requester, "is_superuser", False)
        is_admin = is_super or role_name == "Admin"
        is_org_admin = role_name == "Organization Admin"

        requester_org_id = getattr(getattr(requester, "organization", None), "id", None)
        target_org_id = getattr(getattr(target_user, "organization", None), "id", None)

        allowed = (
            target_user == requester
            or is_admin
            or (is_org_admin and requester_org_id and requester_org_id == target_org_id)
        )
        if not allowed:
            messages.error(request, "You are not allowed to change this password.")
            return HttpResponseRedirect(redirect_url)

        old_password = request.POST.get("old_password")
        new_password1 = request.POST.get("new_password1")
        new_password2 = request.POST.get("new_password2")

        requires_old = target_user == requester and not is_admin and not is_org_admin

        if requires_old and not old_password:
            messages.error(request, "Current password is required.")
            return HttpResponseRedirect(redirect_url)

        if requires_old and not requester.check_password(old_password):
            messages.error(request, "Incorrect current password.")
            return HttpResponseRedirect(redirect_url)

        if not new_password1 or not new_password2:
            messages.error(request, "New password fields are required.")
            return HttpResponseRedirect(redirect_url)

        if new_password1 != new_password2:
            messages.error(request, "Passwords do not match.")
            return HttpResponseRedirect(redirect_url)

        ok, msg = _password_strength_valid(new_password1)
        if not ok:
            messages.error(request, msg)
            return HttpResponseRedirect(redirect_url)

        try:
            target_user.set_password(new_password1)
            target_user.password_updt_time = timezone.now()
            target_user.save(update_fields=["password", "password_updt_time"])
            if target_user == requester:
                update_session_auth_hash(request, target_user)
            messages.success(request, "Password updated.")
        except Exception:
            messages.error(request, "Unable to change password.")

        return HttpResponseRedirect(redirect_url)


class Roles(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsViewer,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_role = UserRoles.objects.exclude(role__in=["Viewer"])  # hide viewer; 'Analyst' shown as 'User' via filter
            serialized_data = UserRoleSerializers(user_role, many=True)
        else:
            try:
                user_role = UserRoles.objects.get(uu_id=uu_id)
                serialized_data = UserRoleSerializers(user_role, many=False)
            except UserRoles.DoesNotExist:
                return Response(
                    {"message": "User Role Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)


class OrganizationDetail(APIView):
    renderer_classes = [TemplateHTMLRenderer, JSONRenderer]
    template_name = "organization/org_list.html"

    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        organization = Organization.objects.all()
        serialized_data = OrganizationSerializers(organization, many=False)
        return Response({"serializer": serialized_data, "organization": organization})

    def post(self, request):
        is_admin = (str(getattr(request.user, "role", "")) == "Admin") or getattr(request.user, "is_superuser", False)
        if not is_admin:
            messages.error(request, "Not authorized")
            return HttpResponseRedirect('/users/list_org/')
        try:
            raw_ids = request.data.get("org_id") or request.POST.get("org_id") or ""
            ids = [u.strip() for u in str(raw_ids).split(",") if u and u.strip()]
            if not ids:
                messages.error(request, "No organization id(s) provided")
                return HttpResponseRedirect('/users/list_org/')
            qs = Organization.objects.filter(uu_id__in=ids)
            deleted_count = qs.count()
            qs.delete()
            if deleted_count:
                messages.success(request, "Organization(s) deleted")
            else:
                messages.error(request, "Organization(s) not found")
            return HttpResponseRedirect('/users/list_org/')
        except Exception:
            messages.error(request, "Unable to delete selected organization(s)")
            return HttpResponseRedirect('/users/list_org/')
class OrgAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer, JSONRenderer]
    template_name = "organization/org_add.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        org = Organization.objects.all()
        form_state = request.session.pop("add_org_form", None)
        ctx = {"org": org}
        if form_state:
            ctx.update(form_state)
        return Response(ctx)

    def post(self, request):
        serializer = OrganizationSerializers(data=request.data)
        serializer.is_valid()

        name = (request.data.get("name") or "").strip()
        description = request.data.get("description") or ""

        errors = {}
        if not name:
            errors["error_name"] = "Organization name is required."
        elif Organization.objects.filter(name__iexact=name).exists():
            errors["error_name"] = "Organization name already taken. Please choose another name."

        if errors:
            if _is_ajax(request):
                return Response({"ok": False, "errors": errors}, status=status.HTTP_400_BAD_REQUEST)
            for _k, _v in errors.items():
                messages.error(request, _v)
            request.session["add_org_form"] = {"posted_name": name, "posted_description": description, **errors}
            return HttpResponseRedirect(reverse("users:add_org"))

        save_org = Organization(name=name, description=description)
        save_org.save()
        if _is_ajax(request):
            return Response({"ok": True, "redirect_url": "/users/list_org/"}, status=status.HTTP_200_OK)
        messages.success(request, "Organization created.")
        return HttpResponseRedirect("/users/list_org/")


class OrgEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer, JSONRenderer]
    template_name = "organization/org_edit.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            org_details = Organization.objects.get(uu_id=uu_id)
            serialized_data = CreateOrganizationSerializers(org_details, many=True)
        else:
            try:
                org_details = Organization.objects.get(uu_id=uu_id)
                serialized_data = CreateOrganizationSerializers(org_details, many=False)
            except UserProfile.DoesNotExist:
                return Response(template_name="error/404.html")
        return Response({"serializer": serialized_data, "org_details": org_details})

    def post(self, request, uu_id):
        serializer = CreateOrganizationSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("name")
        description = request.data.get("description")
        # Enforce unique organization name (case-insensitive) when editing
        if Organization.objects.filter(name__iexact=str(name).strip()).exclude(uu_id=uu_id).exists():
            if _is_ajax(request):
                return Response({"ok": False, "errors": {"error_name": "Organization name already taken. Please choose another name."}}, status=status.HTTP_400_BAD_REQUEST)
            messages.error(request, "Organization name already taken. Please choose another name.")
            return HttpResponseRedirect(reverse("users:edit_org", kwargs={"uu_id": uu_id}))
        org_add = Organization.objects.filter(uu_id=uu_id).update(
            name=name,
            description=description,
        )
        if org_add > 0:
            if _is_ajax(request):
                return Response({"ok": True, "redirect_url": "/users/list_org/"}, status=status.HTTP_200_OK)
            return HttpResponseRedirect("/users/list_org/")
        else:
            return Response(
                {"message": "Org Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class NotificationPrefsUpdate(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        prefs = {
            "notify_email": request.POST.get("notify_email") == "true",
            "notify_in_app": request.POST.get("notify_in_app") == "true",
            "notify_on_scan_start": request.POST.get("notify_on_scan_start") == "true",
            "notify_on_scan_complete": request.POST.get("notify_on_scan_complete") == "true",
            "notify_on_scan_fail": request.POST.get("notify_on_scan_fail") == "true",
            "notify_critical_only": request.POST.get("notify_critical_only") == "true",
        }
        UserProfile.objects.filter(id=request.user.id).update(**prefs)
        messages.success(request, "Notification preferences updated")
        return HttpResponseRedirect(reverse("users:profile"))


def send_invitation_email(email, activation_link):
    subject = "Invitation to Activate Your Account"
    message = f"Please click the following link to activate your account and set a new password:\n{activation_link}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])


