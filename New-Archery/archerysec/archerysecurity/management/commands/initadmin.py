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


from django.conf import settings
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
class Command(BaseCommand):
    def handle(self, *args, **options):
        # Only operate for the default auth.User. This project uses a
        # custom user model (user_management.UserProfile) with different
        # required fields, so we skip to avoid runtime errors.
        if getattr(settings, "AUTH_USER_MODEL", "auth.User") != "auth.User":
            self.stdout.write("initadmin: custom user model in use; skipping")
            return

        User = get_user_model()
        if User.objects.count() == 0:
            for user in settings.ADMINS:
                username = user[0].replace(" ", "")
                email = user[1]
                password = "admin"
                User.objects.create_superuser(username, email, password)
        else:
            self.stdout.write(
                "Admin accounts can only be initialized if no Accounts exist"
            )
