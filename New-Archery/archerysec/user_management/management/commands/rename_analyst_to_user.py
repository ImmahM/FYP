# -*- coding: utf-8 -*-
"""
Management command to migrate the role name 'Analyst' to 'User'.

Safe/idempotent:
- If a 'User' role already exists, reassign any users linked to 'Analyst' to 'User'.
- If 'User' does not exist, rename 'Analyst' to 'User'.
- If neither exists, no action.

Usage:
    python manage.py rename_analyst_to_user
"""

from django.core.management.base import BaseCommand

from user_management.models import UserProfile, UserRoles


class Command(BaseCommand):
    help = "Rename 'Analyst' role to 'User' and migrate users accordingly."

    def handle(self, *args, **options):
        analyst = UserRoles.objects.filter(role="Analyst").first()
        user_role = UserRoles.objects.filter(role="User").first()

        if not analyst and not user_role:
            self.stdout.write(self.style.WARNING("No 'Analyst' or 'User' role found; nothing to do."))
            return

        if analyst and user_role:
            # Reassign all users pointing to Analyst to point to User
            moved = UserProfile.objects.filter(role=analyst).update(role=user_role)
            # Optionally delete the old Analyst role if no longer in use
            remaining = UserProfile.objects.filter(role=analyst).count()
            if remaining == 0:
                analyst.delete()
            self.stdout.write(self.style.SUCCESS(f"Reassigned {moved} user(s) from 'Analyst' to 'User'."))
            return

        if analyst and not user_role:
            # Rename Analyst to User
            old = analyst.role
            analyst.role = "User"
            analyst.save(update_fields=["role"])
            self.stdout.write(self.style.SUCCESS(f"Renamed role '{old}' to 'User'."))
            return

        if user_role and not analyst:
            self.stdout.write(self.style.SUCCESS("'User' role already present; nothing to migrate."))
            return

