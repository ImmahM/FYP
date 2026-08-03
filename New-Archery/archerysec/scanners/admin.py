from django.contrib import admin

from scanners.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ["created_at", "action", "user", "resource_type", "resource_id", "ip_address"]
    list_filter = ["action", "resource_type", "created_at"]
    search_fields = ["user__email", "resource_id", "details"]
    readonly_fields = ["id", "created_at", "user", "action", "resource_type", "resource_id", "details", "ip_address", "user_agent"]
    date_hierarchy = "created_at"
    ordering = ["-created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        if obj is not None:
            return False
        return super().has_change_permission(request, obj)
