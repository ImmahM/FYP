from django.db import IntegrityError

from scanners.models import AuditLog


def log_action(request, action, resource_type="", resource_id="", details=None):
    try:
        user = getattr(request, "user", None)
        if user and not user.is_authenticated:
            user = None
    except Exception:
        user = None

    ip_address = None
    if request:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.META.get("REMOTE_ADDR")

    user_agent = request.META.get("HTTP_USER_AGENT", "") if request else ""

    try:
        AuditLog.objects.create(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else "",
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except IntegrityError:
        pass
