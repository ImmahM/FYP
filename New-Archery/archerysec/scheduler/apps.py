from django.apps import AppConfig


class SchedulerConfig(AppConfig):
    name = "scheduler"
    verbose_name = "Archery Scheduler"

    def ready(self):
        try:
            from .background_tasks import bootstrap

            bootstrap()
        except Exception:
            # Avoid crashing migrations/management commands if scheduler bootstrap fails
            pass
