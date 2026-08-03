from django.apps import AppConfig


class ScannersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanners"
    verbose_name = "Unified Scanners"

    def ready(self):
        # Import signals if needed
        pass