import logging
import re


class IgnoreSourceMap404(logging.Filter):
    """Silence noisy 404s for DevTools source maps and similar assets.

    Matches messages like:
      - "Not Found: /static/.../*.map"
      - "Not Found: /.well-known/appspecific/com.chrome.devtools.json"
    on the django.request logger.
    """

    _pattern = re.compile(
        r"Not Found:\s+(?:/.*\.map\b|/.well-known/appspecific/com\.chrome\.devtools\.json)",
        re.IGNORECASE,
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if record.name == "django.request":
                msg = record.getMessage()
                if self._pattern.search(msg):
                    return False
        except Exception:
            # Never block logs on filter errors
            return True
        return True

