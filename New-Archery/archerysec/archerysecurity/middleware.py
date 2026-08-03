from django.utils.deprecation import MiddlewareMixin


class NoCacheMiddleware(MiddlewareMixin):
    """
    Prevent browsers from serving cached authenticated pages after logout/back.
    Adds no-store headers to all HTML responses (safe for our use), or at
    minimum for authenticated users.
    """

    def process_response(self, request, response):
        try:
            # Only set for authenticated sessions and HTML-ish responses
            content_type = (response.get("Content-Type", "") or "").lower()
            is_html = content_type.startswith("text/html") or content_type.startswith("application/xhtml")
            if is_html:
                response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                response["Pragma"] = "no-cache"
                response["Expires"] = "0"
                response["Vary"] = ", ".join(sorted(set(filter(None, [response.get("Vary"), "Cookie"]))))
        except Exception:
            pass
        return response

