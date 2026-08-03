from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def is_analyst_staff(context):
    """Treat 'User' or 'Organization Admin' as analyst-equivalent for staff checks."""
    user = context["request"].user
    try:
        role_name = str(getattr(user, "role", ""))
    except Exception:
        role_name = ""
    if role_name in ("User", "Organization Admin") and getattr(user, "is_staff", False):
        return True
    return False


@register.filter(name='role_display')
def role_display(value):
    """Normalize legacy role names for display."""
    if str(value) == "Analyst":
        return "User"
    return value


@register.filter(name="user_scan_type")
def user_scan_type(value, fallback="Scan"):
    """Return a scanner-agnostic scan type for non-admin views.

    Strips leading scanner names like "ZAP ", "Nikto ", "OpenVAS ", or "Nmap ".
    If the resulting value is empty, returns the provided fallback (defaults to "Scan").
    """
    try:
        s = (value or "").strip()
    except Exception:
        s = ""
    if not s:
        return fallback
    low = s.lower()
    prefixes = ["zap", "nikto", "openvas", "nmap", "openvas-scanner", "openvasscanner"]
    for p in prefixes:
        if low.startswith(p):
            # remove the prefix and common separators
            s = s[len(p):]
            s = s.lstrip("-: ")
            break
    s = s.strip()
    return s or fallback


@register.filter(name="demojibake")
def demojibake(value):
    """Replace common UTF-8 mojibake sequences with intended punctuation.

    Helps PDF exports where text from mis-decoded sources contains sequences
    like 'â€“', 'â€”', 'â€˜', 'â€™', 'â€œ', 'â€', 'Â', etc.
    """
    try:
        s = str(value)
    except Exception:
        return value
    replacements = {
        "â€“": "–",  # en dash
        "â€”": "—",  # em dash
        "â€˜": "‘",  # left single quote
        "â€™": "’",  # right single quote
        "â€œ": "“",  # left double quote
        "â€": "”",  # right double quote
        "â€¢": "•",  # bullet
        "Â": "",    # stray padding
        "â€¦": "…",  # ellipsis
        "â€": '"',   # generic smart quote fallback
        # common stray glyphs observed in PDFs
        "º": "•",    # masculine ordinal used as bullet in some sources
        "°": "•",    # degree sign used as bullet
        "'º": "•",   # quote + stray glyph -> plain bullet
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    return s
