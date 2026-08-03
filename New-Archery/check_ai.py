#!/usr/bin/env python3
import urllib.request, urllib.parse, re, sys
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:8991"
cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

resp = opener.open(f"{BASE}/auth/login/")
html = resp.read().decode()
idx = html.index("csrfmiddlewaretoken")
start = html.index('value="', idx) + 7
end = html.index('"', start)
csrf = html[start:end]

data = urllib.parse.urlencode({
    "csrfmiddlewaretoken": csrf,
    "email": "immah@gmail.com",
    "password": "wXXTBTT7dHrU5p4e75cuXeAd5wQ",
}).encode()
resp = opener.open(f"{BASE}/auth/auth/", data)
resp.read()
assert any(c.name == "sessionid" for c in cj), "login failed"

url = (f"{BASE}/reports/download/?format=html&project_id=1&scan_types=web"
    "&sections=overview&sections=priority_targets&sections=web"
    "&summary_fields=url&summary_fields=total&summary_fields=high"
    "&summary_fields=medium&summary_fields=low"
    "&vuln_table_fields=title&vuln_table_fields=cvss_score"
    "&vuln_table_fields=severity"
    "&vuln_meta_fields=title"
    "&vuln_detail_sections=description"
    "&scan_urls=https%3A%2F%2Fjuice-shop.herokuapp.com%2F")
resp = opener.open(url)
data = resp.read().decode("utf-8", errors="replace")

print(f"Size: {len(data)}")
print(f"Has 'executive_narrative': {'executive_narrative' in data}")
print(f"Has 'risk_overview': {'risk_overview' in data}")
print(f"Has 'priority_analysis': {'priority_analysis' in data}")

m = re.search(r"executive_narrative\"[^>]*>(.*?)</div>", data, re.DOTALL)
if m:
    text = re.sub(r"<[^>]+>", "", m.group(1)).strip()
    print(f"Narrative: {text[:200]}")
    print(f"Narrative length: {len(text)} chars")
else:
    # check if it's hidden by {% if %} condition
    for line in data.split("\n"):
        if "executive" in line.lower() or "narrative" in line.lower():
            print(f"  line: {line.strip()[:150]}")
    print("Narrative section NOT RENDERED in output")
    sys.exit(1)
