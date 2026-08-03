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

url = (f"{BASE}/reports/download/?format=html"
    f"&project_id=1&scan_types=web"
    f"&sections=overview&sections=priority_targets&sections=web"
    f"&summary_fields=url&summary_fields=total&summary_fields=high"
    f"&summary_fields=medium&summary_fields=low"
    f"&vuln_table_fields=title&vuln_table_fields=cvss_score"
    f"&vuln_table_fields=severity"
    f"&vuln_meta_fields=title"
    f"&vuln_detail_sections=description"
    f"&scan_urls=https%3A%2F%2Fjuice-shop.herokuapp.com%2F")
resp = opener.open(url)
data = resp.read().decode("utf-8", errors="replace")

idx = data.find("Executive Summary")
if idx >= 0:
    print("=== Section around 'Executive Summary' ===")
    print(data[idx:idx+2000])
else:
    print("'Executive Summary' heading NOT FOUND")
    idx = data.find("overall_counts")
    if idx >= 0:
        print("Found overall_counts in data around:", idx)
        print(data[max(0,idx-200):idx+200])
    else:
        print("No overall_counts found either")
        # find has_scan_data
        if "has_scan_data" in data:
            print("has_scan_data found in data")
        # Check for any of our expected vars
        for v in ["risk_overview", "executive_narrative", "priority_analysis", "analysis_score"]:
            if v in data:
                print(f"  Found: {v}")
        print("\n--- First 3000 chars ---")
        print(data[:3000])
