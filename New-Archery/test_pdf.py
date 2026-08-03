#!/usr/bin/env python3
import os, re, sys
import urllib.request, urllib.parse
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:8991"
OUT = os.path.join(os.environ.get("TEMP", "."), "archery_test")
os.makedirs(OUT, exist_ok=True)
cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. GET login page for CSRF
resp = opener.open(f"{BASE}/auth/login/")
html = resp.read().decode("utf-8")
print("len:", len(html), "csrf:", "csrfmiddlewaretoken" in html)
idx = html.find("csrfmiddlewaretoken")
if idx < 0:
    print("NO CSRF")
    sys.exit(1)
start = html.index('value="', idx) + 7
end = html.index('"', start)
csrf = html[start:end]
print("CSRF:", csrf[:20])

# 2. POST auth
data = urllib.parse.urlencode({
    "csrfmiddlewaretoken": csrf,
    "email": "immah@gmail.com",
    "password": "wXXTBTT7dHrU5p4e75cuXeAd5wQ",
}).encode()
resp = opener.open(f"{BASE}/auth/auth/", data)
print("Auth code:", resp.getcode(), "url:", resp.geturl())
resp.read()
print("Cookies:", [f"{c.name}={c.value[:15]}" for c in cj])

session = [c for c in cj if c.name == "sessionid"]
if not session:
    print("LOGIN FAILED")
    sys.exit(1)

# Common query params
common = ("&sections=overview&sections=coverage&sections=priority_targets"
    "&sections=web&sections=network&scan_types=web"
    "&summary_fields=url&summary_fields=status&summary_fields=scanner"
    "&summary_fields=total&summary_fields=high&summary_fields=medium"
    "&summary_fields=low&summary_fields=duplicates"
    "&vuln_table_fields=title&vuln_table_fields=cvss_score"
    "&vuln_table_fields=cvss_severity&vuln_table_fields=status"
    "&vuln_table_fields=risk"
    "&vuln_meta_fields=title&vuln_meta_fields=risk&vuln_meta_fields=status"
    "&vuln_detail_sections=description&vuln_detail_sections=solution"
    "&vuln_detail_sections=reference"
    "&scan_urls=https%3A%2F%2Fjuice-shop.herokuapp.com%2F")

tests = [
    ("pdf",  "application/pdf",  b"%PDF"),
    ("html", "text/html",        b"<!DOCTYPE html>"),
    ("csv",  "text/csv",         None),
    ("xml",  "application/xml",  b"<?xml"),
]

all_ok = True
for fmt, expected_type, magic in tests:
    url = f"{BASE}/reports/download/?format={fmt}&project_id=1{common}"
    print(f"\n--- Fetching {fmt.upper()} ---")
    resp = opener.open(url)
    data = resp.read()
    ct = resp.headers.get("Content-Type", "")
    print(f"  Code: {resp.getcode()}  Type: {ct}  Size: {len(data)}")
    if expected_type and expected_type not in ct:
        print(f"  FAIL: expected content type {expected_type}")
        all_ok = False
    if magic and magic not in data[:50]:
        print(f"  FAIL: expected magic bytes {magic!r}, got {data[:30]!r}")
        all_ok = False
    fpath = os.path.join(OUT, f"report.{fmt}")
    with open(fpath, "wb") as f:
        f.write(data)
    print(f"  Saved to {fpath}")

print(f"\n{'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")
sys.exit(0 if all_ok else 1)
