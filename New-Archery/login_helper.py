import re, sys
html = open("/tmp/login_page.html").read()
m = re.search(r"csrfmiddlewaretoken\s+value=\"([^\"]+)\"", html)
if m:
    token = m.group(1)
    print("CSRF:" + token)
    open("/tmp/csrf_token.txt", "w").write(token)
else:
    print("NO CSRF FOUND")
    print(html[:2000] if html else "empty")
