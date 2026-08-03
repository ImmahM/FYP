import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()

# Test the full auth_view flow with debugging
from django.test import Client
from django.contrib.auth import authenticate, login
from django.http import HttpRequest
from django.contrib.sessions.backends.db import SessionStore

client = Client()
response = client.get('/auth/login/')
content = response.content.decode()

import re
csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.content.decode())
csrf_token = None
if csrf_match:
    csrf_token = csrf_match.group(1)
    print('CSRF token found:', csrf_token[:20] + '...')

# Now let's trace through what happens in auth_view
# We'll manually call the auth_view function
from authentication.views import auth_view
from django.http import QueryDict, HttpRequest
from django.contrib.sessions.backends.db import SessionStore

# Create a proper request
request = HttpRequest()
request.method = 'POST'
request.POST = QueryDict('email=immah%40gmail.com&password=wXXTBTT7dHrU5p4e75cuXeAd5wQ&csrfmiddlewaretoken=test')
request.META = {}
request.session = SessionStore()
request.session.save()

print('Session key before:', request.session.session_key)

# Call auth_view
from authentication.views import auth_view
from django.urls import reverse
from django.contrib import auth, messages

try:
    response = auth_view(request)
    print('Response status:', response.status_code)
    print('Response type:', type(response))
    print('Redirect URL:', response.url if hasattr(response, 'url') else 'N/A')
    print('Session after:', dict(request.session))
    print('User:', request.user)
except Exception as e:
    print('Exception:', e)
    import traceback
    traceback.print_exc()