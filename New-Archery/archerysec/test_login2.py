import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()
from django.test import Client

client = Client()
response = client.get('/auth/login/')
content = response.content.decode()

import re
csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', content)
csrf_token = csrf_match.group(1) if csrf_match else None

print('CSRF token:', csrf_token[:20] + '...' if csrf_token else 'None')

# Post with debug
from django.test import Client
from django.conf import settings
from django.contrib.auth import authenticate

client = Client()
response = client.post('/auth/login/', {
    'email': 'immah@gmail.com',
    'password': 'wXXTBTT7dHrU5p4e75cuXeAd5wQ',
    'csrfmiddlewaretoken': re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', client.get('/auth/login/').content.decode()).group(1)
}, follow=True)

print('POST status:', response.status_code)
print('Redirect chain:', response.redirect_chain)
print('User:', response.wsgi_request.user)
print('Session keys:', list(response.wsgi_request.session.keys()))

# Debug: check what the request.POST contains
from django.contrib.auth import authenticate
user = authenticate(username='immah@gmail.com', password='wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('Direct authenticate:', user)