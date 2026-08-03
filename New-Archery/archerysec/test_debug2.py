import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()

# Test the entire flow with Django test client with full debugging
from django.test import Client
from django.contrib.auth import authenticate, login

client = Client()

# 1. Get login page
response = client.get('/auth/login/')
print('GET /auth/login/ - status:', response.status_code)

# 2. Get CSRF token
import re
content = response.content.decode()
csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.content.decode())
csrf_token = None
if csrf_match:
    csrf_token = csrf_match.group(1)
    print('CSRF token found:', csrf_token[:20] + '...')

# 3. Post login
response = client.post('/auth/login/', {
    'email': 'immah@gmail.com',
    'password': 'wXXTBTT7dHrU5p4e75cuXeAd5wQ',
    'csrfmiddlewaretoken': csrf_token
}, follow=True)

print('POST status:', response.status_code)
print('Redirect chain:', response.redirect_chain)
print('Final URL:', response.url if hasattr(response, 'url') else 'N/A')
print('User:', response.wsgi_request.user)
print('Session keys:', list(response.wsgi_request.session.keys()))
print('Session session_key:', response.wsgi_request.session.session_key if response.wsgi_request.session else 'None')

# Debug: Check what request.POST contains in auth_view
# Let's manually trace through the auth_view logic
from django.http import QueryDict
from django.contrib.auth import authenticate

# Simulate what auth_view does
post_data = QueryDict('email=immah%40gmail.com&password=wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('QueryDict email:', post_data.get('email'))
print('QueryDict password:', post_data.get('password'))

# Test authenticate with the same data
from django.contrib.auth import authenticate
user = authenticate(username='immah@gmail.com', password='wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('Authenticate result:', user)

# Test with request.POST simulation
from django.http import HttpRequest
from django.contrib.auth import auth

request = HttpRequest()
request.POST = QueryDict('email=immah%40gmail.com&password=wXXTBTT7dHrU5p4e75cuXeAd5wQ')
request.method = 'POST'
request.META = {}

# Test what auth.authenticate gets
email = request.POST.get('email', '')
password = request.POST.get('password', '')
print('Request.POST email:', email)
print('Request.POST password:', password[:5] + '...' if password else 'None')

user = authenticate(username=email, password=password)
print('Authenticate result:', user)