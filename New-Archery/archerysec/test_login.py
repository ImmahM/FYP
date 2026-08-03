import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()
from django.test import Client
import re

client = Client()
response = client.get('/auth/login/')
print('GET status:', response.status_code)

content = response.content.decode()
csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', content)
if csrf_match:
    csrf_token = csrf_match.group(1)
    print('CSRF token:', csrf_token[:20] + '...')
    
    response = client.post('/auth/login/', {
        'email': 'immah@gmail.com',
        'password': 'wXXTBTT7dHrU5p4e75cuXeAd5wQ',
        'csrfmiddlewaretoken': csrf_token
    }, follow=True)
    print('POST status:', response.status_code)
    print('Redirect chain:', response.redirect_chain)
    print('User:', response.wsgi_request.user)
    print('Session keys:', list(response.wsgi_request.session.keys()))
else:
    print('No CSRF token found')