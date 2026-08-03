import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()

# Test the authenticate function directly
from django.contrib.auth import authenticate
user = authenticate(username='immah@gmail.com', password='wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('Direct authenticate:', user)

# Test the backend directly
from authentication.backends import EmailBackend
backend = EmailBackend()
user = backend.authenticate(None, username='immah@gmail.com', password='wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('Backend authenticate:', user)

# Test with request.POST simulation
from django.http import QueryDict
post_data = QueryDict('email=immah%40gmail.com&password=wXXTBTT7dHrU5p4e75cuXeAd5wQ')
print('QueryDict email:', post_data.get('email'))
print('QueryDict password:', post_data.get('password'))