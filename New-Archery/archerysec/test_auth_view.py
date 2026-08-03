import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'archerysecurity.settings.base')
import django
django.setup()

# Test the actual auth_view with proper request
from authentication.views import auth_view
from django.http import QueryDict, HttpRequest
from django.contrib.sessions.backends.db import SessionStore

# Create a proper request with session
request = HttpRequest()
request.method = 'POST'
request.POST = QueryDict('email=immah%40gmail.com&password=wXXTBTT7dHrU5p4e75cuXeAd5wQ&csrfmiddlewaretoken=test')
request.META = {}
request.session = SessionStore()
request.session.save()

# Add user attribute to request (simulating AuthenticationMiddleware)
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
User = get_user_model()

# Add a dummy user to request
request.user = authenticate(username='immah@gmail.com', password='wXXTBTT7dHrU5p4e75cuXeAd5wQ')

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
except Exception as e:
    print('Exception:', e)
    import traceback
    traceback.print_exc()