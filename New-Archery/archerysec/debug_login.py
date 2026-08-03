import requests

session = requests.Session()
r = session.get('http://127.0.0.1:8000/auth/login/')
csrf_token = session.cookies.get('csrftoken')
login_data = {
    'email': 'immah@gmail.com',
    'password': 'wXXTBTT7dHrU5p4e75cuXeAd5wQ',
    'csrfmiddlewaretoken': csrf_token
}
headers = {'Referer': 'http://127.0.0.1:8000/auth/login/'}
r = session.post('http://127.0.0.1:8000/auth/login/', data=login_data, headers=headers, allow_redirects=False)
text = r.text
idx = text.find('Traceback')
if idx >= 0:
    print(text[idx:idx+3000])