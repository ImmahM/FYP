import requests, json

accounts = [
    ('immah@gmail.com', 'wXXTBTT7dHrU5p4e75cuXeAd5wQ', 'Admin+Superuser'),
    ('testadmin@testorg.com', 'TestPass123!', 'OrgA Admin'),
    ('testorgadmin@testorg.com', 'TestPass123!', 'OrgA OrgAdmin'),
    ('testusera@testorg.com', 'TestPass123!', 'OrgA Analyst'),
    ('testuserb@testorg.com', 'TestPass123!', 'OrgA Analyst'),
    ('testuserc@testorg2.com', 'TestPass123!', 'OrgB Analyst'),
    ('testorgb@testorg.com', 'TestPass123!', 'OrgB OrgAdmin'),
    ('testdisabled@testorg.com', 'TestPass123!', 'Disabled'),
]

for email, pwd, role in accounts:
    r = requests.post('http://localhost:8000/api/v1/auth/login/', json={'email': email, 'password': pwd})
    if r.status_code == 200:
        token = r.json()['access']
        h = {'Authorization': f'Bearer {token}'}
        r2 = requests.get('http://localhost:8000/api/v1/project-list/', headers=h)
        projs = r2.json()
        plist = projs if isinstance(projs, list) else projs.get('results', [])
        pname = [p.get('project_name') or p.get('project_disc') or '?' for p in plist]
        print(f'  OK  {role:20} {email:30} projects={pname}')
    else:
        status = r.status_code
        detail = r.json().get('detail', r.text[:80])
        print(f'FAIL  {role:20} {email:30} {status} {detail}')
