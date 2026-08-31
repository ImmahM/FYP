#!/bin/bash

# Fail fast on any error and undefined var; catch pipeline errors
set -euo pipefail

export DJANGO_DEBUG=1

# Ensure DJANGO_SETTINGS_MODULE is sane and trimmed
if [ -n "$DJANGO_SETTINGS_MODULE" ]; then
  DJANGO_SETTINGS_MODULE="$(echo -n "$DJANGO_SETTINGS_MODULE" | xargs)"
  export DJANGO_SETTINGS_MODULE
else
  export DJANGO_SETTINGS_MODULE="archerysecurity.settings.production"
fi
echo "Using DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE"

# wait for Postgres to be available (when configured)
if [ -z "${DB_HOST:-}" ]; then
  echo "DB_HOST not set; skipping Postgres wait"
else
  until PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -c '\q' >/dev/null 2>&1; do
    >&2 echo "Postgres is unavailable - sleeping"
    sleep 1
  done
  >&2 echo "Postgres is up"
fi

# Only the web role should perform migrations to avoid race conditions.
if [ "${ARCHERY_WORKER:-False}" != "True" ]; then
  echo "Running migrations (tolerating errors for already-applied schemas)"
  python3 manage.py migrate --noinput || {
    echo "WARN: migrate --noinput encountered errors; faking remaining and retrying"
    python3 manage.py migrate --fake || true
    python3 manage.py migrate --noinput || echo "WARN: migrate still failing; app will start anyway"
  }
  echo "Collecting static"
  python3 manage.py collectstatic --noinput
fi

echo "Checking Variables"
if [ -z "$NAME" ]
then
      echo "\$NAME is empty, Please Provide User Name. Ex NAME=user"
      exit 1
else
      echo "\$NAME Found"
fi

if [ -z "$EMAIL" ]
then
      echo "\$EMAIL is empty, Please Provide User Name. Ex EMAIL=user@user.com"
      exit 1
else
      echo "\$EMAIL Found"
fi

if [ -z "$PASSWORD" ]
then
      echo "\$PASSWORD is empty, Please Provide User Name. Ex PASSWORD=userpassword"
      exit 1
else
      echo "\$PASSWORD Found"
fi


if [ "${ARCHERY_WORKER:-False}" = "True" ]
then
    # Ensure DB and at least core tables exist before starting worker
    if [ -n "${DB_HOST:-}" ]; then
      echo "Worker waiting for django_session table to be present"
      until PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='django_session'" | grep -q 1; do
        sleep 1
      done
      echo "django_session table present (worker)"
    fi
    # The scheduler uses in-process threading.Timer (scheduler/background_tasks.py).
    # Keep the container alive so gunicorn's scheduler threads continue firing.
    echo "Worker container started — in-process scheduler handles execution."
    exec tail -f /dev/null
else
    echo 'Seeding default roles (idempotent)'
    echo "from user_management.models import UserRoles; data=[('Admin','Admin can manage organization level site'),('Analyst','Analyst can create scannings'),('Viewer','Viewers can only view dashboards'),('Organization Admin','Can manage users and settings within their organization')];
for r,d in data:
    UserRoles.objects.get_or_create(role=r, defaults={'description': d})" | python3 manage.py shell
    echo 'Ensure default organization and superuser'
    cat <<PYCODE | python3 manage.py shell
from user_management.models import UserProfile, UserRoles, Organization
from archerysettings.models import ZapSettingsDb
email = "${EMAIL}"
name = "${NAME}"
password = "${PASSWORD}"
org, _ = Organization.objects.get_or_create(
    name='default',
    defaults={'description':'Default Organization','logo':'default_logo','contact':'','address':'default'}
)
role = UserRoles.objects.filter(role='Organization Admin').first() or UserRoles.objects.filter(role='Admin').first()
if not role:
    role = UserRoles.objects.create(role='Organization Admin', description='Can manage users and settings within their organization')
if not UserProfile.objects.filter(email=email).exists():
    UserProfile.objects.create_superuser(email=email, name=name, role=role.id, organization=org.id, password=password)
else:
    print('Superuser already exists for', email)

# Ensure a default ZAP setting points at the bundled zaproxy container
try:
    zs = ZapSettingsDb.objects.filter(organization=org).first()
    if zs is None:
        ZapSettingsDb.objects.create(
            zap_url='zapscanner',
            zap_api='none',
            zap_port=8090,
            enabled=True,
            organization=org,
            created_by=UserProfile.objects.filter(is_superuser=True).first(),
            updated_by=UserProfile.objects.filter(is_superuser=True).first(),
        )
        print('Seeded default ZAP settings -> zapscanner:8090 (enabled)')
    else:
        print('ZAP settings already present')
except Exception as e:
    print('ZAP settings seed failed:', e)
PYCODE
    echo '================================================================='
    echo 'User Created'
    echo 'User Name :' ${NAME}
    echo 'User Email': ${EMAIL}
    echo 'Role : Admin'
    echo 'Done !'
    # Ensure the sessions table exists before starting Gunicorn to prevent
    # 'relation "django_session" does not exist' on the first request.
    if [ -n "${DB_HOST:-}" ]; then
      echo "Waiting for django_session table to be present"
      until PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='django_session'" | grep -q 1; do
        sleep 1
      done
      echo "django_session table present"
    fi
    echo "Now running application"
    # Reduce noise from nmap fingerprint probes hitting Gunicorn
    exec gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800 --log-level error
fi
