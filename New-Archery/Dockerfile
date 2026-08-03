#Ubuntu base OS
FROM ubuntu:22.04

# Labels and Credits
LABEL \
    name="CustomArcherySec" \
    author="Teamcloud <devteam@teamcloud.my>" \
    maintainer="Teamcloud <devteam@teamcloud.my>" \
    description="Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to perform scans and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scanning for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium. The developers can also utilize the tool for implementation of their DevOps CI/CD environment."


ENV DJANGO_SETTINGS_MODULE="archerysecurity.settings.base" \
    DJANGO_WSGI_MODULE="archerysecurity.wsgi" \
    DEBIAN_FRONTEND=noninteractive

RUN \
    apt update -y && apt install -y  --no-install-recommends \
    build-essential \
    default-jre \
    wget \
    curl \
    unzip \
    git \
    python3 \
    python3-dev \
    python3-pip \
    pkg-config \
    virtualenv \
    gunicorn \
    postgresql \
    python3-psycopg2 \
    postgresql-server-dev-all \
    libpq-dev \
    python-is-python3 \
    openssh-client \
    libmagic1 \
    python3.10-venv \
    iputils-ping \
    telnet \
    nano \
    net-tools \
    # WeasyPrint dependencies
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libcairo2-dev \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    libcap2-bin \
    nikto \
    nmap 

# Show Nikto/Nmap versions during build logs (visible in Docker Desktop build view)
RUN echo "=== Nikto installed; version info ===" && nikto -Version || true \
 && echo "=== Nmap installed; version info ===" && nmap --version || true

# Grant raw-socket capabilities to nmap so non-root user can use -sS and -O
RUN echo "=== Granting nmap raw-socket capabilities for non-root user ===" \
 && setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" || true

# Set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_VIRTUALENVS_CREATE=false

# Create archerysec user and group
RUN groupadd -g 9901 archerysec 
RUN adduser archerysec --shell /bin/false -u 9901 --ingroup archerysec --gecos "" --disabled-password

# Install Poetry
RUN python3 -m pip install --upgrade --no-cache-dir pip && \
    python3 -m pip install --no-cache-dir poetry==$POETRY_VERSION

# Create archerysec folder and set work directory.
RUN mkdir -p /home/archerysec/app
WORKDIR /home/archerysec/app

# Copy the dependency files (including lock file) to the container
COPY archerysec/pyproject.toml archerysec/poetry.lock ./

# Configure Poetry to not create virtual environments
RUN poetry config virtualenvs.create $POETRY_VIRTUALENVS_CREATE

# Install dependencies from lock file
RUN poetry install --only main --no-root --no-interaction --no-ansi

# Downgrade setuptools to a version that ships pkg_resources (removed in 70+)
# Required by coreapi and other legacy packages
RUN pip install --no-cache-dir "setuptools>=59.6.0,<70.0.0"

# Fix Python 3.10 compatibility issues in openvas-lib
RUN find /usr/local/lib/python*/dist-packages/openvas_lib/ -name "*.py" -type f -exec sed -i 's/from collections import Iterable/from collections.abc import Iterable/g' {} + 2>/dev/null || true
RUN find /usr/local/lib/python*/dist-packages/openvas_lib/ -name "*.py" -type f -exec sed -i 's/from collections import MutableMapping/from collections.abc import MutableMapping/g' {} + 2>/dev/null || true
RUN find /usr/local/lib/python*/dist-packages/openvas_lib/ -name "*.py" -type f -exec sed -i 's/from collections import Mapping/from collections.abc import Mapping/g' {} + 2>/dev/null || true
RUN find /usr/local/lib/python*/dist-packages/openvas_lib/ -name "*.py" -type f -exec sed -i 's/from collections import Set/from collections.abc import Set/g' {} + 2>/dev/null || true
RUN find /usr/local/lib/python*/dist-packages/openvas_lib/ -name "*.py" -type f -exec sed -i 's/from collections import Sequence/from collections.abc import Sequence/g' {} + 2>/dev/null || true

# Cleanup
RUN \
apt remove -y \
    libssl-dev \
    libffi-dev \
    libcairo2-dev \
    libxml2-dev \
    libxslt1-dev \
    python3-dev \
    wget && \
apt clean && \
apt autoclean && \
apt autoremove -y && \
rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Copy all file to archerysec folder.
COPY archerysec/ .
 
# Include init script
ADD archerysec/docker-files/init.sh /usr/local/bin/init.sh

RUN chmod +x /usr/local/bin/init.sh
RUN sed -i 's/\r$//' /usr/local/bin/init.sh

RUN mkdir -p nikto_result logs/nikto

# Cleanup
RUN \
    apt remove -y \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Exposing port.
EXPOSE 8000

RUN chown -R archerysec:archerysec /home/archerysec/app
USER archerysec


# UP & RUN application.
CMD ["/usr/local/bin/init.sh"]
