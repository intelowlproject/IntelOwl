# Stage 1: Frontend
# Remove this part if it is conflicting with the frontend you are currently testing
FROM node:lts-alpine3.21 AS frontend-build

WORKDIR /

COPY frontend/package.json frontend/package-lock.json ./
RUN npm install npm@11.11.0 --location=global && npm install

# copy react source code
COPY frontend/ .
# copy version file as an env file
COPY docker/.env .env.local
RUN PUBLIC_URL=/static/reactapp/ npm run build

# Stage 2: Backend
FROM python:3.11.7 AS backend-build

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=intel_owl.settings
ENV PYTHONPATH=/opt/deploy/intel_owl
ENV LOG_PATH=/var/log/intel_owl
ARG REPO_DOWNLOADER_ENABLED=true
ARG TARGETARCH
ENV watch_logs_cmd="watch -n1 tail -n10 /var/log/intel_owl/django/api_app.log"
# This is required to allow compatibility with different OpenCTI instances
ARG PYCTI_VERSION=6.8.8
# this is required for if/else statements
SHELL ["/bin/bash", "-c"]

RUN mkdir -p ${LOG_PATH} \
    ${LOG_PATH}/django \
    ${LOG_PATH}/uwsgi \
    ${LOG_PATH}/asgi \
    /opt/deploy/files_required /opt/deploy/configuration /opt/deploy/files_required/blint /opt/deploy/files_required/yara

# install required packages. some notes about:o
# python3-psycopg2 is required to use PostgresSQL with Django
# apache2-utils is required to execute htpasswd
# tshark is required for Hfinger file analyzer
# libemail-outlook-message-perl and libemail-address-perl are required for msgconvert
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils libsasl2-dev libssl-dev netcat-traditional \
    vim libldap2-dev libfuzzy-dev net-tools python3-psycopg2 git apache2-utils tshark  \
    libemail-outlook-message-perl libemail-address-perl \
    && apt-get clean && apt-get autoclean && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# use uv to manage dependencies
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR $PYTHONPATH
ENV PATH="/opt/venv/bin:$PATH"
COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group certego \
    && uv pip install pycti==${PYCTI_VERSION}

COPY api_app/analyzers_manager/repo_downloader.sh ${PYTHONPATH}/api_app/analyzers_manager/repo_downloader.sh

RUN touch ${LOG_PATH}/django/api_app.log ${LOG_PATH}/django/api_app_errors.log \
    && touch ${LOG_PATH}/django/intel_owl.log ${LOG_PATH}/django/intel_owl_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_auth_ldap.log ${LOG_PATH}/django/django_errors.log \
    && touch ${LOG_PATH}/django/certego_saas.log ${LOG_PATH}/django/certego_saas_errors.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && touch ${LOG_PATH}/asgi/daphne.log \
    && mkdir -p -m 755 ${PYTHONPATH}/.cache \
    # download github stuff
    && ${PYTHONPATH}/api_app/analyzers_manager/repo_downloader.sh

COPY . $PYTHONPATH

RUN chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/.cache

FROM backend-build

COPY --from=frontend-build /build /var/www/reactapp

# quarkengine calls
# HOME_DIR = f"{Path.home()}/.quark-engine/"
# Path(HOME_DIR).mkdir(parents=True, exist_ok=True)
# so we have to set the home env variable to allow to create its directory
ENV HOME="${PYTHONPATH}"
ENV XDG_CACHE_HOME="${PYTHONPATH}/.cache"


