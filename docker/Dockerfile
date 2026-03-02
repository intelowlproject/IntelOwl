## ------------------------------- Frontend Build Stage ------------------------------ ##
# Remove this part if it is conflicting with the frontend you are currently testing
FROM node:lts-alpine3.21 AS frontend-build

WORKDIR /app

# install dependencies first for layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm install

# copy react source code and version env file
COPY frontend/ .
COPY docker/.env .env.local
RUN PUBLIC_URL=/static/reactapp/ npm run build

## ------------------------------- Production Stage ------------------------------ ##

FROM python:3.11.7 AS production

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=intel_owl.settings
ENV PYTHONPATH=/opt/deploy/intel_owl
ENV LOG_PATH=/var/log/intel_owl
ARG REPO_DOWNLOADER_ENABLED=true
ENV watch_logs_cmd="watch -n1 tail -n10 /var/log/intel_owl/django/api_app.log"
# This is required to allow compatibility with different OpenCTI instances
ARG PYCTI_VERSION=6.8.8
# this is required for if/else statements
SHELL ["/bin/bash", "-c"]

# Install runtime dependencies
# python3-psycopg2 is required to use PostgresSQL with Django
# apache2-utils is required to execute htpasswd
# tshark is required for Hfinger file analyzer
# libemail-outlook-message-perl and libemail-address-perl are required for msgconvert
# curl for healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils libsasl2-dev libssl-dev \
    vim libldap2-dev libfuzzy-dev net-tools python3-psycopg2 git apache2-utils tshark \
    libemail-outlook-message-perl libemail-address-perl curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR $PYTHONPATH

# Install python packages
COPY requirements/project-requirements.txt $PYTHONPATH/requirements/project-requirements.txt
COPY requirements/certego-requirements.txt $PYTHONPATH/requirements/certego-requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q \
    -r requirements/project-requirements.txt \
    && pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q \
    pycti==${PYCTI_VERSION} \
    && pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q \
    -r requirements/certego-requirements.txt

# Copy files
COPY . $PYTHONPATH
COPY --from=frontend-build /app/build /var/www/reactapp

# separation is required to avoid to re-execute os installation in case of change of python requirements
RUN mkdir -p ${LOG_PATH}/django ${LOG_PATH}/uwsgi ${LOG_PATH}/asgi \
    /opt/deploy/files_required /opt/deploy/configuration /opt/deploy/files_required/blint /opt/deploy/files_required/yara \
    && touch ${LOG_PATH}/django/api_app.log ${LOG_PATH}/django/api_app_errors.log \
    && touch ${LOG_PATH}/django/intel_owl.log ${LOG_PATH}/django/intel_owl_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_auth_ldap.log ${LOG_PATH}/django/django_errors.log \
    && touch ${LOG_PATH}/django/certego_saas.log ${LOG_PATH}/django/certego_saas_errors.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && touch ${LOG_PATH}/asgi/daphne.log \
    && mkdir -p -m 755 ${PYTHONPATH}/.cache \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/.cache \
    # download github stuff
    && ${PYTHONPATH}/api_app/analyzers_manager/repo_downloader.sh \
    && rm -rf frontend/

# quarkengine calls
# HOME_DIR = f"{Path.home()}/.quark-engine/"
# Path(HOME_DIR).mkdir(parents=True, exist_ok=True)
# so we have to set the home env variable to allow to create its directory
ENV HOME="${PYTHONPATH}"
ENV XDG_CACHE_HOME="${PYTHONPATH}/.cache"

## ------------------------------- Development Stage ------------------------------ ##

FROM production AS development

# Install dev/test requirements
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check -q \
    -r requirements/test-requirements.txt

## ------------------------------- CI Stage ------------------------------ ##
# CI image is based on the development image and includes test requirements
FROM development AS ci

## ------------------------------- Default Stage ------------------------------ ##

# Ensure the default build target is production
FROM production
