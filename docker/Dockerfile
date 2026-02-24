# Stage 1: Frontend
# Remove this part if it is conflicting with the frontend you are currently testing
FROM node:lts-alpine3.21 AS frontend-build

WORKDIR /
# copy react source code
COPY frontend/ .
# copy version file as an env file
COPY docker/.env .env.local
# install and build
RUN npm install npm@latest --location=global \
    && npm install \
    && PUBLIC_URL=/static/reactapp/ npm run build

# Stage 2: Backend
FROM python:3.11.7 AS backend-build

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=intel_owl.settings
ENV PYTHONPATH=/opt/deploy/intel_owl
ENV LOG_PATH=/var/log/intel_owl
ARG REPO_DOWNLOADER_ENABLED=true
ARG WATCHMAN=false
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
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --upgrade pip

COPY requirements/project-requirements.txt $PYTHONPATH/project-requirements.txt
COPY requirements/certego-requirements.txt $PYTHONPATH/certego-requirements.txt
WORKDIR $PYTHONPATH

RUN pip3 install --no-cache-dir --use-pep517 --compile -r project-requirements.txt \
    && pip3 install --no-cache-dir pycti==${PYCTI_VERSION} \
    && pip3 install --no-cache-dir --compile -r certego-requirements.txt

COPY . $PYTHONPATH

RUN touch ${LOG_PATH}/django/api_app.log ${LOG_PATH}/django/api_app_errors.log \
    && touch ${LOG_PATH}/django/intel_owl.log ${LOG_PATH}/django/intel_owl_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && touch ${LOG_PATH}/django/django_auth_ldap.log ${LOG_PATH}/django/django_errors.log \
    && touch ${LOG_PATH}/django/certego_saas.log ${LOG_PATH}/django/certego_saas_errors.log \
    && touch ${LOG_PATH}/django/authentication.log ${LOG_PATH}/django/authentication_errors.log \
    && touch ${LOG_PATH}/asgi/daphne.log \
    && mkdir -p ${PYTHONPATH}/.cache \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ ${PYTHONPATH}/.cache \
    && ${PYTHONPATH}/docker/scripts/watchman_install.sh \
    # download github stuff
    && ${PYTHONPATH}/api_app/analyzers_manager/repo_downloader.sh

FROM backend-build

COPY --from=frontend-build /build /var/www/reactapp

# quarkengine calls
# HOME_DIR = f"{Path.home()}/.quark-engine/"
# Path(HOME_DIR).mkdir(parents=True, exist_ok=True)
# so we have to set the home env variable to allow to create its directory
ENV HOME="${PYTHONPATH}"
ENV XDG_CACHE_HOME="${PYTHONPATH}/.cache"


