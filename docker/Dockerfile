# Stage 1: Frontend
FROM node:lts-alpine3.21 AS frontend-build

WORKDIR /

COPY frontend/package.json frontend/package-lock.json ./
RUN npm install npm@11.11.0 --location=global && npm install

# copy react source code
COPY frontend/ .
# copy pyproject.toml to extract version
COPY pyproject.toml .
# extract version using uv
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /bin/uv
RUN echo "REACT_APP_INTELOWL_VERSION=v$(uv version --short)" > .env.local
# install and build
RUN PUBLIC_URL=/static/reactapp/ npm run build

# Stage 2: Backend
FROM python:3.11.7 AS backend-build

# Add uv
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=intel_owl.settings
ENV PYTHONPATH=/opt/deploy/intel_owl
ENV LOG_PATH=/var/log/intel_owl
ARG REPO_DOWNLOADER_ENABLED=true
ARG TARGETARCH
ENV watch_logs_cmd="watch -n1 tail -n10 /var/log/intel_owl/django/api_app.log"
# Use the system python for uv sync
ENV UV_PROJECT_ENVIRONMENT=/usr/local
# this is required for if/else statements
SHELL ["/bin/bash", "-c"]

# set build variables
RUN mkdir -p ${LOG_PATH}/django/

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential gcc libpq-dev libpcre3-dev curl \
    vim libldap2-dev libfuzzy-dev libsasl2-dev net-tools python3-psycopg2 git apache2-utils tshark  \
    libemail-outlook-message-perl libemail-address-perl \
    && apt-get clean && apt-get autoclean && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock $PYTHONPATH/
WORKDIR $PYTHONPATH

RUN uv sync --frozen --no-dev

COPY api_app/analyzers_manager/repo_downloader.sh ${PYTHONPATH}/api_app/analyzers_manager/repo_downloader.sh

COPY . $PYTHONPATH

RUN touch ${LOG_PATH}/django/api_app.log ${LOG_PATH}/django/api_app_errors.log \
    && touch ${LOG_PATH}/django/intel_owl.log ${LOG_PATH}/django/intel_owl_errors.log \
    && chmod -R 777 ${LOG_PATH}

RUN if [ "$REPO_DOWNLOADER_ENABLED" = "true" ] ; then bash api_app/analyzers_manager/repo_downloader.sh ; fi

# copy build from first stage
COPY --from=frontend-build /build static/reactapp/

EXPOSE 80
