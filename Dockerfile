FROM python:3.6

ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE intel_owl.settings
ENV PYTHONPATH /opt/deploy/intel_owl
ENV LOG_PATH /var/log/intel_owl
ENV ELASTICSEARCH_DSL_VERSION 7.1.4

RUN mkdir -p ${LOG_PATH} \
    ${LOG_PATH}/django ${LOG_PATH}/uwsgi \
    ${LOG_PATH}/peframe ${LOG_PATH}/thug ${LOG_PATH}/capa ${LOG_PATH}/box-js \
    ${LOG_PATH}/apk_analyzers \
    /opt/deploy/files_required /opt/deploy/yara /opt/deploy/configuration

RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils libsasl2-dev libssl-dev \
        vim libfuzzy-dev net-tools python-psycopg2 git osslsigncode exiftool \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --upgrade pip

COPY requirements.txt $PYTHONPATH/requirements.txt
WORKDIR $PYTHONPATH

RUN pip3 install --no-cache-dir --compile -r requirements.txt
# install elasticsearch-dsl's appropriate version as specified by user
RUN pip3 install --no-cache-dir django-elasticsearch-dsl==${ELASTICSEARCH_DSL_VERSION}

COPY . $PYTHONPATH

RUN touch ${LOG_PATH}/django/api_app.log ${LOG_PATH}/django/api_app_errors.log \
    && touch ${LOG_PATH}/django/celery.log ${LOG_PATH}/django/celery_errors.log \
    && chown -R www-data:www-data ${LOG_PATH} /opt/deploy/ \
# this is cause stringstifer creates this directory during the build and cause celery to crash
    && rm -rf /root/.local

RUN api_app/script_analyzers/yara_repo_downloader.sh

# this is because botocore points to legacy endpoints
# more info: https://stackoverflow.com/questions/41062055/celery-4-0-0-amazon-sqs-credential-should-be-scoped-to-a-valid-region-not
RUN sed -i "s/{region}.queue/sqs.{region}/g" $(find / -name endpoints.json 2>/dev/null | head -n 1)