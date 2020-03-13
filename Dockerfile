FROM python:3.6

ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE intel_owl.settings
ENV PYTHONPATH /opt/deploy/intel_owl

RUN mkdir -p /var/log/intel_owl /var/log/intel_owl/django /var/log/intel_owl/uwsgi /opt/deploy/files_required /opt/deploy/yara /opt/deploy/configuration

RUN apt-get update
RUN apt-get install -y --no-install-recommends apt-utils libsasl2-dev libssl-dev vim libfuzzy-dev net-tools python-psycopg2 git osslsigncode exiftool
RUN pip3 install --upgrade pip

COPY requirements.txt $PYTHONPATH/requirements.txt
WORKDIR $PYTHONPATH

RUN pip3 install --compile -r requirements.txt

COPY . $PYTHONPATH

RUN touch /var/log/intel_owl/django/api_app.log /var/log/intel_owl/django/api_app_errors.log \
    touch /var/log/intel_owl/django/celery.log /var/log/intel_owl/django/celery_errors.log \
    && chown -R www-data:www-data /var/log/intel_owl /opt/deploy/ \
# this is cause stringstifer creates this directory during the build and cause celery to crash
    && rm -rf /root/.local

RUN api_app/script_analyzers/yara_repo_downloader.sh

# this is because botocore points to legacy endpoints
# more info: https://stackoverflow.com/questions/41062055/celery-4-0-0-amazon-sqs-credential-should-be-scoped-to-a-valid-region-not
RUN sed -i "s/{region}.queue/sqs.{region}/g" $(find / -name endpoints.json 2>/dev/null | head -n 1)