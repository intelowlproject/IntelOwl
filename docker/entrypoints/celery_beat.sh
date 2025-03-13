#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done
ARGUMENTS="-A intel_owl.celery beat --uid www-data --gid www-data --pidfile= --schedule=/tmp/celerybeat-schedule --scheduler django_celery_beat.schedulers:DatabaseScheduler"
if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    echo "Running celery with autoreload"
    python3 manage.py celery_reload -c "$ARGUMENTS"
else
  # shellcheck disable=SC2086
  /usr/local/bin/celery $ARGUMENTS
fi