#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

/usr/local/bin/celery -A intel_owl.celery beat --uid www-data --gid www-data --pidfile= --schedule=/tmp/celerybeat-schedule --scheduler django_celery_beat.schedulers:DatabaseScheduler