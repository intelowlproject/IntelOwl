#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

# Ensure capa cache directory exists and is writable by www-data
mkdir -p /opt/deploy/intel_owl/.cache
chmod 755 /opt/deploy/intel_owl/.cache
chown www-data:www-data /opt/deploy/intel_owl/.cache

if [ "$AWS_SQS" = "True" ]
then
  queues="ingestor.fifo,config.fifo"
else
  queues="ingestor,broadcast,config"
fi

ARGUMENTS="-A intel_owl.celery worker -n worker_ingestor --uid www-data --gid www-data --time-limit=40000 --pidfile= -Ofair -Q ${queues} -E --autoscale=1,15 --without-gossip"
if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    echo "Running celery with autoreload"
    python3 manage.py celery_reload -c "$ARGUMENTS"
else
  # shellcheck disable=SC2086
  /usr/local/bin/celery $ARGUMENTS
fi