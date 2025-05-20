#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done
if [ "$AWS_SQS" = "True" ]
then
  queues="local.fifo,config.fifo"
else
  queues="local,broadcast,config"
fi

ARGUMENTS="-A intel_owl.celery worker -n worker_local --uid www-data --time-limit=10000 --gid www-data --pidfile= -Ofair -Q ${queues} -E --without-gossip"
if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    echo "Running celery with autoreload"
    python3 manage.py celery_reload -c "$ARGUMENTS"
else
  # shellcheck disable=SC2086
  /usr/local/bin/celery $ARGUMENTS
fi