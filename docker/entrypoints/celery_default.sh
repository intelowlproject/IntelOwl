#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

echo "environment: $STAGE"
if [ "$STAGE" = "ci" ]
then
   worker_number=1
else
   # default is prod
   worker_number=8
fi

ARGUMENTS="-A intel_owl.celery worker -n worker_default --uid www-data --gid www-data --time-limit=10000 --pidfile= -c $worker_number -Ofair -Q default,broadcast,config -E --without-gossip"
if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    echo "Running celery with autoreload"
    python3 manage.py celery_reload -c "$ARGUMENTS"
else
  /usr/local/bin/celery $ARGUMENTS
fi