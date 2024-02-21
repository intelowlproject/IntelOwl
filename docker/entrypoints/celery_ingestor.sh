#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done
ARGUMENTS="-A intel_owl.celery worker -n worker_ingestor --uid www-data --gid www-data --time-limit=40000 --pidfile= -Ofair -Q ingestor,broadcast,config -E --autoscale=1,15 --without-gossip"
if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    echo "Running celery with autoreload"
    python3 manage.py celery_reload -c "$ARGUMENTS"
else
  /usr/local/bin/celery $ARGUMENTS
fi