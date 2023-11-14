#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

# Apply database migrations
echo "Waiting for db and UWSGI to be ready..."
sleep 10

/usr/local/bin/celery -A intel_owl.celery worker -n worker_default --uid www-data --gid www-data --time-limit=10000 --pidfile= -Ofair -Q default,broadcast,config -E --without-gossip