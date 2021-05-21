#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

# Apply database migrations
echo "Waiting for db to be ready..."
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput  

echo "------------------------------"
echo "DEBUG: " $DEBUG
echo "------------------------------"

if [ $DEBUG == "True" ];
then
    python manage.py runserver 0.0.0.0:8001
else
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/intel_owl.ini
fi
