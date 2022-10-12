#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

# Apply database migrations
echo "Waiting for db to be ready..."
sleep 3
# makemigrations is needed only for the durin package.
# The customization of the parameters is not applied until the migration is done
python manage.py makemigrations durin
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput
echo "------------------------------"
echo "DEBUG: " $DEBUG
echo "DJANGO_TEST_SERVER: " $DJANGO_TEST_SERVER
echo "------------------------------"
CHANGELOG_NOTIFICATION_COMMAND='python manage.py changelog_notification .github/CHANGELOG.md INTELOWL --number-of-releases 3'
python manage.py migrate_secrets

if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    $CHANGELOG_NOTIFICATION_COMMAND --debug
    python manage.py runserver 0.0.0.0:8001
else
    $CHANGELOG_NOTIFICATION_COMMAND
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/intel_owl.ini
fi
