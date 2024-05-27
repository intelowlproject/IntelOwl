#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done
sudo su www-data -c "mkdir -p /var/log/intel_owl/django /var/log/intel_owl/uwsgi /var/log/intel_owl/asgi /opt/deploy/intel_owl/files_required/blint /opt/deploy/intel_owl/files_required/yara"

# Apply database migrations
echo "Waiting for db to be ready..."
# makemigrations is needed only for the durin package.
# The customization of the parameters is not applied until the migration is done
python manage.py makemigrations durin
python manage.py makemigrations rest_email_auth
python manage.py createcachetable
# fake-initial does not fake the migration if the table does not exist
python manage.py migrate --fake-initial
if ! python manage.py migrate --check
 then
    echo "Issue with migration exiting"
    exit 1
fi
# Collect static files
python manage.py collectstatic --noinput
echo "------------------------------"
echo "DEBUG: " $DEBUG
echo "DJANGO_TEST_SERVER: " $DJANGO_TEST_SERVER
echo "------------------------------"
CHANGELOG_NOTIFICATION_COMMAND='python manage.py changelog_notification .github/CHANGELOG.md INTELOWL --number-of-releases 3'

if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    $CHANGELOG_NOTIFICATION_COMMAND --debug
    python manage.py runserver 0.0.0.0:8001
else
    $CHANGELOG_NOTIFICATION_COMMAND
    /usr/local/bin/uwsgi --ini /etc/uwsgi/sites/intel_owl.ini --stats 127.0.0.1:1717 --stats-http
fi
