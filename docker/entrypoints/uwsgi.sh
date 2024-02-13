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
python manage.py makemigrations rest_email_auth
# fake-initial does not fake the migration if the table does not exist
python manage.py migrate api_app --fake-initial
python manage.py migrate analyzers_manager --fake-initial
python manage.py migrate analyzers_manager --fake-initial
python manage.py migrate connectors_manager --fake-initial
python manage.py migrate visualizers_manager --fake-initial
python manage.py migrate ingestors_manager --fake-initial
python manage.py migrate pivots_manager --fake-initial
python manage.py migrate playbooks_manager --fake-initial
python manage.py migrate
if ! python manage.py migrate --check
 then
    echo "Issue with migration exiting"
    exit 1
fi
python manage.py createcachetable
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
