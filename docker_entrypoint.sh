#!/bin/bash

python manage.py makemigrations api_app
python manage.py migrate                  # Apply database migrations
python manage.py collectstatic --noinput  # Collect static files

/usr/local/bin/uwsgi --ini /etc/uwsgi/sites/intel_owl.ini