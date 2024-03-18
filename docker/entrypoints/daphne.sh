#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done
mkdir -p /var/log/intel_owl/asgi
touch /var/log/intel_owl/asgi/daphne.log
chown -R www-data:www-data /var/log/intel_owl/asgi

# verbosity param levels: https://github.com/django/daphne/blob/df0680c9ad699817725e18a9264df17fff2927da/daphne/cli.py#L213
# not useful to improve logging
/usr/local/bin/daphne --proxy-headers --access-log /var/log/intel_owl/asgi/daphne.log -p 8011 -b 0.0.0.0 --no-server-name --application-close-timeout 60 --ping-interval 30 --ping-timeout 35 intel_owl.asgi:application
