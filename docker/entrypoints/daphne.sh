#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

/usr/local/bin/daphne --proxy-headers --access-log /var/log/intel_owl/asgi/daphne.log -p 8011 -b 0.0.0.0 --no-server-name --application-close-timeout 60 --ping-interval 30 --ping-timeout 35 intel_owl.asgi:application    
