#!/bin/bash  

docker exec intelowl_gunicorn ls -al /var/log/intel_owl/"$1" 
docker exec -ti intelowl_gunicorn tail -f /var/log/intel_owl/"$1"  
