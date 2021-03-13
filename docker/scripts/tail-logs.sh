docker exec intelowl_uwsgi ls -al /var/log/intel_owl/$1
docker exec -ti intelowl_uwsgi tail -f /var/log/intel_owl/$1