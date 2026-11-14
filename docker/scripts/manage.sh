#!/bin/bash
docker exec -ti intelowl_gunicorn python3 manage.py "$@"
