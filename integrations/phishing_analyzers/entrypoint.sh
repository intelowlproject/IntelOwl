#!/bin/sh

gunicorn 'app:app' \
    --bind '0.0.0.0:4005' \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log