#!/bin/sh
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R ${USER}:${USER} . ${LOG_PATH}
gunicorn 'app:app' \
    --bind '0.0.0.0:4005' \
    --log-level ${LOG_LEVEL} \
    --user ${USER} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log