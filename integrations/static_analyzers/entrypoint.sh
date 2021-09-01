#!/bin/bash
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R static_analyzers-user:static_analyzers-user ${LOG_PATH}
# clamav processes
freshclam # download db for first time
freshclam -d & # run updater in bg
clamd --debug & # run daemon in bg
# change user
su static_analyzers-user -s /bin/bash
# start flask server
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4002' \
    --user static_analyzers-user \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log
