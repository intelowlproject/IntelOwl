#!/bin/sh

touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R apk-user:apk-user ${LOG_PATH}
su apk-user -s /bin/bash
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4004' \
    --user ${USER} \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log