#!/bin/sh
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R tor-user:tor-user ${LOG_PATH}
su tor-user -s /bin/bash
exec tor &
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4001' \
    --user ${USER} \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log