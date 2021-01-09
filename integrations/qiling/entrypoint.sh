#!/bin/sh
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R ${USER}:${USER} ${LOG_PATH}
su ${USER} -s /bin/sh
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4005' \
    --user ${USER} \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log