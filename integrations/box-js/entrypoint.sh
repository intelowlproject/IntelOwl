#!/bin/sh

touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R boxjs-user:boxjs-user ${LOG_PATH}
su boxjs-user -s /bin/sh
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4003' \
    --user boxjs-user \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log