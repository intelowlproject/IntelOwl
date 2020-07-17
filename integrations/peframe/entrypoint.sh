#!/bin/sh

touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R peframe-user:peframe-user ${LOG_PATH}
su peframe-user -s /bin/sh
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4000' \
    --user peframe-user \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log