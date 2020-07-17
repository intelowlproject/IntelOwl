#!/bin/sh

touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R thug:thug ${LOG_PATH}
su thug -s /bin/bash
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4001' \
    --user thug \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log