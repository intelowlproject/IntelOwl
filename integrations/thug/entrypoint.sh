#!/bin/bash
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log ${LOG_PATH}/thug.log ${LOG_PATH}/thug_errors.log
chown ${USER}:${USER} ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log ${LOG_PATH}/thug.log ${LOG_PATH}/thug_errors.log
# change user
su thug-user -s /bin/bash
echo "running gunicorn"
# start flask server
exec /opt/deploy/flask/venv/bin/gunicorn 'app:app' \
    --bind '0.0.0.0:4002' \
    --user thug-user \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log
