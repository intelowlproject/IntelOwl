#!/bin/bash
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log ${LOG_PATH}/thug.log ${LOG_PATH}/thug_errors.log
chown -R ${USER}:${USER} ${LOG_PATH}
# change user
su thug -s /bin/bash
echo "running gunicorn"
# start flask server
/usr/local/bin/gunicorn 'app:app' \
    --bind '0.0.0.0:4002' \
    --user thug \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log
