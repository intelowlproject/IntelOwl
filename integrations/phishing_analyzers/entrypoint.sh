#!/bin/sh
sudo /usr/bin/mkdir -p ${LOG_PATH}
sudo /usr/bin/touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
sudo /usr/bin/chown -R ${USER}:${USER} . ${LOG_PATH}

/usr/local/bin/gunicorn 'app:app' \
    --bind '0.0.0.0:4005' \
    --log-level ${LOG_LEVEL} \
    --user ${USER} \
    --group ${USER} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log