#!/bin/sh

# Define log path
LOG_PATH="/var/log/intel_owl/bbot_analyzer"

# Ensure log directory and files exist
/usr/bin/sudo /usr/bin/mkdir -p ${LOG_PATH}
/usr/bin/sudo /usr/bin/touch ${LOG_PATH}/gunicorn_access.log \
      ${LOG_PATH}/gunicorn_errors.log
/usr/bin/sudo /usr/bin/chown -R bbot-user:bbot-user \
      ${BBOT_HOME} ${LOG_PATH}

if [ -z "$LOG_LEVEL" ]; then
    LOG_LEVEL="debug"
fi

# Start Gunicorn to run the Flask API
/usr/local/bin/gunicorn 'app:app' \
    --bind '0.0.0.0:5000' \
    --log-level ${LOG_LEVEL} \
    --user bbot-user \
    --group bbot-user \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log
