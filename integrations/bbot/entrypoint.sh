#!/bin/sh

# Define log path
LOG_PATH="/var/log/intel_owl/bbot_analyzer"

# Ensure log directory and files exist
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/hypercorn_access.log ${LOG_PATH}/hypercorn_errors.log
chown -R bbot-user:bbot-user ${BBOT_HOME} ${LOG_PATH}

# Set log level
LOG_LEVEL="debug"

# Start Hypercorn to run the Quart API
exec hypercorn 'app:app' \
    --bind '0.0.0.0:5000' \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/hypercorn_access.log \
    --error-logfile ${LOG_PATH}/hypercorn_errors.log \
    --workers 1