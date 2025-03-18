#!/bin/sh

# Define log path
LOG_PATH="/var/log/intel_owl/bbot_analyzer"

# Ensure log directory and files exist
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/uvicorn_access.log ${LOG_PATH}/uvicorn_errors.log
chown -R bbot-user:bbot-user ${BBOT_HOME} ${LOG_PATH}

# Set log level
LOG_LEVEL="debug"

# Start Uvicorn server with access logging, and redirect errors manually
exec uvicorn app:app \
    --host 0.0.0.0 \
    --port 5000 \
    --log-level ${LOG_LEVEL}
    # --access-log > ${LOG_PATH}/uvicorn_access.log 2> ${LOG_PATH}/uvicorn_errors.log
