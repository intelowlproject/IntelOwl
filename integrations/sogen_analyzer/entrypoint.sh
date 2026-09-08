#!/bin/sh
mkdir -p "${LOG_PATH}"
touch "${LOG_PATH}/gunicorn_access.log" "${LOG_PATH}/gunicorn_errors.log"
chown -R "${USER}":"${USER}" "${LOG_PATH}"

echo "Starting Sogen analyzer Flask API..."
exec gosu "${USER}" /app/venv/bin/gunicorn 'app:app' \
    --bind '0.0.0.0:4009' \
    --timeout 300 \
    --access-logfile "${LOG_PATH}"/gunicorn_access.log \
    --error-logfile "${LOG_PATH}"/gunicorn_errors.log
