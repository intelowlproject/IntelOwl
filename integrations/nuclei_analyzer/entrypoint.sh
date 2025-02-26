#!/bin/sh
mkdir -p "${LOG_PATH}"
touch "${LOG_PATH}/gunicorn_access.log" "${LOG_PATH}/gunicorn_errors.log"
chown -R "${USER}":"${USER}" "${LOG_PATH}"

TEMPLATES_DIR="/opt/nuclei-api/nuclei-templates"
echo "Updating Nuclei templates..."
nuclei -update-template-dir $TEMPLATES_DIR -update-templates
sleep 30
echo "Verifying Nuclei templates..."
if [ ! -d "$TEMPLATES_DIR" ] || [ -z "$(ls -A $TEMPLATES_DIR)" ]; then
    echo "Error: Nuclei templates not found or directory is empty. Please check you internet connection. Exiting..."
    exit 1
else
    echo "Nuclei templates successfully updated."
fi
echo "Templates downloaded successfully. Starting Flask API..."
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4008' \
    --access-logfile "${LOG_PATH}"/gunicorn_access.log \
    --error-logfile "${LOG_PATH}"/gunicorn_errors.log