#!/bin/sh

TEMPLATES_DIR="/opt/nuclei-api/nuclei-templates"

echo "Updating Nuclei templates..."
nuclei -update-template-dir $TEMPLATES_DIR -update-templates

echo "Verifying Nuclei templates..."
while [ ! -d "$TEMPLATES_DIR" ] || [ -z "$(ls -A $TEMPLATES_DIR)" ]; do
    echo "Templates not found or empty, retrying update in 10 seconds..."
    nuclei -update-template-dir $TEMPLATES_DIR -update-templates
    sleep 10
done

echo "Templates downloaded successfully. Starting Flask API..."
exec gunicorn -b 0.0.0.0:4008 --timeout 120 --access-logfile - "app:app"
