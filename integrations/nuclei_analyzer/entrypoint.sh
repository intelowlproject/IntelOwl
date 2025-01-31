#!/bin/sh

# Update Nuclei templates
nuclei -update-template-dir /opt/nuclei-api/nuclei-templates -update-templates
sleep 60
TEMPLATES_DIR="/opt/nuclei-api/nuclei-templates"

echo "Waiting for Nuclei templates to be available..."
while [ ! -d "$TEMPLATES_DIR" ] || [ -z "$(ls -A $TEMPLATES_DIR)" ]; do
    echo "Templates not found, retrying in 10 seconds..."
    sleep 10
done

echo "Templates downloaded successfully. Starting Flask app..."

# Start the Flask app
exec gunicorn -b 0.0.0.0:4008 --timeout 120 --access-logfile - "app:app"