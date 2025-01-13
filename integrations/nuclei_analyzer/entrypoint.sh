#!/bin/bash

# Ensure proper permissions for logs
chown -R ${USER}:${USER} ${LOG_PATH}

# Run any initialization logic for Nuclei
echo "Starting Nuclei Analyzer Service..."

# Run the Flask application with Gunicorn
exec gunicorn --bind 0.0.0.0:4008 \
              --timeout 600 \
              --workers 4 \
              --log-level info \
              app:app
