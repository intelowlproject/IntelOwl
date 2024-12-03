FROM python:3.10-slim

WORKDIR /opt/app

# Install required system packages
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ .

# Create directories
RUN mkdir -p /opt/deploy/yara_rules

# Setup cron
RUN apt-get update && apt-get install -y cron
COPY crontab /etc/cron.d/yara-forge-cron
RUN chmod 0644 /etc/cron.d/yara-forge-cron && \
    crontab /etc/cron.d/yara-forge-cron

# Script to run cron and the app
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]