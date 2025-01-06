FROM python:3.9-slim

# Set environment variables
ENV PROJECT_PATH=/opt/nuclei-api
ENV LOG_PATH=/var/log/nuclei_analyzer
ENV USER=nuclei-user

# Install required packages and download nuclei
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    unzip
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    && apt-get autoremove -y 
RUN unzip nuclei_3.3.7_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei_3.3.7_linux_amd64.zip

# Create non-root user
RUN useradd -ms /bin/bash ${USER}

# Create necessary directories
RUN mkdir -p ${PROJECT_PATH} ${LOG_PATH} && \
    chown -R ${USER}:${USER} ${PROJECT_PATH} ${LOG_PATH}

# Set working directory
WORKDIR ${PROJECT_PATH}

# Copy application files
COPY requirements.txt .
COPY app.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set proper permissions
RUN chown -R ${USER}:${USER} ${PROJECT_PATH}

# Switch to non-root user
USER ${USER}

# Expose port
EXPOSE 5000

# Run using gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000","--timeout", "600", "--workers", "4", "app:app"]
