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
    unzip && \
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip nuclei_3.3.7_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei_3.3.7_linux_amd64.zip && \
    nuclei -update-template-dir /opt/nuclei-api/nuclei-templates -update-templates


# Create non-root user
RUN useradd -ms /bin/bash ${USER}

# Create necessary directories
RUN mkdir -p ${PROJECT_PATH} ${LOG_PATH}

# Set working directory
WORKDIR ${PROJECT_PATH}

# Copy application files
COPY requirements.txt .
COPY app.py .
COPY entrypoint.sh .

# Set proper permissions
RUN chmod +x entrypoint.sh && \
    chown -R ${USER}:${USER} ${PROJECT_PATH} && \
    chown -R ${USER}:${USER} ${LOG_PATH} && \
    chmod 755 ${PROJECT_PATH} && \
    chmod 755 ${LOG_PATH}

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Switch to non-root user
USER ${USER}

# Expose port
EXPOSE 4008

# Use full path to entrypoint script (this is another key fix)
ENTRYPOINT ["./entrypoint.sh"]