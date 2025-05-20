FROM projectdiscovery/nuclei:v3.4.4

ENV LOG_PATH=/var/log/intel_owl/nuclei_analyzer
ENV USER=nuclei-user
ENV PROJECT_PATH=/app

# Create non-root user
RUN adduser -D -h /home/${USER} ${USER}

# Install required packages using apk and clean cache in the same layer
RUN apk add --no-cache python3=3.11.12-r0 py3-pip \
    && rm -rf /var/cache/apk/* \
    && pip3 install --no-cache-dir --upgrade pip

# Create working directory and set ownership
WORKDIR /app

# Copy and install requirements first (better layer caching)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt \
    && rm -rf ~/.cache/pip/*

# Create log directory with proper permissions
RUN mkdir -p ${LOG_PATH} \
    && touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} ${LOG_PATH} \
    && chmod 755 ${LOG_PATH} \
    && chmod 666 ${LOG_PATH}/gunicorn_access.log \
    && chmod 666 ${LOG_PATH}/gunicorn_errors.log
# Copy application files
COPY app.py .
COPY entrypoint.sh /entrypoint.sh

# Set proper permissions
RUN chown -R ${USER}:${USER} /app \
    && chmod +x /entrypoint.sh

# Expose the API port
EXPOSE 4008

HEALTHCHECK --interval=45s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:4008/health || exit 1
  
ENTRYPOINT ["/entrypoint.sh"]