FROM projectdiscovery/nuclei:v3.7.0
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV LOG_PATH=/var/log/intel_owl/nuclei_analyzer
ENV USER=nuclei-user
ENV PROJECT_PATH=/app

# Create non-root user
RUN adduser -D -h /home/${USER} ${USER}

# Install required packages using apk and clean cache in the same layer
RUN apk add --no-cache python3 py3-pip gosu

# Create working directory and set ownership
WORKDIR /app

# Copy and install requirements first (better layer caching)
COPY app.py requirements.txt entrypoint.sh ./
RUN --mount=type=cache,target=/root/.cache/uv python3 -m venv venv \
    && . venv/bin/activate \
    && uv pip install -r requirements.txt \
    && rm -rf ~/.cache/pip/*

# Create log directory with proper permissions
RUN mkdir -p ${LOG_PATH} \
    && touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} ${LOG_PATH} \
    && chmod 755 ${LOG_PATH} \
    && chmod 666 ${LOG_PATH}/gunicorn_access.log \
    && chmod 666 ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} /app \
    && chmod +x entrypoint.sh

# Expose the API port
EXPOSE 4008

HEALTHCHECK --interval=45s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:4008/health || exit 1
  
ENTRYPOINT ["/app/entrypoint.sh"]