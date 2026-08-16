FROM python:3.11-slim-trixie

ENV LOG_PATH=/var/log/intel_owl/sogen_analyzer
ENV USER=sogen-user
ENV PROJECT_PATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git pkg-config gosu curl ca-certificates \
    libx11-dev libxext-dev libxrender-dev libxss-dev libxcursor-dev \
    libxi-dev libxfixes-dev libxrandr-dev libxtst-dev \
    libwayland-dev libgl1-mesa-dev libasound2-dev libudev-dev libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --home /home/${USER} ${USER}

RUN mkdir -p /opt/sogen_root && \
    curl -fsSL https://sogen.dev/root.zip -o /tmp/root.zip && \
    (cd /opt/sogen_root && python3 -m zipfile -e /tmp/root.zip .) && \
    rm /tmp/root.zip && \
    chown -R ${USER}:${USER} /opt/sogen_root

WORKDIR /app
COPY app.py requirements.txt entrypoint.sh ./
RUN python3 -m venv venv \
    && . venv/bin/activate \
    && pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir -r requirements.txt \
    && rm -rf ~/.cache/pip/*

RUN mkdir -p ${LOG_PATH} \
    && touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} ${LOG_PATH} \
    && chmod 755 ${LOG_PATH} \
    && chmod 666 ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} /app \
    && chmod +x entrypoint.sh

EXPOSE 4009
HEALTHCHECK --interval=45s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:4009/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
