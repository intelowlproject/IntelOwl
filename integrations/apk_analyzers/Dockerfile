FROM python:3.8.4-slim

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/apk_analyzers
ENV USER apk-user

# Add a new low-privileged user
RUN useradd -r -s /sbin/nologin ${USER}

# update and install packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install --no-install-recommends -y git build-essential gcc pandoc curl \
    && rm -rf /var/lib/apt/lists/*

# Place to bind a mount point to for scratch pad work
WORKDIR ${PROJECT_PATH}
RUN mkdir input/ \
    && chown -R ${USER}:${USER} input/

# 1. Install APKiD and it's dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip wheel --quiet --no-cache-dir --wheel-dir=/tmp/yara-python --build-option="build" --build-option="--enable-dex" git+https://github.com/VirusTotal/yara-python.git@v3.11.0 \
    && pip install --quiet --no-cache-dir --no-index --find-links=/tmp/yara-python yara-python \
    && pip install --no-cache-dir apkid \
    && rm -rf /tmp/yara-python

# Cleanup
RUN apt-get remove --purge -y git gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# 2. Build Flask REST API
WORKDIR ${PROJECT_PATH}/apkid-flask
COPY app.py requirements.txt entrypoint.sh ./

RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4004
ENTRYPOINT ["./entrypoint.sh"]
