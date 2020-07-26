FROM python:3.8.4-slim

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/capa

# update and install packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Add a new low-privileged user
RUN useradd -ms /bin/bash capa-user

# Install capa standalone binary
WORKDIR ${PROJECT_PATH}
RUN wget -q https://github.com/fireeye/capa/releases/download/v1.0.0/capa-v1.0.0-linux.zip \
    && unzip capa-v1.0.0-linux.zip && rm -f capa-v1.0.0-linux.zip \
    && ln -s ${PROJECT_PATH}/capa-v1.0.0-linux /usr/local/bin/capa \
    && chown -R capa-user:capa-user .

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/capa-flask
COPY app.py requirements.txt entrypoint.sh ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R capa-user:capa-user . \
    && chmod +x entrypoint.sh

# not needed anymore
RUN apt-get remove -y wget unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Serve Flask application using gunicorn
EXPOSE 4002
ENTRYPOINT ["./entrypoint.sh"]