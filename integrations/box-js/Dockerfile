FROM python:3.8.4-alpine3.12

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/box-js

# update and install packages
RUN apk update && apk add --no-cache git nodejs npm file gcc m4

# Add a new low-privileged user
RUN adduser -DH --shell /sbin/login boxjs-user

# Install Box-js
RUN apk add --no-cache -U --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing aufs-util \
    && npm install box-js --global --production \
    && mkdir -p /tmp/boxjs \
    && chown -R boxjs-user:boxjs-user /tmp/boxjs

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/boxjs-flask
COPY entrypoint.sh app.py requirements.txt ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R boxjs-user:boxjs-user . \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4003
ENTRYPOINT ["./entrypoint.sh"]