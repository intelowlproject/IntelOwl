FROM python:3.8.4-alpine3.12

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/peframe

# update and install packages
RUN apk update && apk upgrade
RUN apk add --no-cache git libssl1.1 swig g++ make openssl-dev libffi-dev libmagic

# Build and install PEframe
RUN git clone https://github.com/guelfoweb/peframe.git ${PROJECT_PATH}/peframe
WORKDIR ${PROJECT_PATH}/peframe
RUN rm -rf .git && pip install -r requirements.txt --no-cache-dir \
    && python3 setup.py install \
    # not needed anymore
    && apk del git \
    && rm -rf ../peframe

# Add a new low-privileged user
RUN adduser -DH -s /sbin/login peframe-user

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/peframe-flask
COPY app.py requirements.txt entrypoint.sh ./

RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R peframe-user:peframe-user . \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4000
ENTRYPOINT ["./entrypoint.sh"]
