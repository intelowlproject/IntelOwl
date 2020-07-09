FROM python:3.8.2-alpine3.11

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/peframe

# update and install packages
RUN apk update && apk upgrade
RUN apk add --no-cache git libssl1.1 swig g++ make openssl-dev libffi-dev libmagic 	

# Build and install PEframe
RUN git clone https://github.com/guelfoweb/peframe.git ${PROJECT_PATH}/peframe
WORKDIR ${PROJECT_PATH}/peframe
RUN rm -rf .git && pip install -r requirements.txt --no-cache-dir \
    && python3 setup.py install

# Add a new low-privileged user
RUN adduser --shell /sbin/login peframe-user -DH

# Create log files
RUN mkdir -p ${LOG_PATH}
WORKDIR ${LOG_PATH}
VOLUME ${LOG_PATH}
RUN touch peframe.log peframe_errors.log gunicorn_access.log gunicorn_errors.log \
    && chown -R peframe-user:peframe-user ./

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/flask
COPY app.py requirements.txt ./
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R peframe-user:peframe-user .

EXPOSE 4000

USER peframe-user
ENTRYPOINT gunicorn 'app:app' \
            --bind '0.0.0.0:4000' \
            --user peframe-user \
            --log-level ${LOG_LEVEL} \
            --access-logfile ${LOG_PATH}/gunicorn_access.log \
            --error-logfile ${LOG_PATH}/gunicorn_errors.log