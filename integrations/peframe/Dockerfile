FROM python:3.8.2-alpine3.11

MAINTAINER eshaan7bansal@gmail.com

# VOLUME /var/log/intel_owl
ENV PROJECT_PATH /opt/deploy/integrations/peframe
ENV LOG_PATH /var/log/intel_owl/integrations

# update and install packages
RUN apk update && apk upgrade
RUN apk add --no-cache git libssl1.1 swig g++ make openssl-dev libffi-dev libmagic 	

# Build and install PEframe
RUN git clone https://github.com/guelfoweb/peframe.git ${PROJECT_PATH}/peframe
WORKDIR ${PROJECT_PATH}/peframe
RUN rm -rf .git && pip install -r requirements.txt --no-cache-dir \
    && python3 setup.py install

# Add a new low-privileged user
RUN adduser --shell /sbin/login www-data -DH

# Create log files
WORKDIR ${LOG_PATH}
RUN touch peframe.log peframe_errors.log \
    && chown -R www-data ./

# Build Flask REST API
WORKDIR ${PROJECT_PATH}
COPY app.py requirements.txt ./
RUN pip install -r requirements.txt --no-cache-dir \
    && chown -R www-data ./

USER www-data

EXPOSE 4000
CMD echo "****Starting PEframe-REST-Server****"
ENTRYPOINT gunicorn 'app:app' \
            --bind '0.0.0.0:4000' \
            --workers ${WORKERS} \
            --log-level ${LOG_LEVEL} 
            # --log-file ${LOG_PATH}/peframe.log \
            # --error-logfile ${LOG_PATH}/peframe_errors.log
