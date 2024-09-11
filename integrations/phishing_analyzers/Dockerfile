FROM python:3.12.3

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/phishing_analyzers
ENV USER=phishing-user

# Add a new low-privileged user
RUN useradd -ms /bin/bash ${USER}

RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && pip3 install --no-cache-dir --upgrade pip

# Cleanup
RUN apt-get remove --purge -y gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# 2. Build Flask REST API
WORKDIR ${PROJECT_PATH}/phishing-analyzer
COPY app.py requirements.txt entrypoint.sh ./

RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4005
ENTRYPOINT ["./entrypoint.sh"]
