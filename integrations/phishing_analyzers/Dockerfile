FROM python:3.12.3

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/phishing_analyzers
ENV USER=phishing-user
ENV HOME ${PYTHONPATH}

# Add a new low-privileged user
RUN useradd -ms /bin/bash ${USER}

# Install Google Chrome and Chromium
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    libvulkan1 libu2f-udev fonts-liberation chromium \
    && wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && dpkg -i google-chrome-stable_current_amd64.deb \
    && pip3 install --no-cache-dir --upgrade pip

# Cleanup
RUN apt-get remove --purge -y gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# Create application environment and files
WORKDIR ${PROJECT_PATH}/phishing_analyzers
COPY app.py requirements.txt entrypoint.sh analyze_phishing_site.py ./
RUN chmod +x entrypoint.sh \
    && pip3 install -r requirements.txt --no-cache-dir \
    && mkdir -p ${LOG_PATH} \
    && touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log \
    && chown -R ${USER}:${USER} .


# Serve Flask application using gunicorn as low-privileged user
USER ${USER}
EXPOSE 4005
ENTRYPOINT ["./entrypoint.sh"]
