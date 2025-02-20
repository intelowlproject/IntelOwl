FROM python:3.12.3

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/phishing_analyzers
ENV USER=phishing-user
ENV HOME=${PYTHONPATH}

# Add a new low-privileged user
RUN useradd -ms /bin/bash ${USER}

# Install Google Chrome and Chromium
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    libvulkan1 libu2f-udev fonts-liberation sudo \
    && pip3 install --no-cache-dir --upgrade pip \
    # Cleanup
    && apt-get remove --purge -y gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# Create application environment and files
WORKDIR ${PROJECT_PATH}/phishing_analyzers
COPY --chown=${USER}:${USER} app.py requirements.txt entrypoint.sh ./
COPY --chown=${USER}:${USER} analyzers/* ./analyzers/
RUN chmod u+x entrypoint.sh \
    && pip3 install -r requirements.txt --no-cache-dir

# unprivileged user must run some commands as root to avoid conflicts with other volumes.
# adding them to sudoers file to avoid running entrypoint as root usesr.
RUN echo "${USER} ALL=(root) NOPASSWD: /usr/bin/mkdir -p ${LOG_PATH}" > /etc/sudoers.d/create_log_directory \
  && echo "${USER} ALL=(root) NOPASSWD: /usr/bin/touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log" > /etc/sudoers.d/create_log_files \
  && echo "${USER} ALL=(root) NOPASSWD: /usr/bin/chown -R ${USER}\:${USER} ${PROJECT_PATH}/phishing_analyzers ${LOG_PATH}" > /etc/sudoers.d/chown_log_and_workdir_unprivileged

# use a unprivileged user to run flask
USER ${USER}

# Serve Flask application using gunicorn as low-privileged user
EXPOSE 4005
ENTRYPOINT ["./entrypoint.sh"]
