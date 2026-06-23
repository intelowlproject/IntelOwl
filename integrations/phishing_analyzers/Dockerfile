FROM python:3.14.6

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/phishing_analyzers
ENV USER=phishing-user
ENV HOME=${PYTHONPATH}
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Add a new low-privileged user
RUN useradd -ms /bin/bash ${USER}

# Install Google Chrome and Chromium
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install -y --no-install-recommends \
    libvulkan1 libu2f-udev fonts-liberation gosu \
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
    && pip3 install -r requirements.txt --no-cache-dir \
    && playwright install chromium --with-deps \
    && chmod -R o+rX /ms-playwright


# Serve Flask application using gunicorn as low-privileged user
EXPOSE 4005
ENTRYPOINT ["./entrypoint.sh"]
