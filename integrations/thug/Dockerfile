FROM thughoneyclient/thug:v6.11

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/thug
ENV USER=thug-user

# Add a new low-privileged user
RUN useradd -r -s /sbin/nologin ${USER}

# update and install packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update -qq \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

# Cleanup
RUN apt-get remove --purge -y git gcc \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/* > /dev/null 2>&1

# 2. Build Flask REST API
WORKDIR ${PROJECT_PATH}/thug-flask
COPY app.py requirements.txt entrypoint.sh ./

RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . \
    && chmod +x entrypoint.sh

# 3. Copy Bundled tools
COPY bundled bundled
RUN chmod 755 -R bundled

# Serve Flask application using gunicorn
EXPOSE 4001
ENTRYPOINT ["./entrypoint.sh"]
