FROM python:3.12.3
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

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
RUN --mount=type=cache,target=/root/.cache/uv chmod u+x entrypoint.sh \
    && uv pip install --system -r requirements.txt \
    && playwright install chromium --with-deps \
    && chmod -R o+rX /ms-playwright


# Serve Flask application using gunicorn as low-privileged user
EXPOSE 4005
ENTRYPOINT ["./entrypoint.sh"]
