FROM python:3.11.11-slim-bookworm

ENV USER=intelowl
ENV GROUP=intelowl
ENV PROJECT_PATH=/home/${USER}

RUN groupadd -r ${GROUP} && useradd -r -g ${GROUP} ${USER}

# avoid writing to __pycache__
ENV PYTHONDONTWRITEBYTECODE=1
# force stdout and stderr to be unbuffered
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl sudo git \
    && apt-get clean && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /usr/share/doc/* /usr/share/man/*

# Add uv
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /uvx /bin/

# Set up project directory
WORKDIR ${PROJECT_PATH}/phishing_analyzers

# Copy application files and requirements
COPY --chown=${USER}:${USER} app.py requirements.txt entrypoint.sh ./
COPY --chown=${USER}:${USER} analyzers/* ./analyzers/
RUN chmod u+x entrypoint.sh \
    && uv pip install --system --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps \
    && chmod -R o+rX /ms-playwright

# unprivileged user must run some commands as root to avoid conflicts with other volumes.
# adding them to sudoers file to avoid running entrypoint as root usesr.
RUN echo "${USER} ALL=(ALL) NOPASSWD: /usr/bin/chown -R ${USER}\:${GROUP} ${PROJECT_PATH}/phishing_analyzers/results" >> /etc/sudoers

# Set ownership and switch to unprivileged user
RUN chown -R ${USER}:${GROUP} ${PROJECT_PATH}
USER ${USER}

ENTRYPOINT ["./entrypoint.sh"]
