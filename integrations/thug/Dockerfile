# This base image is the one currently (02/2025) updated by the maintainer
# but it does not support ARM
FROM thughoneyclient/thug:v6.20
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

USER root
ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/thug
ENV USER=thug

# update and install gosu
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

# 2. Build Flask REST API
WORKDIR ${PROJECT_PATH}/flask
COPY app.py requirements.txt entrypoint.sh ./

RUN --mount=type=cache,target=/root/.cache/uv uv pip install --system -r requirements.txt \
    && mkdir -p ${PROJECT_PATH}/thug \
    && chown -R ${USER}:${USER} . ${PROJECT_PATH}/thug \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4002
ENTRYPOINT ["./entrypoint.sh"]
