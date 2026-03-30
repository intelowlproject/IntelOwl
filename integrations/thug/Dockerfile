# This base image is the one currently (02/2025) updated by the maintainer
# but it does not support ARM
FROM thughoneyclient/thug:v6.18

USER root
ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/thug

# Add uv
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /uvx /bin/

# 2. Build Flask REST API
WORKDIR ${PROJECT_PATH}/flask
COPY app.py requirements.txt entrypoint.sh ./

RUN uv pip install --system --no-cache-dir -r requirements.txt \
    && mkdir -p ${PROJECT_PATH}/thug \
    && chown -R ${USER}:${USER} . ${PROJECT_PATH}/thug \
    && chmod +x entrypoint.sh

# Serve Flask application using gunicorn
EXPOSE 4002
ENTRYPOINT ["./entrypoint.sh"]
