# https://github.com/jasonish/docker-suricata/tree/master/7.0
FROM jasonish/suricata:7.0
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/pcap_analyzers
ENV USER=pcap_analyzers-user
RUN dnf -y install python3-pip wget && dnf clean all && useradd -ms /bin/bash ${USER} \
    && wget -q -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.19/gosu-amd64" \
    && chmod +x /usr/local/bin/gosu

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/pcap_analyzers-flask
COPY app.py requirements.txt entrypoint.sh ./
COPY check_pcap.py update_signatures.sh /
COPY crontab /etc/cron.d/suricata
# adding Suricata config files and sigs
# these copies are required in case a Docker Volume is used instead of a Bind volume (Swarm deployments)
COPY config/suricata/etc/* /etc/suricata/
COPY config/suricata/rules/* /var/lib/suricata/rules/

RUN --mount=type=cache,target=/root/.cache/uv uv pip install --system -r requirements.txt \
    && chown -R ${USER}:${USER} . /etc/suricata /var/lib/suricata \
    && mkdir -p ${LOG_PATH}/suricata/ \
    && touch /var/log/cron.log ${LOG_PATH}/suricata/suricata.log \
    && chmod 0666 ${LOG_PATH}/suricata \
    && chmod 0644 /etc/cron.d/suricata /var/log/cron.log ${LOG_PATH}/suricata/suricata.log

# Serve Flask application using gunicorn
EXPOSE 4004
ENTRYPOINT ["./entrypoint.sh"]