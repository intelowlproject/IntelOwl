# https://github.com/jasonish/docker-suricata/tree/master/7.0
FROM jasonish/suricata:7.0

ENV PROJECT_PATH=/opt/deploy
ENV LOG_PATH=/var/log/intel_owl/pcap_analyzers
ENV USER=pcap_analyzers-user
RUN dnf -y install python3-pip && dnf clean all && useradd -ms /bin/bash ${USER}

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/pcap_analyzers-flask
COPY app.py requirements.txt entrypoint.sh ./
COPY check_pcap.py update_signatures.sh /
COPY crontab /etc/cron.d/suricata
# adding Suricata config files and sigs
# these copies are required in case a Docker Volume is used instead of a Bind volume (Swarm deployments)
COPY config/suricata/etc/* /etc/suricata
COPY config/suricata/rules/* /var/lib/suricata/rules

RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . /etc/suricata /var/lib/suricata \
    && mkdir -p ${LOG_PATH}/suricata/ \
    && touch /var/log/cron.log ${LOG_PATH}/suricata/suricata.log \
    && chmod 0666 ${LOG_PATH}/suricata \
    && chmod 0644 /etc/cron.d/suricata /var/log/cron.log ${LOG_PATH}/suricata/suricata.log

# Serve Flask application using gunicorn
EXPOSE 4004
ENTRYPOINT ["./entrypoint.sh"]