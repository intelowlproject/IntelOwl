# https://github.com/jasonish/docker-suricata/tree/master/6.0
FROM jasonish/suricata:6.0

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/pcap_analyzers
ENV USER pcap_analyzers-user
# Python 3.8 is required to have Flask work correctly. Base leverage Python 3.6
RUN dnf -y remove python3 && dnf -y install python3.8 && dnf clean all && useradd -ms /bin/bash ${USER}

# Build Flask REST API
WORKDIR ${PROJECT_PATH}/pcap_analyzers-flask
COPY app.py requirements.txt entrypoint.sh ./
COPY check_pcap.py update_signatures.sh /
COPY crontab /etc/cron.d/suricata
RUN pip3 install -r requirements.txt --no-cache-dir \
    && chown -R ${USER}:${USER} . /etc/suricata /var/lib/suricata \
    && touch /var/log/cron.log \
    && chmod 0644 /etc/cron.d/suricata /var/log/cron.log

# Serve Flask application using gunicorn
EXPOSE 4004
ENTRYPOINT ["./entrypoint.sh"]