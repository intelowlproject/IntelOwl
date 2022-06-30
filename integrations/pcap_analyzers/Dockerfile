FROM jasonish/suricata:6.0.5

ENV PROJECT_PATH /opt/deploy
ENV LOG_PATH /var/log/intel_owl/pcap_analyzers
ENV USER pcap_analyzers-user
RUN useradd -ms /bin/bash ${USER}

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