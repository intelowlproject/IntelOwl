#!/bin/sh
mkdir -p ${LOG_PATH}
touch ${LOG_PATH}/gunicorn_access.log ${LOG_PATH}/gunicorn_errors.log
chown -R pcap_analyzers-user:pcap_analyzers-user ${LOG_PATH}
su pcap_analyzers-user -s /bin/bash
suricata-update update-sources
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source sslbl/ja3-fingerprints
suricata-update enable-source etnetera/aggressive
suricata-update enable-source tgreen/hunting
suricata-update enable-source malsilo/win-malware
suricata-update
crond
crontab /etc/cron.d/suricata
suricata --unix-socket=/tmp/suricata.socket &
exec gunicorn 'app:app' \
    --bind '0.0.0.0:4004' \
    --user ${USER} \
    --log-level ${LOG_LEVEL} \
    --access-logfile ${LOG_PATH}/gunicorn_access.log \
    --error-logfile ${LOG_PATH}/gunicorn_errors.log

