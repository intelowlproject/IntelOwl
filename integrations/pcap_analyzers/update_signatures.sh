#!/bin/sh
suricata-update update-sources
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source sslbl/ja3-fingerprints
suricata-update enable-source etnetera/aggressive
suricata-update enable-source tgreen/hunting
suricata-update enable-source malsilo/win-malware
suricata-update
kill $(pidof suricata)
suricata --unix-socket=/tmp/suricata.socket &