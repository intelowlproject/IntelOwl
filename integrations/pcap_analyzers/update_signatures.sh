#!/bin/sh
suricata-update update-sources
suricata-update
kill $(pidof suricata)
suricata --unix-socket=/tmp/suricata.socket &