#!/bin/sh
mkdir "/tmp/eve_$2"
if [ -z "$3" ]
then
  suricata --runmode=single -r $1 -l "/tmp/eve_$2"
else
  suricata --runmode=single -r $1 -l "/tmp/eve_$2" --set output.1.eve-log.types.1.alert.payload=no --set output.1.eve-log.types.1.alert.payload-printable=no --set output.1.eve-log.types.1.alert.http-body=no --set output.1.eve-log.types.1.alert.http-body-printable=no
fi