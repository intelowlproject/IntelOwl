#!/bin/sh
mkdir "/tmp/eve_$2"
if [ -z "$3" ]
then
  suricata --runmode=single -r $1 -l "/tmp/eve_$2"
else
  suricata --runmode=single -r $1 -l "/tmp/eve_$2" --set outputs.1.eve-log.types.0.alert.payload=no --set outputs.1.eve-log.types.0.alert.payload-printable=no --set outputs.1.eve-log.types.0.alert.http-body=no --set outputs.1.eve-log.types.0.alert.http-body-printable=no
fi