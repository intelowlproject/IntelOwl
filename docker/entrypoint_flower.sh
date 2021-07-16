#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

USER="${FLOWER_USER:=flower}"
PASSWORD="${FLOWER_PWD:=flower}"
echo "------------------------------"
echo "DEBUG:  ${DEBUG}"
echo "DJANGO_TEST_SERVER: ${DJANGO_TEST_SERVER}"
echo "BROKER: ${CELERY_BROKER_URL}"
echo "------------------------------"

CMD="/usr/local/bin/celery  -A intel_owl.celery --broker $CELERY_BROKER_URL flower --broker_api=http://guest:guest@rabbitmq:15672/api/"

if [[ $DEBUG == "True" ]] && [[ $DJANGO_TEST_SERVER == "True" ]];
then
    ${CMD} --debug
else
  if [[ ! -f ".htpasswd" ]]; then
    htpasswd -cb .htpasswd ${USER} ${PASSWORD}
  fi
    ${CMD}
fi
