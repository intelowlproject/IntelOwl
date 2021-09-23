#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

echo "------------------------------"
echo "DEBUG:  ${DEBUG}"
echo "DJANGO_TEST_SERVER: ${DJANGO_TEST_SERVER}"
echo "------------------------------"

# this is required for retrocompatibility (this env variable did not exist before v3.0.2)
if [ -z "${BROKER_URL_API}" ]
then
  BROKER_URL_API="http://guest:guest@rabbitmq:15672/api/"
fi

if [ -z "${BROKER_URL}" ]
then
  BROKER_URL="amqp://guest:guest@rabbitmq:5672"
fi

if [ -z "${FLOWER_USR}" ]
then
  FLOWER_USR="flower"
fi

if [ -z "${FLOWER_PWD}" ]
then
  FLOWER_PWD="flower"
fi

CMD="/usr/local/bin/celery -A intel_owl.celery --broker ${BROKER_URL} flower --broker_api=${BROKER_URL_API} --max_tasks=1000 --max_workers=500"
htpasswd -cb /opt/deploy/shared_htpasswd/.htpasswd ${FLOWER_USER} ${FLOWER_PWD}

if [[ ${DEBUG} == "True" ]] && [[ ${DJANGO_TEST_SERVER} == "True" ]];
then
    ${CMD} --debug
else
    ${CMD}
fi
