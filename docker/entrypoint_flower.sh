#!/bin/bash

until cd /opt/deploy/intel_owl
do
    echo "Waiting for server volume..."
done

echo "------------------------------"
echo "DEBUG:  ${DEBUG}"
echo "DJANGO_TEST_SERVER: ${DJANGO_TEST_SERVER}"
echo "------------------------------"

CMD="/usr/local/bin/celery -A intel_owl.celery --broker ${BROKER_URL} flower --broker_api=http://guest:guest@rabbitmq:15672/api/"
htpasswd -cb /opt/deploy/shared_htpasswd/.htpasswd ${FLOWER_USER} ${FLOWER_PWD}

if [[ ${DEBUG} == "True" ]] && [[ ${DJANGO_TEST_SERVER} == "True" ]];
then
    ${CMD} --debug
else
    ${CMD}
fi
