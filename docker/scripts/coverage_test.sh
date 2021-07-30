docker exec intelowl_uwsgi \
    coverage run \
    manage.py test $@