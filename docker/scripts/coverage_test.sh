docker exec intelowl_uwsgi \
    coverage run --append \
    manage.py test $@