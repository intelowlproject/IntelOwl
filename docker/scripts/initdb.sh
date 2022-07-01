docker exec intelowl_uwsgi python3 manage.py makemigrations
docker exec intelowl_uwsgi python3 manage.py migrate
docker exec -ti intelowl_uwsgi python3 manage.py createsuperuser \
--username admin --email admin@admin.com --first_name admin --last_name admin
