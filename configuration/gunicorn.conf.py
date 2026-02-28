# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Gunicorn configuration file for IntelOwl

bind = "0.0.0.0:8001"
worker_class = "gthread"

workers = 12
threads = 2

timeout = 600


max_requests = 1000
max_requests_jitter = 50

keepalive = 5
preload_app = True

accesslog = "/var/log/intel_owl/gunicorn/intel_owl_access.log"
errorlog = "/var/log/intel_owl/gunicorn/intel_owl_errors.log"
loglevel = "info"


proc_name = "intel_owl_gunicorn"
