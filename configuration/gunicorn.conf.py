# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import multiprocessing

# Gunicorn configuration file for IntelOwl

bind = "0.0.0.0:8001"
worker_class = "gthread"

# Dynamic worker calculation: (2 x num_cores) + 1
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2

timeout = 600

max_requests = 1000
max_requests_jitter = 50
keepalive = 5
preload_app = True

# Standard Docker logging to stdout/stderr
accesslog = "-"
errorlog = "-"
loglevel = "info"

proc_name = "intel_owl_gunicorn"

# Handle headers from Nginx correctly
forwarded_allow_ips = "*"
proxy_allow_ips = "*"
