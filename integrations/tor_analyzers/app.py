# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

# system imports
import os

# web imports
from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

# Logging configuration
# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", "20")
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/tor_analyzers")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/tor_analyzers.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/tor_analyzers_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

# Globals
app = Flask(__name__)
# Config
CONFIG = {
    "SECRET_KEY": __import__("secrets").token_hex(16),
}
app.config.update(CONFIG)

executor = Executor(app)
shell2http = Shell2HTTP(app, executor)

# with this, we can make http calls to the endpoint: /onionscan
shell2http.register_command(endpoint="onionscan", command_name="./bundled/onionscan")
