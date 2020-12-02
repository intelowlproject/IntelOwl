# system imports
import os
import logging
import secrets

# web imports
from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter(
    "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s"
)
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/capa")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/capa.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/capa_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

# Globals
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

executor = Executor(app)
shell2http = Shell2HTTP(app, executor)

# with this, we can make http calls to the endpoint: /capa
shell2http.register_command(endpoint="capa", command_name="/usr/local/bin/capa")
