# system imports
import os
import logging

# web imports
from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

# Logging configuration
# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/apk_analyzers")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/apkid.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/apkid_errors.log")
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

# with this, we can make http calls to the endpoint: /apkid
shell2http.register_command(endpoint="apkid", command_name="apkid")
