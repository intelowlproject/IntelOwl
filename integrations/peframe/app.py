# system imports
import os
import logging

# web imports
from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

# Globals
app = Flask(__name__)
executor = Executor(app)
shell2http = Shell2HTTP(app, executor)

# with this, we can make http calls to the endpoint: /peframe
shell2http.register_command(endpoint="peframe", command_name="peframe")

# Config
CONFIG = {
    "SECRET_KEY": __import__("secrets").token_hex(16),
}
app.config.update(CONFIG)


# Application Runner
if __name__ == "__main__":
    app.run(port=4000)
else:
    # get flask-shell2http logger instance
    logger = logging.getLogger("flask_shell2http")
    # logger config
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    log_level = os.getenv("LOG_LEVEL", logging.INFO)
    log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/peframe")
    # create new file handlers
    fh = logging.FileHandler(f"{log_path}/peframe.log")
    fh.setFormatter(formatter)
    fh.setLevel(log_level)
    fh_err = logging.FileHandler(f"{log_path}/peframe_errors.log")
    fh_err.setFormatter(formatter)
    fh_err.setLevel(logging.ERROR)
    # set the logger
    logger.addHandler(fh)
    logger.addHandler(fh_err)
