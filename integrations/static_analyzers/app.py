# system imports
import os
import logging
import json
import secrets

# web imports
from flask import Flask
from flask_executor import Executor
from flask_executor.futures import Future
from flask_shell2http import Shell2HTTP

# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/static_analyzers")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/static_analyzers.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/static_analyzers_errors.log")
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


# Functions


def intercept_result(context, future: Future) -> None:
    """
    Floss doesn't output result to standard output but to a file,
    using this callback function,
    we intercept the future object and update it's result attribute
    by reading the final analysis result from the saved result file
    before it is ready to be consumed.
    """
    # 1. get current result object
    res = future.result()
    # 2. dir from which we will read final analysis result
    f_loc = context.get("read_result_from", None)
    if not f_loc:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        try:
            with open(f"/tmp/{f_loc}.json", "r") as fp:
                try:
                    res["report"] = json.load(fp)
                except json.JSONDecodeError:
                    res["report"] = fp.read()
        except FileNotFoundError:
            res["error"] += ", Output File Not Found."

    # 4. set final result after modifications
    future._result = res

    # 5. file can be removed now
    os.remove(f_loc)


# with this, we can make http calls to the endpoint: /capa
shell2http.register_command(endpoint="capa", command_name="/usr/local/bin/capa")

# with this, we can make http calls to the endpoint: /floss
shell2http.register_command(
    endpoint="floss", command_name="/usr/local/bin/floss", callback_fn=intercept_result
)

# with this, we can make http calls to the endpoint: /peframe
shell2http.register_command(endpoint="peframe", command_name="peframe")

# with this, we can make http calls to the endpoint: /stringsifter
shell2http.register_command(
    endpoint="stringsifter", command_name="./stringsifter_wrapper.py"
)

# with this, we can make http calls to the endpoint: /manalyze
shell2http.register_command(endpoint="manalyze", command_name="/usr/local/bin/manalyze")
