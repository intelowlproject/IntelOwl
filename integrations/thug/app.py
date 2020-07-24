# system imports
import os
import logging
import json
import shutil

# web imports
from flask import Flask, safe_join
from flask_executor import Executor
from flask_executor.futures import Future
from flask_shell2http import Shell2HTTP

# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/thug")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/thug.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/thug_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

# Globals
app = Flask(__name__)
CONFIG = {
    "SECRET_KEY": __import__("secrets").token_hex(16),
}
app.config.update(CONFIG)

executor = Executor(app)
shell2http = Shell2HTTP(app, executor)


# Functions
def intercept_result(context, future: Future) -> None:
    """
    Thug doesn't output result to standard output but to a file,
    using this callback function,
    we intercept the future object and update it's result attribute
    by reading the final analysis result from the saved result file
    before it is ready to be consumed.
    """
    # 1. get current result object
    res = future.result()
    # 2. dir from which we will read final analysis result
    dir_name = context.get("read_result_from", None)
    if not dir_name:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        # 3. read saved result file, if it exists
        dir_loc = safe_join("/home/thug", dir_name)
        f_loc = dir_loc + "/analysis/json/analysis.json"
        if not os.path.exists(f_loc):
            res["error"] += f", result file {f_loc} does not exists."
            if res.get("returncode", -1) == 0:
                res["returncode"] = -1
        else:
            with open(f_loc, "r") as fp:
                try:
                    res["report"] = json.load(fp)
                except json.JSONDecodeError:
                    res["report"] = fp.read()

    # 4. set final result after modifications
    future._result = res

    # 5. directory can be removed now
    shutil.rmtree(dir_loc, ignore_errors=True)


# with this, we can make http calls to the endpoint: /thug
shell2http.register_command(
    endpoint="thug", command_name="thug -qZF", callback_fn=intercept_result
)
