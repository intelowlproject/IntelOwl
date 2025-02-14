# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import os

# system imports
import secrets
import shutil

# web imports
from flask import Flask
from flask_executor import Executor
from flask_executor.futures import Future
from flask_shell2http import Shell2HTTP

LOG_NAME = "thug"

# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{LOG_NAME}")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/{LOG_NAME}.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/{LOG_NAME}_errors.log")
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


def intercept_thug_result(context, future: Future) -> None:
    """
    Thug doesn't output result to standard output but to a file,
    using this callback function,
    we intercept the future object and update its result attribute
    by reading the final analysis result from the saved result file
    before it is ready to be consumed.
    """
    # 1. get current result object
    res = future.result()
    # 2. dir from which we will read final analysis result
    dir_loc = context.get("read_result_from", None)
    if not dir_loc:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        # 3. read saved result file, if it exists
        f_loc = dir_loc + "/analysis/json/analysis.json"
        if not os.path.exists(f_loc):
            res["error"] += f", result file {f_loc} does not exists."
            if res.get("returncode", -1) == 0:
                res["returncode"] = -1
        else:
            with open(f_loc, "r", encoding="utf-8") as fp:
                try:
                    res["report"] = json.load(fp)
                except json.JSONDecodeError:
                    res["report"] = fp.read()

    # 4. set final result after modifications
    future._result = res  # skipcq PYL-W0212

    # 5. directory can be removed now
    if dir_loc:
        shutil.rmtree(dir_loc, ignore_errors=True)


# with this, we can make http calls to the endpoint: /thug
shell2http.register_command(
    endpoint="thug",
    command_name="/opt/deploy/thug/venv/bin/thug -qZF",
    callback_fn=intercept_thug_result,
)
