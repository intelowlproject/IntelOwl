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

LOG_NAME = "pcap_analyzers"

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


def intercept_suricata_result(context, future: Future) -> None:
    # 1. get current result object
    res = future.result()
    # 2. dir from which we will read final analysis result
    directory = context.get("read_result_from", None)
    if not directory:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        res["report"] = {"data": []}
        with open(f"{directory}/eve.json", "r", encoding="utf_8") as fp:
            for line in fp:
                try:
                    res["report"]["data"].append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.debug(e)
                    res["report"]["data"].append(fp.read())

    # 3. set final result after modifications
    future._result = res  # skipcq PYL-W0212

    # 4 remove the log file
    shutil.rmtree(directory)


shell2http.register_command(
    endpoint="suricata",
    command_name="python3 /check_pcap.py",
    callback_fn=intercept_suricata_result,
)
