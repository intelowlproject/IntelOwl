# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

# system imports
import os
import secrets
import shutil
import time

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
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/pcap_analyzers")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/pcap_analyzers.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/pcap_analyzers.log")
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
    directory = context.get("read_result_from", None)
    if not directory:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        max_tries = 60
        poll_interval = 2
        res["report"] = {"data": []}
        for try_ in range(max_tries):
            try:
                with open(f"{directory}/eve.json", "r") as fp:
                    for line in fp:
                        try:
                            res["report"]["data"].append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logger.debug(e)
                            res["report"]["data"].append(fp.read())
                    # this means that Suricata has finished its computation
                    if res["report"].get("data"):
                        logger.info("report found, stop the loop")
                        break
            except Exception as e:
                res["error"] += str(e)
                logger.exception(e)
            logger.debug("report empty, waiting")
            time.sleep(poll_interval)

    # 3. set final result after modifications
    future._result = res

    # 4 remove the log file
    shutil.rmtree(directory)


shell2http.register_command(
    endpoint="suricata",
    command_name="./check_pcap.sh",
    callback_fn=intercept_suricata_result,
)
