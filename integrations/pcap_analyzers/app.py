# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

# system imports
import os
import secrets
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
    eve_json_file = context.get("read_result_from", None)
    if not eve_json_file:
        res["error"] += ", No specified file to read result from"
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
    else:
        max_tries = 60
        poll_interval = 2
        for try_ in range(max_tries):
            try:
                with open(eve_json_file, "r+") as fp:
                    try:
                        res["report"] = json.load(fp)
                    except json.JSONDecodeError:
                        res["report"] = fp.read()
                    # this means that Suricata has finished its computation
                    # todo check ID in the report and remove that part in the file
                    if res.get("report"):
                        res
                        logger.info("report empty, waiting")
                        break
            except Exception as e:
                res["error"] += str(e)
                logger.exception(e)
            time.sleep(poll_interval)

    logger.error("result")
    logger.error(res)

    # 3. set final result after modifications
    future._result = res


shell2http.register_command(
    endpoint="suricata",
    command_name="./upload_pcap.sh",
    callback_fn=intercept_suricata_result,
)
