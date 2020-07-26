# system imports
import os
import logging
import json
import shutil
import secrets

# web imports
from flask import Flask, safe_join
from flask_executor import Executor
from flask_executor.futures import Future
from flask_shell2http import Shell2HTTP

# Logging configuration
# get flask-shell2http logger instance
logger = logging.getLogger("flask_shell2http")
# logger config
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/box-js")
# create new file handlers, files are created if doesn't already exists
fh = logging.FileHandler(f"{log_path}/box-js.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)
fh_err = logging.FileHandler(f"{log_path}/box-js_errors.log")
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
def read_files_and_make_report(dir_loc):
    report = {}
    files_to_read = [
        "IOC.json",
        "snippets.json",
        "resources.json",
        "analysis.log",
        "urls.json",
        "active_urls.json",
    ]
    # Read output from files one by one
    for fname in files_to_read:
        try:
            with open(safe_join(dir_loc, fname)) as fp:
                try:
                    report[fname] = json.load(fp)
                except json.JSONDecodeError:
                    report[fname] = fp.readlines()
        except FileNotFoundError:
            report[fname] = f"FileNotFoundError: {fname}"

    return report


def intercept_result(context, future: Future) -> None:
    """
    Box-JS doesn't output result to standard output but to a file,
    using this callback function,
    we intercept the future object and update it's result attribute
    by reading the final analysis result from the saved result file
    before it is ready to be consumed.
    """
    # get current result
    res = future.result()
    fname = context.get("read_result_from", "")
    dir_loc = safe_join("/tmp/boxjs", fname + ".results")
    if not fname:
        if res.get("returncode", -1) == 0:
            res["returncode"] = -1
        raise Exception("No file specified to read result from")
    try:
        res["report"] = read_files_and_make_report(dir_loc)
    except Exception as e:
        res["error"] += str(e)
    finally:
        # set final result
        future._result = res
        # Remove the directory
        shutil.rmtree(dir_loc, ignore_errors=True)


# with this, we can make http calls to the endpoint: /boxjs
shell2http.register_command(
    endpoint="boxjs", command_name="box-js", callback_fn=intercept_result
)
