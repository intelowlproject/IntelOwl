# system imports
import os
import logging
import json
import shutil
import secrets

# web imports
from flask import Flask, jsonify, make_response, safe_join, request
from flask_executor import Executor
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

# with this, we can make http calls to the endpoint: /boxjs
shell2http.register_command(endpoint="boxjs", command_name="box-js")


@app.route("/get-result")
def get_result():
    # user provides us with dir_name i.e {filename}.results
    fname = request.args.get("name", None)
    try:
        if not fname:
            raise Exception("No name in GET request's query params.")
        dir_loc = safe_join("/tmp/boxjs", fname + ".results")
        result = read_files_and_make_result(dir_loc)

        return make_response(jsonify(result), 200)
    except Exception as e:
        return make_response(jsonify(error=str(e)), 400)


def read_files_and_make_result(dir_loc):
    result = {}
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
                if fname.endswith(".json"):
                    result[fname] = json.load(fp)
                else:
                    result[fname] = fp.readlines()
        except FileNotFoundError:
            result[fname] = f"FileNotFoundError: {fname}"

    # Remove the directory
    shutil.rmtree(dir_loc, ignore_errors=True)

    return result
