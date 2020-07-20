# system imports
import os
import logging
import json

# web imports
from flask import Flask, jsonify, make_response, safe_join, request
from flask_executor import Executor
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

# with this, we can make http calls to the endpoint: /thug
shell2http.register_command(endpoint="thug", command_name="thug -qZF")


@app.route("/get-result")
def get_result():
    dir_name = request.args.get("name", None)
    try:
        f_loc = safe_join("/tmp/thug", dir_name) + "/analysis/json/analysis.json"
        if not os.path.exists(f_loc):
            raise Exception(f"File {f_loc} does not exists.")
        with open(f_loc, "r") as fp:
            result = json.load(fp)
        return make_response(jsonify(result), 200)
    except Exception as e:
        return make_response(jsonify(error=str(e)), 400)
