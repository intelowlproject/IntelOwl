import logging
import os
import secrets

# web imports
from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

LOG_NAME = "phishing_analyzers"

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

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)
# Disable Werkzeug 3.x default form memory limit (500kB) to avoid false 400
# errors on multipart requests.
# See: https://werkzeug.palletsprojects.com/en/stable/changes/#version-3-1-0
app.config["MAX_FORM_MEMORY_SIZE"] = None
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB
executor = Executor(app)
shell2http = Shell2HTTP(app, executor)


# ensure error responses are JSON (not HTML) for flask-shell2http callers
@app.errorhandler(400)
def bad_request(e):
    return {"error": str(e)}, 400


@app.errorhandler(413)
def too_large(e):
    return {"error": str(e)}, 413


shell2http.register_command(
    endpoint="phishing_extractor",
    command_name="/usr/local/bin/python3 /opt/deploy/phishing_analyzers/analyzers/extract_phishing_site.py",
)

shell2http.register_command(
    endpoint="phishing_extractor_playwright",
    command_name="/usr/local/bin/python3 /opt/deploy/phishing_analyzers/analyzers/extract_phishing_site_playwright.py",
)

shell2http.register_command(
    endpoint="phishing_extractor_cloakbrowser",
    command_name="/usr/local/bin/python3 /opt/deploy/phishing_analyzers/analyzers/extract_phishing_site_cloakbrowser.py",
)
