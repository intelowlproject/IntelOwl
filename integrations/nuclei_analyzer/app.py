import json
import logging
import os

from flask import Flask
from flask_executor import Executor
from flask_shell2http import Shell2HTTP

# Logger configuration
LOG_NAME = "nuclei_scanner"
logger = logging.getLogger("flask_shell2http")

# Create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Set log level from environment variable or default to INFO
log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{LOG_NAME}")

# Create file handlers for both general logs and errors
fh = logging.FileHandler(f"{log_path}/{LOG_NAME}.log")
fh.setFormatter(formatter)
fh.setLevel(log_level)

fh_err = logging.FileHandler(f"{log_path}/{LOG_NAME}_errors.log")
fh_err.setFormatter(formatter)
fh_err.setLevel(logging.ERROR)

# Add handlers to logger
logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

# Flask application instance with secret key
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24).hex())

# Initialize the Executor for background task processing
executor = Executor(app)

# Initialize the Shell2HTTP for exposing shell commands as HTTP endpoints
shell2http = Shell2HTTP(app=app, executor=executor)


@app.route("/health", methods=["GET"])
def health_check():
    return {"status": "healthy"}, 200


def my_callback_fn(context, future):
    """
    Callback function to handle Nuclei scan results
    """
    try:
        result = future.result()
        report = result["report"]
        # The report is a string with multiple JSON objects separated by newlines
        json_objects = []
        for line in report.strip().split("\n"):
            try:
                json_objects.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"Skipping non-JSON line: {line}")
        result["report"] = {"data": json_objects}
        logger.info(f"Nuclei scan completed for context: {context}")
        logger.debug(f"Scan result: {result}")
    except Exception as e:
        logger.error(f"Error in callback function: {str(e)}", exc_info=True)
        raise


# Register the 'nuclei' command
shell2http.register_command(
    endpoint="run-nuclei",
    command_name="nuclei -j -ud /opt/nuclei-api/nuclei-templates -u",
    callback_fn=my_callback_fn,
)


if __name__ == "__main__":
    logger.info("Starting Nuclei scanner API server")
    app.run(host="0.0.0.0", port=4008)
