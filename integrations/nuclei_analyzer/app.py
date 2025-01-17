import json
import logging
import os
import subprocess
import traceback
import uuid
from datetime import datetime
from threading import Thread
from typing import Any, Dict, Tuple

from flask import Flask, jsonify, request

app = Flask(__name__)

log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/nuclei_analyzers")
os.makedirs(log_path, exist_ok=True)  # Ensure the directory exists

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nuclei-analyzer")

# Set up file logging
file_handler = logging.FileHandler(f"{log_path}/nuclei_analyzer.log")
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# In-memory store for task results
task_store = {}

temp_dirs = {
    "cloud",
    "code",
    "cves",
    "vulnerabilities",
    "dns",
    "file",
    "headless",
    "helpers",
    "http",
    "javascript",
    "network",
    "passive",
    "profiles",
    "ssl",
    "workflows",
}


def run_nuclei_command(
    url: str, template_dirs: list = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Returns: (success: bool, result: dict)
    """
    try:
        logger.info(f"Starting Nuclei scan for URL: {url}")
        logger.info(f"Template directories: {template_dirs}")

        nuclei_path = "./nuclei" if os.path.exists("./nuclei") else "nuclei"
        command = [nuclei_path, "-u", url, "-jsonl"]

        if template_dirs:
            for template_dir in template_dirs:
                if template_dir not in temp_dirs:
                    logger.error(f"Invalid template directory: {template_dir}")
                    return False, {
                        "success": False,
                        "error": "Invalid template directory",
                        "details": f"Invalid template directory: {template_dir}",
                    }
                else:
                    command.extend(["-t", template_dir])

        logger.info(f"Running command: {' '.join(command)}")

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            logger.error(f"Nuclei command failed with return code {result.returncode}")
            logger.error(f"Error message: {error_msg}")
            return False, {
                "success": False,
                "error": "Failed to run Nuclei",
                "details": error_msg,
            }

        logger.info("Processing Nuclei scan output")
        output_lines = [
            line.strip() for line in result.stdout.split("\n") if line.strip()
        ]
        parsed_results = []

        for line in output_lines:
            try:
                parsed_results.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON line: {line}, error: {str(e)}")
                continue

        logger.info(f"Nuclei scan completed successfully for {url}")
        logger.info(f"Found {len(parsed_results)} results")
        return True, {
            "success": True,
            "results": parsed_results,
            "scan_status": "COMPLETED",
            "statistics": {"total_findings": len(parsed_results)},
        }

    except subprocess.TimeoutExpired:
        logger.error("Nuclei scan timed out after 600 seconds")
        return False, {
            "success": False,
            "error": "Scan timed out",
            "scan_status": "TIMEOUT",
        }
    except Exception as e:
        logger.error(f"Unexpected error during Nuclei scan: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return False, {
            "success": False,
            "error": "An unexpected error occurred",
            "details": str(e),
            "scan_status": "ERROR",
        }


def async_nuclei_scan(task_id: str, url: str, template_dirs: list = None):
    """
    Asynchronous function to run Nuclei scan and store results
    """
    logger.info(f"Starting async scan for task {task_id} on URL {url}")
    try:
        success, result = run_nuclei_command(url, template_dirs)
        logger.info(f"Scan completed for task {task_id}. Success: {success}")

        task_store[task_id].update(
            {
                "status": "completed",
                "result": result,
                "completed_at": datetime.utcnow().isoformat(),
            }
        )
        logger.info(f"Task {task_id} results stored successfully")
    except Exception as e:
        logger.error(f"Error in async scan for task {task_id}: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        task_store[task_id].update(
            {
                "status": "error",
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat(),
            }
        )
        logger.info(f"Task {task_id} error status stored")


@app.route("/run-nuclei", methods=["POST", "GET"])
def run_nuclei():
    if request.method == "GET":
        task_id = request.args.get("key")
        if not task_id:
            logger.error("GET request missing task key parameter")
            return (
                jsonify({"success": False, "error": "Missing task key parameter"}),
                400,
            )

        if task_id not in task_store:
            logger.warning(f"Task {task_id} not found in task store")
            return jsonify({"success": False, "error": "Invalid task key"}), 404

        task_info = task_store[task_id]

        if task_info["status"] == "running":
            return (
                jsonify({"status": "running", "started_at": task_info["started_at"]}),
                200,
            )

        logger.info(f"Returning completed results for task {task_id}")
        return (
            jsonify(
                {
                    "status": task_info["status"],
                    "result": task_info.get("result"),
                    "error": task_info.get("error"),
                    "started_at": task_info["started_at"],
                    "completed_at": task_info["completed_at"],
                }
            ),
            200,
        )

    # Handle POST request to start new scan
    try:
        logger.info("Received POST request for new scan")
        data = request.get_json()

        if not data or "observable" not in data:
            logger.error("Invalid POST request: missing 'observable' field")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid request, 'observable' field is required",
                    }
                ),
                400,
            )

        obs = data["observable"]
        template_dirs = data.get("template_dirs", [])
        logger.info(f"Processing scan request for URL: {obs}")
        logger.info(f"Template directories: {template_dirs}")

        if not isinstance(template_dirs, list):
            logger.error("Invalid template_dirs format: not a list")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid request, 'template_dirs' must be a list",
                    }
                ),
                400,
            )

        task_id = str(uuid.uuid4())

        task_store[task_id] = {
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
        }

        thread = Thread(target=async_nuclei_scan, args=(task_id, obs, template_dirs))
        thread.start()

        return jsonify({"status": "accepted", "key": task_id}), 200

    except Exception as e:
        logger.error(f"Unexpected error processing POST request: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": "An unexpected error occurred",
                    "details": str(e),
                }
            ),
            500,
        )


if __name__ == "__main__":
    logger.info("Starting the Nuclei Analyzer API")
    app.run(host="0.0.0.0", port=4011)
