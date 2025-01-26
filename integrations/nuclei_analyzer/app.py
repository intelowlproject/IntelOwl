import json
import logging
import os
import subprocess
import uuid
from datetime import datetime
from threading import Thread
from typing import Any, Dict, Tuple

from flask import Flask, jsonify, request

app = Flask(__name__)

log_path = os.getenv("LOG_PATH", "/var/log/intel_owl/nuclei_analyzers")
os.makedirs(log_path, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"{log_path}/nuclei_analyzer.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("nuclei-analyzer")

# In-memory store for task reports
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
    "exposures",
}


def run_nuclei_command(
    url: str, template_dirs: list = None
) -> Tuple[bool, Dict[str, Any]]:
    try:
        logger.info(f"Starting Nuclei scan for URL: {url}")
        logger.info(f"Template directories: {template_dirs}")

        # Assumes nuclei is in PATH or current directory
        nuclei_path = "./nuclei" if os.path.exists("./nuclei") else "nuclei"
        command = [
            nuclei_path,
            "-ud",
            "/opt/nuclei-api/nuclei-templates",
            "-u",
            url,
            "-jsonl",
        ]

        if template_dirs:
            for template_dir in template_dirs:
                if template_dir not in temp_dirs:
                    return False, {
                        "success": False,
                        "error": "Invalid template directory",
                        "details": f"Invalid template directory: {template_dir}",
                    }
                else:
                    command.extend(["-t", template_dir])

        logger.info(f"Running command: {' '.join(command)}")

        report = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1200,
            check=True,
        )

        if report.returncode != 0:
            error_msg = report.stderr.strip()
            return False, {
                "success": False,
                "error": "Failed to run Nuclei",
                "details": error_msg,
            }

        output_lines = [
            line.strip() for line in report.stdout.split("\n") if line.strip()
        ]
        parsed_reports = []

        for line in output_lines:
            try:
                parsed_reports.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON line: {line}, error: {str(e)}")
                continue

        return True, {
            "success": True,
            "result": parsed_reports,
            "scan_status": "COMPLETED",
            "statistics": {"total_findings": len(parsed_reports)},
        }

    except subprocess.TimeoutExpired:
        return False, {
            "success": False,
            "error": "Scan timed out",
            "scan_status": "TIMEOUT",
        }
    except Exception as e:
        return False, {
            "success": False,
            "error": "An unexpected error occurred",
            "details": str(e),
            "scan_status": "ERROR",
        }


def async_nuclei_scan(task_id: str, url: str, template_dirs: list = None):
    try:
        _, report = run_nuclei_command(url, template_dirs)

        task_store[task_id].update(
            {
                "status": "completed",
                "report": report,
                "completed_at": datetime.utcnow().isoformat(),
            }
        )
        logger.info(f"Task {task_id} reports stored successfully")
    except Exception as e:
        task_store[task_id].update(
            {
                "status": "error",
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat(),
            }
        )


@app.route("/run-nuclei", methods=["GET"])
def get_nuclei_scan_status():
    task_id = request.args.get("key")
    if not task_id:
        return jsonify({"success": False, "error": "Missing task key parameter"}), 400

    if task_id not in task_store:
        return jsonify({"success": False, "error": "Invalid task key"}), 404

    task_info = task_store[task_id]

    if task_info["status"] == "running":
        return (
            jsonify({"status": "running", "started_at": task_info["started_at"]}),
            200,
        )

    return (
        jsonify(
            {
                "status": task_info["status"],
                "report": task_info.get("report"),
                "error": task_info.get("error"),
                "started_at": task_info["started_at"],
                "completed_at": task_info["completed_at"],
            }
        ),
        200,
    )


@app.route("/run-nuclei", methods=["POST"])
def start_nuclei_scan():
    try:
        data = request.get_json()

        if not data or "observable" not in data:
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

        if not isinstance(template_dirs, list):
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
    app.run(host="0.0.0.0", port=4008)
