import json
import logging
import os
import subprocess
import traceback
from typing import Any, Dict, Tuple

from flask import Flask, jsonify, request

# Set the log path (ensure this is a valid directory)
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

app = Flask(__name__)


def run_nuclei_command(
    url: str, template_dirs: list = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Returns: (success: bool, result: dict)
    """
    try:
        logger.info(f"Starting Nuclei scan for URL: {url}")

        # Ensure nuclei binary exists
        nuclei_path = "./nuclei" if os.path.exists("./nuclei") else "nuclei"

        command = [nuclei_path, "-u", url, "-jsonl"]

        if template_dirs:
            for template_dir in template_dirs:
                command.extend(["-t", template_dir])

        logger.debug(f"Running command: {' '.join(command)}")

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            logger.error(f"Nuclei scan failed: {error_msg}")
            return False, {
                "success": False,
                "error": "Failed to run Nuclei",
                "details": error_msg,
            }

        # Process JSON output
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
        logger.error(traceback.format_exc())
        return False, {
            "success": False,
            "error": "An unexpected error occurred",
            "details": str(e),
            "scan_status": "ERROR",
        }


@app.route("/run-nuclei", methods=["POST"])
def run_nuclei():
    """
    Endpoint to run Nuclei analysis.

    Expected payload:
    {
        "url": "https://example.com"
    }
    """
    try:
        logger.info("Received Nuclei scan request")

        # Validate request
        data = request.get_json()
        if not data or "url" not in data:
            logger.error("Invalid request: missing 'data' field")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid request, 'data' field is required",
                    }
                ),
                400,
            )

        url = data["url"]
        template_dirs = data.get("template_dirs", [])

        if not isinstance(template_dirs, list):
            logger.error("Invalid request: 'template_dirs' must be a list")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid request, 'template_dirs' must be a list",
                    }
                ),
                400,
            )

        # Run scan
        success, result = run_nuclei_command(url, template_dirs)

        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 500

    except Exception as e:
        logger.error(f"Unexpected API error: {str(e)}")
        logger.error(traceback.format_exc())
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
    app.run(host="0.0.0.0", port=4008)
