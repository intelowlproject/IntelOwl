import logging
import re
import subprocess

import phonenumbers
from flask import Flask, jsonify, request

# Logging Configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)


# Remove ANSI codes from script output
def strip_ansi_codes(text):
    return re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)


# Extract structured data from Phunter CLI output
def parse_phunter_output(output):
    result = {}
    key_mapping = {
        "phone number:": "phone_number",
        "possible:": "possible",
        "valid:": "valid",
        "operator:": "operator",
        "possible location:": "location",
        "location:": "location",
        "carrier:": "carrier",
        "line type:": "line_type",
        "international:": "international_format",
        "national:": "national_format",
        "local time:": "local_time",
        "views count:": "views",
    }

    lines = output.splitlines()

    for line in lines:
        line = line.strip().lower()

        # Special case: spam status
        if "not spammer" in line:
            result["spam_status"] = "Not spammer"
            continue

        for keyword, key_name in key_mapping.items():
            if keyword in line:
                value = line.partition(":")[2].strip()
                # Special handling for booleans
                if key_name in ("possible", "valid"):
                    result[key_name] = "yes" if "✔" in value else "no"
                else:
                    result[key_name] = value
                break  # No need to check other keywords once matched

    return result


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    phone_number = data.get("phone_number")

    logger.info(f"Received request to analyze phone number: {phone_number}")

    if not phone_number:
        logger.warning("Phone number missing from request")
        return jsonify({"error": "No phone number provided"}), 400

    try:
        parsed_number = phonenumbers.parse(phone_number)
        if not phonenumbers.is_valid_number(parsed_number):
            logger.warning(f"Phone number is not valid: {phone_number}")
            return jsonify({"error": "Invalid phone number"}), 400
    except phonenumbers.phonenumberutil.NumberParseException as e:
        logger.warning(f"Number parsing failed: {e}")
        return jsonify({"error": "Invalid phone number format"}), 400

    try:
        logger.info(f"Executing Phunter on: {phone_number}")
        command = ["python3", "phunter.py", "-t", phone_number]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd="/app/Phunter",  # Update if path is different
        )
        raw_output = result.stdout
        logger.debug(f"Raw Phunter output:\n{raw_output}")

        clean_output = strip_ansi_codes(raw_output)
        parsed_output = parse_phunter_output(clean_output)

        logger.info("Phunter analysis completed successfully.")
        logger.info(
            {
                "success": True,
                "report": parsed_output,
            }
        )
        return (
            jsonify(
                {
                    "success": True,
                    "report": parsed_output,
                }
            ),
            200,
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"Phunter execution failed: {e.stderr}")
        return jsonify({"error": "Phunter execution failed", "details": e.stderr}), 500
    except Exception as e:
        logger.exception("Unexpected error during Phunter analysis")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


if __name__ == "__main__":
    logger.info("Starting Phunter Flask API...")
    app.run(host="0.0.0.0", port=5000)
