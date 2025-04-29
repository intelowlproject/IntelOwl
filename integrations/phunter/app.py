import logging
import re
import subprocess

import phonenumbers
from flask import Flask, jsonify, request

# Logging Configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)


def strip_ansi_codes(text):
    """Remove ANSI escape codes from terminal output"""
    return re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)


def parse_phunter_output(output):
    """Parse output from Phunter CLI and convert to structured JSON"""
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

        if "not spammer" in line:
            result["spam_status"] = "Not spammer"
            continue

        for keyword, key in key_mapping.items():
            if keyword in line:
                value = line.partition(":")[2].strip()
                if key in ("possible", "valid"):
                    result[key] = "yes" if "✔" in value else "no"
                else:
                    result[key] = value
                break

    return result


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    phone_number = data.get("phone_number")

    logger.info("Received analysis request")

    if not phone_number:
        logger.warning("No phone number provided in request")
        return jsonify({"error": "No phone number provided"}), 400

    try:
        parsed_number = phonenumbers.parse(phone_number)
        if not phonenumbers.is_valid_number(parsed_number):
            logger.warning("Invalid phone number")
            return jsonify({"error": "Invalid phone number"}), 400

        formatted_number = phonenumbers.format_number(
            parsed_number, phonenumbers.PhoneNumberFormat.E164
        )

    except phonenumbers.phonenumberutil.NumberParseException:
        logger.warning("Phone number parsing failed")
        return jsonify({"error": "Invalid phone number format"}), 400

    try:
        logger.info("Executing Phunter CLI tool")
        command = ["python3", "phunter.py", "-t", formatted_number]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd="/app/Phunter",
        )

        raw_output = result.stdout
        clean_output = strip_ansi_codes(raw_output)
        parsed_output = parse_phunter_output(clean_output)

        logger.info("Phunter analysis completed")

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
        return jsonify({"error": f"Phunter execution failed with error {e}"}), 500


if __name__ == "__main__":
    logger.info("Starting Phunter Flask API...")
    app.run(host="0.0.0.0", port=5612)
