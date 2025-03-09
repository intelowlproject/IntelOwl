import logging

from bbot.scanner import Preset, Scanner
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/run", methods=["POST"])
async def run_scan():
    try:
        data = request.get_json()
        target = data.get("target")
        presets = data.get("presets", ["web-basic"])
        modules = data.get("modules", ["httpx"])

        if not target:
            return jsonify({"error": "No target provided"}), 400

        logger.info(f"Received scan request for target: {target}")
        logger.info(f"Using presets: {presets}")
        logger.info(f"Using modules: {modules}")

        # Initialize the BBOT preset and scanner
        scan_preset = Preset(
            target, modules=modules, presets=presets, output_modules=["json"]
        )
        scan = Scanner(preset=scan_preset)

        results = []
        # Iterate asynchronously over the events
        async for event in scan.async_start():
            results.append(event)

        return jsonify({"results": results})
    except Exception as e:
        logger.error(f"BBOT scan failed: {str(e)}")
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
