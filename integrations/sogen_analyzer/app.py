import logging
import os
import tempfile
import traceback

import sogen
from flask import Flask, jsonify, request

LOG_NAME = "sogen_analyzer"
logger = logging.getLogger(LOG_NAME)

log_level = os.getenv("LOG_LEVEL", logging.INFO)
log_path = os.getenv("LOG_PATH", f"/var/log/intel_owl/{LOG_NAME}")

fh = logging.FileHandler(f"{log_path}/{LOG_NAME}.log")
fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
fh.setLevel(log_level)

fh_err = logging.FileHandler(f"{log_path}/{LOG_NAME}_errors.log")
fh_err.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
fh_err.setLevel(logging.ERROR)

logger.addHandler(fh)
logger.addHandler(fh_err)
logger.setLevel(log_level)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB, matches nuclei_analyzer

EMULATION_ROOT = os.getenv("SOGEN_EMULATION_ROOT", "/opt/sogen_root")


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": str(e)}), 413


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    uploaded = request.files["file"]
    max_instructions = int(request.form.get("max_instructions", 20_000_000))
    timeout_seconds = int(request.form.get("timeout_seconds", 60))

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        uploaded.save(tmp.name)
        sample_path = tmp.name

    module_loads = []
    entry_hit = {"value": False}

    try:
        emu = sogen.windows.create_application(sample_path, emulation_root=EMULATION_ROOT)

        def on_module_load(module):
            module_loads.append({"name": module.name, "entry_point": hex(module.entry_point)})
            if module.name.lower() == uploaded.filename.lower():
                emu.hooks.memory_execution_at(
                    module.entry_point,
                    lambda address: entry_hit.__setitem__("value", True),
                )

        emu.callbacks.on_module_load = on_module_load
        emu.start(count=max_instructions, timeout=timeout_seconds)

        result = {
            "module_loads": module_loads,
            "entry_point_hit": entry_hit["value"],
            "exit_status": getattr(emu.process, "exit_status", None),
            "error": None,
        }
        logger.info(f"Sogen analysis completed for {uploaded.filename}")
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Sogen analysis failed for {uploaded.filename}: {e}", exc_info=True)
        return jsonify(
            {
                "module_loads": module_loads,
                "entry_point_hit": entry_hit["value"],
                "exit_status": None,
                "error": f"{e}\n{traceback.format_exc()}",
            }
        ), 200
    finally:
        os.unlink(sample_path)


if __name__ == "__main__":
    logger.info("Starting Sogen analyzer API server")
    app.run(host="0.0.0.0", port=4009)
