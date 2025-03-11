import asyncio
import multiprocessing
import threading

from bbot.scanner import Preset, Scanner
from hypercorn.asyncio import serve
from hypercorn.config import Config
from quart import Quart, jsonify, request

orig_process_init = multiprocessing.Process.__init__


def non_daemon_process_init(self, *args, **kwargs):
    orig_process_init(self, *args, **kwargs)
    self.daemon = False


multiprocessing.Process.__init__ = non_daemon_process_init

orig_thread_init = threading.Thread.__init__


def non_daemon_thread_init(self, *args, **kwargs):
    kwargs["daemon"] = False
    orig_thread_init(self, *args, **kwargs)


threading.Thread.__init__ = non_daemon_thread_init


app = Quart(__name__)


@app.route("/run", methods=["POST"])
async def run_scan():
    data = await request.get_json()
    target = data.get("target")
    presets = data.get("presets", ["web-basic"])
    modules = data.get("modules", ["httpx"])

    if not target:
        return jsonify({"error": "No target provided"}), 400

    scan_preset = Preset(
        target, modules=modules, presets=presets, output_modules=["json"], max_workers=1
    )

    scanner = Scanner(preset=scan_preset)

    try:
        results = []
        async for event in scanner.async_start():
            results.append(event)
        return {"results": results}
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)

    config = Config()
    config.bind = ["0.0.0.0:5000"]
    asyncio.run(serve(app, config))
