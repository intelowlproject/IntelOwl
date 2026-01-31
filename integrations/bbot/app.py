# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json
import logging
from pathlib import Path

from bbot.errors import BBOTError
from bbot.scanner import Scanner
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    target: str
    presets: list[str] = ["web-basic"]
    modules: list[str] = []


def get_output_json(scan_name):
    """Read and parse output.json which is a NDJSON file into a structured list of events."""
    json_path = Path(f"/opt/deploy/bbot/.bbot/scans/{scan_name}/output.json")
    if not json_path.exists():
        logger.warning(f"output.json not found at {json_path}")
        return []

    events = []
    try:
        with open(json_path, "r", encoding="utf-8") as file:
            for line in file:
                if line := line.strip():
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {line[:100]}... - Error: {e}")
    except OSError as e:
        logger.error(f"Failed to read output.json: {e}")
        return []
    except UnicodeDecodeError as e:
        logger.error(f"Encoding error in output.json: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error reading output.json: {e}")
        return []

    logger.debug(f"Parsed {len(events)} events from output.json")
    return events


@app.post("/run")
async def run_scan(request: ScanRequest):
    if not request.target:
        logger.error("No target provided")
        raise HTTPException(status_code=400, detail="No target provided")

    logger.info(f"Received scan request for target: {request.target}")

    try:
        scanner = Scanner(
            request.target,
            modules=request.modules,
            presets=request.presets,
            output_modules=["json"],
            config={"modules": {"iis_shortnames": {"_enabled": False}}},
        )

        results = []
        async for event in scanner.async_start():
            results.append(event.data)

        logger.info(f"Scan completed with {len(results)} events")
        scan_name = scanner.name
        json_output = get_output_json(scan_name)

        return {
            "success": True,
            "report": {"events": results, "json_output": json_output},
        }

    except BBOTError as e:
        logger.error(f"BBOT error: {e}")
        raise HTTPException(status_code=500, detail=f"BBOT error: {e}")
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid input: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5001)
