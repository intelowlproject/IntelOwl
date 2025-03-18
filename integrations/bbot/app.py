import logging

from bbot.scanner import Scanner
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class scan_request(BaseModel):
    target: str
    presets: list[str] = ["web-basic"]
    modules: list[str] = []


@app.post("/run")
async def run_scan(request: scan_request):
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
        )

        results = []

        async for event in scanner.async_start():
            results.append(event.data)

        logger.info(f"Scan results: {results}")
        return {"success": True, "report": {"events": results}}

    except Exception as e:
        logger.error(f"Error while scanning target: {e}")
        raise HTTPException(status_code=500, detail="Error while scanning")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
