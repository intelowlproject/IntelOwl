from typing import Any, Dict

from api_app.models import Job


class EngineModule:
    def __init__(self, job: Job):
        self.job = job

    def run(self) -> Dict[str, Any]:
        raise NotImplementedError("Method run not implemented")
