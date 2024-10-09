import logging
from typing import Dict

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class PhishingFormCompiler(FileAnalyzer, DockerBasedAnalyzer):
    target_site: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)

        if not (hasattr(self._job, "pivot_parent")):
            raise AnalyzerRunException(f"Analyzer {self.analyzer_name}")

        self.target_site = self._job.pivot_parent.starting_job.observable_name
        if not self.target_site:
            logger.info("Target site not found! Proceeding with only source code.")

    def run(self) -> dict:
        logger.info(self.target_site)
        return {}
